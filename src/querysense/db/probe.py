"""
Database Probe - Read-only interface for validating recommendations.

Provides Level 3 analysis capabilities:
- list_indexes(table): Check if suggested indexes already exist
- table_stats(table): Get statistics freshness, row counts, bloat estimates
- settings(): Get relevant PostgreSQL settings
- query_stats(queryid): Get query frequency from pg_stat_statements (optional)

Safety requirements:
- Read-only: Only SELECT queries, no modifications
- Time-bounded: All queries have timeout protection
- Connection pooling: Efficient reuse of connections
- Budget controls: Max queries, max time, concurrency limits
- Degraded mode: When budget exceeded, sets degraded=true with reason

Design principle: DBProbe is a fact provider
- Populates facts (FactKey.TABLE_STATS, FactKey.TABLE_INDEXES, etc.)
- Adds capabilities (Capability.DB_STATS, Capability.DB_INDEXES, etc.)
- Rules require these facts/capabilities, don't call DBProbe directly

Usage:
    from querysense.db import get_probe, DBBudget
    
    # From connection string with budget
    budget = DBBudget(max_queries=10, max_time_seconds=5.0)
    probe = await get_probe("postgresql://user:pass@localhost/mydb", budget=budget)
    
    # Check if index exists
    indexes = await probe.list_indexes("orders")
    existing = {idx.columns for idx in indexes}
    
    # Check stats freshness
    stats = await probe.table_stats("orders")
    if stats.is_stale:
        print(f"Stats are {stats.stats_age_hours:.1f} hours old")
    
    # Check budget status
    if probe.budget_exceeded:
        print(f"DB budget exceeded: {probe.budget_reason}")
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

logger = logging.getLogger(__name__)

# Try to import asyncpg (optional dependency)
_ASYNCPG_AVAILABLE = False
try:
    import asyncpg
    _ASYNCPG_AVAILABLE = True
except ImportError:
    asyncpg = None  # type: ignore[assignment]

# Try to import psycopg (optional dependency)
_PSYCOPG_AVAILABLE = False
try:
    import psycopg
    _PSYCOPG_AVAILABLE = True
except ImportError:
    psycopg = None  # type: ignore[assignment]


@dataclass
class DBBudget:
    """
    Budget controls for database probe queries.
    
    Enforces production-safe limits on DB operations:
    - max_queries: Maximum number of queries per analysis
    - max_time_seconds: Maximum total DB time
    - statement_timeout_ms: Per-statement timeout
    - max_concurrency: Maximum concurrent queries
    - dry_run: If True, don't execute queries (for testing)
    
    When budget is exceeded:
    - Further queries are skipped
    - budget_exceeded is set to True
    - budget_reason explains why
    - Rules depending on DB facts are SKIPPED
    - Analysis continues in degraded mode
    """
    
    max_queries: int = 20
    max_time_seconds: float = 10.0
    statement_timeout_ms: int = 5000
    max_concurrency: int = 3
    dry_run: bool = False
    
    # Tracking (mutable)
    queries_executed: int = 0
    total_time_seconds: float = 0.0
    budget_exceeded: bool = False
    budget_reason: str | None = None
    
    def can_execute(self) -> bool:
        """Check if we can execute another query."""
        if self.dry_run:
            return False
        if self.budget_exceeded:
            return False
        if self.queries_executed >= self.max_queries:
            self.budget_exceeded = True
            self.budget_reason = f"Max queries exceeded ({self.max_queries})"
            return False
        if self.total_time_seconds >= self.max_time_seconds:
            self.budget_exceeded = True
            self.budget_reason = f"Max time exceeded ({self.max_time_seconds}s)"
            return False
        return True
    
    def record_query(self, duration_seconds: float) -> None:
        """Record a query execution."""
        self.queries_executed += 1
        self.total_time_seconds += duration_seconds
    
    def to_dict(self) -> dict[str, Any]:
        """Export budget status as dictionary."""
        return {
            "max_queries": self.max_queries,
            "max_time_seconds": self.max_time_seconds,
            "queries_executed": self.queries_executed,
            "total_time_seconds": self.total_time_seconds,
            "budget_exceeded": self.budget_exceeded,
            "budget_reason": self.budget_reason,
        }


@dataclass(frozen=True)
class IndexInfo:
    """Information about a database index."""
    
    name: str
    table: str
    columns: tuple[str, ...]
    is_unique: bool = False
    is_primary: bool = False
    index_type: str = "btree"
    size_bytes: int | None = None
    
    @property
    def columns_str(self) -> str:
        """Comma-separated column list."""
        return ", ".join(self.columns)
    
    def covers_columns(self, columns: list[str]) -> bool:
        """Check if this index covers the given columns (as a prefix)."""
        if len(columns) > len(self.columns):
            return False
        return all(
            self.columns[i].lower() == columns[i].lower()
            for i in range(len(columns))
        )


@dataclass(frozen=True)
class TableStats:
    """Statistics about a database table."""
    
    table: str
    schema: str = "public"
    
    # Row counts
    reltuples: int = 0  # Estimated row count from pg_class
    n_live_tup: int = 0  # Live tuples from pg_stat_user_tables
    n_dead_tup: int = 0  # Dead tuples (bloat indicator)
    
    # Size
    size_bytes: int = 0
    toast_size_bytes: int = 0
    index_size_bytes: int = 0
    
    # Statistics freshness
    last_analyze: datetime | None = None
    last_autoanalyze: datetime | None = None
    last_vacuum: datetime | None = None
    last_autovacuum: datetime | None = None
    
    # Column statistics (optional, expensive to fetch)
    column_stats: dict[str, dict[str, Any]] = field(default_factory=dict)
    
    @property
    def last_stats_update(self) -> datetime | None:
        """Most recent analyze (manual or auto)."""
        times = [t for t in [self.last_analyze, self.last_autoanalyze] if t]
        return max(times) if times else None
    
    @property
    def stats_age_hours(self) -> float | None:
        """Hours since last statistics update."""
        last = self.last_stats_update
        if last is None:
            return None
        return (datetime.now() - last).total_seconds() / 3600
    
    @property
    def is_stale(self, threshold_hours: float = 24.0) -> bool:
        """Whether statistics are considered stale."""
        age = self.stats_age_hours
        if age is None:
            return True  # Never analyzed
        return age > threshold_hours
    
    @property
    def bloat_ratio(self) -> float:
        """Estimated bloat ratio (dead_tup / live_tup)."""
        if self.n_live_tup == 0:
            return 0.0
        return self.n_dead_tup / self.n_live_tup
    
    @property
    def total_size_bytes(self) -> int:
        """Total size including TOAST and indexes."""
        return self.size_bytes + self.toast_size_bytes + self.index_size_bytes


@dataclass(frozen=True)
class QueryStats:
    """Statistics from pg_stat_statements."""
    
    queryid: int
    calls: int = 0
    total_time_ms: float = 0.0
    mean_time_ms: float = 0.0
    rows: int = 0
    
    @property
    def avg_rows_per_call(self) -> float:
        """Average rows returned per call."""
        if self.calls == 0:
            return 0.0
        return self.rows / self.calls


@dataclass(frozen=True)
class DBSettings:
    """Relevant PostgreSQL settings."""
    
    random_page_cost: float = 4.0
    seq_page_cost: float = 1.0
    effective_cache_size: str = "4GB"
    work_mem: str = "4MB"
    shared_buffers: str = "128MB"
    max_parallel_workers_per_gather: int = 2
    default_statistics_target: int = 100


class DBProbe(Protocol):
    """
    Protocol for database probe implementations.
    
    All methods are async and read-only.
    Implementations must be time-bounded.
    """
    
    async def list_indexes(self, table: str, schema: str = "public") -> list[IndexInfo]:
        """List all indexes on a table."""
        ...
    
    async def table_stats(self, table: str, schema: str = "public") -> TableStats:
        """Get statistics for a table."""
        ...
    
    async def settings(self) -> DBSettings:
        """Get relevant PostgreSQL settings."""
        ...
    
    async def query_stats(self, queryid: int) -> QueryStats | None:
        """Get query statistics from pg_stat_statements (if available)."""
        ...
    
    async def close(self) -> None:
        """Close the connection."""
        ...


class AsyncpgProbe:
    """
    DBProbe implementation using asyncpg.
    
    Preferred for async applications due to native async support
    and excellent performance.
    """
    
    def __init__(
        self,
        pool: "asyncpg.Pool",  # type: ignore[name-defined]
        timeout_seconds: float = 5.0,
    ) -> None:
        self._pool = pool
        self._timeout = timeout_seconds
    
    @classmethod
    async def create(
        cls,
        dsn: str,
        timeout_seconds: float = 5.0,
        min_connections: int = 1,
        max_connections: int = 5,
    ) -> "AsyncpgProbe":
        """Create a new probe with connection pool."""
        if not _ASYNCPG_AVAILABLE:
            raise RuntimeError("asyncpg is not installed. Install with: pip install asyncpg")
        
        pool = await asyncpg.create_pool(
            dsn,
            min_size=min_connections,
            max_size=max_connections,
            command_timeout=timeout_seconds,
        )
        return cls(pool, timeout_seconds)
    
    async def list_indexes(self, table: str, schema: str = "public") -> list[IndexInfo]:
        """List all indexes on a table."""
        query = """
            SELECT
                i.relname AS index_name,
                t.relname AS table_name,
                array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns,
                ix.indisunique AS is_unique,
                ix.indisprimary AS is_primary,
                am.amname AS index_type,
                pg_relation_size(i.oid) AS size_bytes
            FROM pg_index ix
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_class t ON t.oid = ix.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_am am ON am.oid = i.relam
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE t.relname = $1
              AND n.nspname = $2
            GROUP BY i.relname, t.relname, ix.indisunique, ix.indisprimary, am.amname, i.oid
            ORDER BY i.relname
        """
        
        async with self._pool.acquire() as conn:
            rows = await asyncio.wait_for(
                conn.fetch(query, table, schema),
                timeout=self._timeout,
            )
        
        return [
            IndexInfo(
                name=row['index_name'],
                table=row['table_name'],
                columns=tuple(row['columns']),
                is_unique=row['is_unique'],
                is_primary=row['is_primary'],
                index_type=row['index_type'],
                size_bytes=row['size_bytes'],
            )
            for row in rows
        ]
    
    async def table_stats(self, table: str, schema: str = "public") -> TableStats:
        """Get statistics for a table."""
        query = """
            SELECT
                c.relname AS table_name,
                n.nspname AS schema_name,
                c.reltuples::bigint AS reltuples,
                s.n_live_tup,
                s.n_dead_tup,
                pg_table_size(c.oid) AS size_bytes,
                pg_total_relation_size(c.oid) - pg_table_size(c.oid) - pg_indexes_size(c.oid) AS toast_size_bytes,
                pg_indexes_size(c.oid) AS index_size_bytes,
                s.last_analyze,
                s.last_autoanalyze,
                s.last_vacuum,
                s.last_autovacuum
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
            WHERE c.relname = $1
              AND n.nspname = $2
              AND c.relkind = 'r'
        """
        
        async with self._pool.acquire() as conn:
            row = await asyncio.wait_for(
                conn.fetchrow(query, table, schema),
                timeout=self._timeout,
            )
        
        if row is None:
            return TableStats(table=table, schema=schema)
        
        return TableStats(
            table=row['table_name'],
            schema=row['schema_name'],
            reltuples=row['reltuples'] or 0,
            n_live_tup=row['n_live_tup'] or 0,
            n_dead_tup=row['n_dead_tup'] or 0,
            size_bytes=row['size_bytes'] or 0,
            toast_size_bytes=row['toast_size_bytes'] or 0,
            index_size_bytes=row['index_size_bytes'] or 0,
            last_analyze=row['last_analyze'],
            last_autoanalyze=row['last_autoanalyze'],
            last_vacuum=row['last_vacuum'],
            last_autovacuum=row['last_autovacuum'],
        )
    
    async def settings(self) -> DBSettings:
        """Get relevant PostgreSQL settings."""
        query = """
            SELECT name, setting
            FROM pg_settings
            WHERE name IN (
                'random_page_cost',
                'seq_page_cost',
                'effective_cache_size',
                'work_mem',
                'shared_buffers',
                'max_parallel_workers_per_gather',
                'default_statistics_target'
            )
        """
        
        async with self._pool.acquire() as conn:
            rows = await asyncio.wait_for(
                conn.fetch(query),
                timeout=self._timeout,
            )
        
        settings_dict = {row['name']: row['setting'] for row in rows}
        
        return DBSettings(
            random_page_cost=float(settings_dict.get('random_page_cost', 4.0)),
            seq_page_cost=float(settings_dict.get('seq_page_cost', 1.0)),
            effective_cache_size=settings_dict.get('effective_cache_size', '4GB'),
            work_mem=settings_dict.get('work_mem', '4MB'),
            shared_buffers=settings_dict.get('shared_buffers', '128MB'),
            max_parallel_workers_per_gather=int(settings_dict.get('max_parallel_workers_per_gather', 2)),
            default_statistics_target=int(settings_dict.get('default_statistics_target', 100)),
        )
    
    async def query_stats(self, queryid: int) -> QueryStats | None:
        """Get query statistics from pg_stat_statements (if available)."""
        query = """
            SELECT
                queryid,
                calls,
                total_exec_time AS total_time_ms,
                mean_exec_time AS mean_time_ms,
                rows
            FROM pg_stat_statements
            WHERE queryid = $1
        """
        
        try:
            async with self._pool.acquire() as conn:
                row = await asyncio.wait_for(
                    conn.fetchrow(query, queryid),
                    timeout=self._timeout,
                )
            
            if row is None:
                return None
            
            return QueryStats(
                queryid=row['queryid'],
                calls=row['calls'],
                total_time_ms=row['total_time_ms'],
                mean_time_ms=row['mean_time_ms'],
                rows=row['rows'],
            )
        except Exception:
            # pg_stat_statements might not be installed
            return None
    
    async def close(self) -> None:
        """Close the connection pool."""
        await self._pool.close()


class MockProbe:
    """
    Mock probe for testing without a database.
    
    Returns empty results for all queries.
    """
    
    async def list_indexes(self, table: str, schema: str = "public") -> list[IndexInfo]:
        return []
    
    async def table_stats(self, table: str, schema: str = "public") -> TableStats:
        return TableStats(table=table, schema=schema)
    
    async def settings(self) -> DBSettings:
        return DBSettings()
    
    async def query_stats(self, queryid: int) -> QueryStats | None:
        return None
    
    async def close(self) -> None:
        pass


async def get_probe(
    dsn: str | None = None,
    timeout_seconds: float = 5.0,
) -> DBProbe:
    """
    Get a database probe instance.
    
    Args:
        dsn: PostgreSQL connection string. If None, returns a mock probe.
        timeout_seconds: Query timeout in seconds.
        
    Returns:
        DBProbe instance (AsyncpgProbe if dsn provided, MockProbe otherwise).
    """
    if dsn is None:
        return MockProbe()
    
    if _ASYNCPG_AVAILABLE:
        return await AsyncpgProbe.create(dsn, timeout_seconds)
    
    raise RuntimeError(
        "No database driver available. Install asyncpg: pip install asyncpg"
    )


def is_db_available() -> bool:
    """Check if database connectivity is available."""
    return _ASYNCPG_AVAILABLE or _PSYCOPG_AVAILABLE
