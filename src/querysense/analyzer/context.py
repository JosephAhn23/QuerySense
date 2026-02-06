"""
AnalysisContext - typed fact store with provenance tracking.

This replaces soft context bags with a strict fact registry where every
fact has explicit provenance (source, evidence level, timestamp).

Design Principles:
- Stop passing implicit state; store explicit facts with provenance
- Capabilities derive from facts present + environment
- Every fact write includes source rule, evidence level, timestamp

Example:
    ctx = AnalysisContext()
    ctx.set_fact(
        FactKey.TABLE_STATS,
        TableStats(...),
        source="db_probe",
        evidence=EvidenceLevel.PLAN_SQL_DB,
    )
    
    if ctx.has_fact(FactKey.TABLE_STATS):
        stats = ctx.get_fact(FactKey.TABLE_STATS)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from querysense.analyzer.capabilities import Capability
from querysense.analyzer.models import EvidenceLevel, SQLConfidence

if TYPE_CHECKING:
    from querysense.analyzer.sql_parser import QueryInfo
    from querysense.db.probe import DBProbe
    from querysense.parser.models import ExplainOutput


class FactKey(str, Enum):
    """
    Typed keys for facts in the analysis context.
    
    Each fact key corresponds to a specific type of data that can
    be stored and retrieved during analysis.
    """
    
    # Core inputs
    EXPLAIN_OUTPUT = "explain_output"       # The EXPLAIN JSON
    SQL_TEXT = "sql_text"                   # Raw SQL query text
    SQL_PARSE_RESULT = "sql_parse_result"   # SQLParseResult from parser
    
    # SQL-derived facts
    SQL_TABLES = "sql_tables"               # List of table names
    SQL_PREDICATES = "sql_predicates"       # WHERE/JOIN predicates
    SQL_COLUMNS = "sql_columns"             # Column references
    SQL_JOINS = "sql_joins"                 # Join specifications
    SQL_HASH = "sql_hash"                   # Normalized SQL hash
    
    # DB-derived facts
    DB_CONNECTED = "db_connected"           # Boolean: DB available
    TABLE_STATS = "table_stats"             # Dict[table, TableStats]
    TABLE_INDEXES = "table_indexes"         # Dict[table, List[IndexInfo]]
    DB_SETTINGS = "db_settings"             # DBSettings object
    PG_STAT_STATEMENTS = "pg_stat_statements"  # Query stats if available
    
    # Analysis-derived facts
    PRIOR_FINDINGS = "prior_findings"       # Findings from earlier rules
    SLOW_NODES = "slow_nodes"               # Nodes exceeding time threshold
    SEQ_SCAN_NODES = "seq_scan_nodes"       # Seq scan nodes
    MISSING_INDEXES = "missing_indexes"     # Suggested indexes
    
    # Config
    CONFIG = "config"                       # Analysis configuration


@dataclass(frozen=True)
class FactEntry:
    """
    A fact with provenance metadata.
    
    Tracks where the fact came from and its reliability.
    """
    
    key: FactKey
    value: Any
    source: str                              # Rule ID or "analyzer" or "db_probe"
    evidence: EvidenceLevel                  # What level of evidence backs this
    timestamp: float = field(default_factory=time.time)
    db_query: str | None = None              # SQL used to fetch (if DB-derived)
    
    def __repr__(self) -> str:
        return f"Fact({self.key.value}, source={self.source}, evidence={self.evidence.value})"


class FactNotFoundError(Exception):
    """Requested fact is not present in context."""
    
    def __init__(self, key: FactKey) -> None:
        self.key = key
        super().__init__(f"Fact not found: {key.value}")


class FactTypeMismatchError(Exception):
    """Fact exists but has unexpected type."""
    
    def __init__(self, key: FactKey, expected: type, actual: type) -> None:
        self.key = key
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Fact {key.value} type mismatch: expected {expected.__name__}, got {actual.__name__}"
        )


class AnalysisContext:
    """
    Typed fact store for analysis state.
    
    Provides:
    - Explicit fact storage with provenance
    - Capability derivation from facts
    - Type-safe fact retrieval
    
    Thread Safety:
        This class is NOT thread-safe. Create one context per analysis.
    """
    
    def __init__(
        self,
        explain: "ExplainOutput | None" = None,
        sql: str | None = None,
        db_probe: "DBProbe | None" = None,
    ) -> None:
        """
        Initialize analysis context.
        
        Args:
            explain: The EXPLAIN output being analyzed
            sql: Optional SQL query text
            db_probe: Optional database probe for live queries
        """
        self._facts: dict[FactKey, FactEntry] = {}
        self._capabilities: set[Capability] = set()
        self._db_probe = db_probe
        self._db_queries_run = 0
        self._db_time_ms = 0.0
        
        # Set core facts if provided
        if explain is not None:
            self.set_fact(
                FactKey.EXPLAIN_OUTPUT,
                explain,
                source="analyzer",
                evidence=EvidenceLevel.PLAN,
            )
            self._capabilities.add(Capability.EXPLAIN_PLAN)
        
        if sql is not None:
            self.set_fact(
                FactKey.SQL_TEXT,
                sql,
                source="analyzer",
                evidence=EvidenceLevel.PLAN,
            )
            self._capabilities.add(Capability.SQL_TEXT)
        
        if db_probe is not None:
            self._capabilities.add(Capability.DB_CONNECTED)
    
    def set_fact(
        self,
        key: FactKey,
        value: Any,
        source: str,
        evidence: EvidenceLevel,
        db_query: str | None = None,
    ) -> None:
        """
        Store a fact with provenance.
        
        Args:
            key: The fact key
            value: The fact value
            source: Source rule ID or "analyzer" or "db_probe"
            evidence: Evidence level backing this fact
            db_query: SQL query used to fetch (for DB-derived facts)
        """
        self._facts[key] = FactEntry(
            key=key,
            value=value,
            source=source,
            evidence=evidence,
            db_query=db_query,
        )
        
        # Update capabilities based on fact
        self._update_capabilities_for_fact(key)
    
    def _update_capabilities_for_fact(self, key: FactKey) -> None:
        """Update capabilities when a fact is added."""
        capability_map: dict[FactKey, list[Capability]] = {
            FactKey.SQL_PARSE_RESULT: [Capability.SQL_AST],
            FactKey.SQL_TABLES: [Capability.SQL_TABLES],
            FactKey.SQL_PREDICATES: [Capability.SQL_PREDICATES],
            FactKey.SQL_COLUMNS: [Capability.SQL_COLUMNS],
            FactKey.SQL_JOINS: [Capability.SQL_JOINS],
            FactKey.TABLE_STATS: [Capability.DB_STATS],
            FactKey.TABLE_INDEXES: [Capability.DB_INDEXES],
            FactKey.DB_SETTINGS: [Capability.DB_SETTINGS],
            FactKey.PG_STAT_STATEMENTS: [Capability.DB_PG_STAT],
            FactKey.PRIOR_FINDINGS: [Capability.PRIOR_FINDINGS],
        }
        
        if key in capability_map:
            for cap in capability_map[key]:
                self._capabilities.add(cap)
    
    def has_fact(self, key: FactKey) -> bool:
        """Check if a fact exists."""
        return key in self._facts
    
    def get_fact(self, key: FactKey) -> Any:
        """
        Get a fact value.
        
        Raises:
            FactNotFoundError: If fact doesn't exist
        """
        if key not in self._facts:
            raise FactNotFoundError(key)
        return self._facts[key].value
    
    def get_fact_or_none(self, key: FactKey) -> Any | None:
        """Get a fact value or None if not present."""
        if key not in self._facts:
            return None
        return self._facts[key].value
    
    def get_fact_entry(self, key: FactKey) -> FactEntry | None:
        """Get full fact entry with provenance."""
        return self._facts.get(key)
    
    def get_fact_typed(self, key: FactKey, expected_type: type) -> Any:
        """
        Get a fact with type checking.
        
        Raises:
            FactNotFoundError: If fact doesn't exist
            FactTypeMismatchError: If fact has wrong type
        """
        value = self.get_fact(key)
        if not isinstance(value, expected_type):
            raise FactTypeMismatchError(key, expected_type, type(value))
        return value
    
    @property
    def capabilities(self) -> frozenset[Capability]:
        """Get immutable set of available capabilities."""
        return frozenset(self._capabilities)
    
    def has_capability(self, cap: Capability) -> bool:
        """Check if a capability is available."""
        return cap in self._capabilities
    
    def add_capability(self, cap: Capability) -> None:
        """Manually add a capability (e.g., from environment)."""
        self._capabilities.add(cap)
    
    @property
    def db_probe(self) -> "DBProbe | None":
        """Get the database probe if available."""
        return self._db_probe
    
    @property
    def db_queries_run(self) -> int:
        """Number of DB queries executed during analysis."""
        return self._db_queries_run
    
    @property
    def db_time_ms(self) -> float:
        """Total time spent on DB queries."""
        return self._db_time_ms
    
    def record_db_query(self, duration_ms: float) -> None:
        """Record a DB query execution for budgeting."""
        self._db_queries_run += 1
        self._db_time_ms += duration_ms
    
    def compute_evidence_level(self, sql_confidence: SQLConfidence) -> EvidenceLevel:
        """
        Compute the evidence level based on available facts.
        
        Evidence Level is computed, not set by hand:
        - PLAN: Have EXPLAIN output
        - PLAN+SQL: Have EXPLAIN + SQL with confidence >= MEDIUM
        - PLAN+SQL+DB: Have EXPLAIN + SQL + DBProbe facts
        """
        has_plan = self.has_fact(FactKey.EXPLAIN_OUTPUT)
        has_sql = sql_confidence in (SQLConfidence.HIGH, SQLConfidence.MEDIUM)
        has_db = any([
            self.has_fact(FactKey.TABLE_STATS),
            self.has_fact(FactKey.TABLE_INDEXES),
            self.has_fact(FactKey.DB_SETTINGS),
        ])
        
        if has_plan and has_sql and has_db:
            return EvidenceLevel.PLAN_SQL_DB
        elif has_plan and has_sql:
            return EvidenceLevel.PLAN_SQL
        else:
            return EvidenceLevel.PLAN
    
    def all_facts(self) -> dict[FactKey, FactEntry]:
        """Get all facts with their provenance (for debugging)."""
        return dict(self._facts)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize context state for debugging."""
        return {
            "facts": [
                {
                    "key": entry.key.value,
                    "source": entry.source,
                    "evidence": entry.evidence.value,
                    "timestamp": entry.timestamp,
                }
                for entry in self._facts.values()
            ],
            "capabilities": sorted(cap.value for cap in self._capabilities),
            "db_queries_run": self._db_queries_run,
            "db_time_ms": self._db_time_ms,
        }
