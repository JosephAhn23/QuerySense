"""
Typed capabilities and fact store for the analyzer.

Capabilities are typed interfaces (not freeform strings) that rules can
require and provide. This enables:
- Compile-time checking of capability names
- DAG validation at startup
- Explicit SKIP reasons with missing capabilities

Facts are typed values with provenance that rules produce and consume.
Each fact includes:
- The value itself
- Source rule that produced it
- Evidence level
- Timestamp
- Optional DB query used (for debugging)

Design principles:
- Single source of truth: Capabilities are interfaces, not vibes
- Explicit contracts: Rules declare what they need and provide
- Provenance tracking: Every fact knows where it came from
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from querysense.analyzer.models import EvidenceLevel


class Capability(str, Enum):
    """
    Typed capability keys that rules can require and provide.
    
    Capabilities are interfaces - they represent what data/functionality
    is available for rule execution. Using an enum instead of freeform
    strings prevents typos and enables static analysis.
    
    Categories:
    - SQL_*: SQL parsing capabilities
    - DB_*: Database probe capabilities
    - PLAN_*: Plan analysis capabilities
    - RULE_*: Capabilities provided by other rules
    """
    
    # SQL parsing capabilities
    SQL_AST = "sql_ast"                    # SQL AST available (pglast or sqlparse)
    SQL_AST_HIGH = "sql_ast_high"          # SQL AST with HIGH confidence (pglast only)
    SQL_AST_MEDIUM = "sql_ast_medium"      # SQL AST with MEDIUM+ confidence
    SQL_NORMALIZED = "sql_normalized"      # Normalized SQL for fingerprinting
    SQL_TABLES = "sql_tables"              # Table list extracted from SQL
    SQL_COLUMNS = "sql_columns"            # Column usage info from SQL
    SQL_PREDICATES = "sql_predicates"      # WHERE/JOIN predicates from SQL
    SQL_JOINS = "sql_joins"                # JOIN info from SQL
    
    # Database probe capabilities
    DB_CONNECTED = "db_connected"          # Database connection available
    DB_SCHEMA = "db_schema"                # Schema information available
    DB_STATS = "db_stats"                  # Table statistics available
    DB_INDEXES = "db_indexes"              # Index information available
    DB_SETTINGS = "db_settings"            # PostgreSQL settings available
    DB_PG_STAT = "db_pg_stat"              # pg_stat_statements available
    
    # Plan analysis capabilities
    EXPLAIN_PLAN = "explain_plan"          # EXPLAIN plan available (always true)
    EXPLAIN_ANALYZE = "explain_analyze"    # EXPLAIN ANALYZE data available
    EXPLAIN_BUFFERS = "explain_buffers"    # Buffer statistics available
    
    # Cross-phase capabilities
    PRIOR_FINDINGS = "prior_findings"      # Findings from PER_NODE phase (auto for AGGREGATE)
    
    # Rule-provided capabilities (examples - rules can define their own)
    SEQ_SCAN_FINDINGS = "seq_scan_findings"
    JOIN_FINDINGS = "join_findings"
    INDEX_RECOMMENDATIONS = "index_recommendations"
    VALIDATED_INDEXES = "validated_indexes"
    
    def __str__(self) -> str:
        return self.value


class FactKey(str, Enum):
    """
    Typed keys for facts stored in the analysis context.
    
    Facts are values with provenance that rules produce and consume.
    Using typed keys prevents typos and enables autocomplete.
    """
    
    # SQL facts
    SQL_AST = "sql_ast"
    SQL_HASH = "sql_hash"
    SQL_CONFIDENCE = "sql_confidence"
    SQL_TABLES = "sql_tables"
    SQL_FILTER_COLUMNS = "sql_filter_columns"
    SQL_JOIN_COLUMNS = "sql_join_columns"
    SQL_ORDER_BY_COLUMNS = "sql_order_by_columns"
    NORMALIZED_SQL = "normalized_sql"
    
    # Plan facts
    PLAN_FINGERPRINT = "plan_fingerprint"
    PLAN_NODE_COUNT = "plan_node_count"
    PLAN_TOTAL_COST = "plan_total_cost"
    PLAN_EXECUTION_TIME = "plan_execution_time"
    
    # Database facts (keyed by table name)
    TABLE_STATS = "table_stats"            # Dict[table_name, TableStats]
    TABLE_INDEXES = "table_indexes"        # Dict[table_name, List[IndexInfo]]
    TABLE_ROWCOUNT = "table_rowcount"      # Dict[table_name, int]
    ESTIMATED_SELECTIVITY = "estimated_selectivity"  # Dict[predicate, float]
    
    # Database settings
    DB_SETTINGS = "db_settings"
    
    # Rule-produced facts
    SEQ_SCAN_TABLES = "seq_scan_tables"    # Tables with sequential scans
    JOIN_PAIRS = "join_pairs"              # Table pairs being joined
    MISSING_INDEXES = "missing_indexes"    # Recommended indexes
    
    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class FactProvenance:
    """
    Provenance information for a fact.
    
    Tracks where a fact came from for debugging and auditing.
    """
    
    source_rule: str | None = None         # Rule that produced this fact (None = system)
    evidence_level: str | None = None      # Evidence level when fact was produced
    timestamp: float = field(default_factory=time.time)
    db_query: str | None = None            # DB query used (redacted for security)
    
    def __repr__(self) -> str:
        source = self.source_rule or "system"
        return f"FactProvenance(source={source}, evidence={self.evidence_level})"


T = TypeVar("T")


@dataclass
class Fact(Generic[T]):
    """
    A fact with its value and provenance.
    
    Facts are the typed values that flow through the analysis pipeline.
    Each fact knows where it came from (provenance) for debugging.
    """
    
    key: FactKey
    value: T
    provenance: FactProvenance = field(default_factory=FactProvenance)
    
    def __repr__(self) -> str:
        return f"Fact({self.key.value}={self.value!r}, {self.provenance})"


class FactStore:
    """
    Typed fact registry for analysis context.
    
    Replaces the "soft bag" of context variables with a strict,
    typed store where every fact has provenance.
    
    Usage:
        store = FactStore()
        store.set(FactKey.SQL_HASH, "abc123", source_rule="sql_parser")
        
        if store.has(FactKey.SQL_HASH):
            sql_hash = store.get(FactKey.SQL_HASH)
    """
    
    def __init__(self) -> None:
        self._facts: dict[FactKey, Fact[Any]] = {}
        self._capabilities: set[Capability] = set()
    
    def set(
        self,
        key: FactKey,
        value: Any,
        *,
        source_rule: str | None = None,
        evidence_level: str | None = None,
        db_query: str | None = None,
    ) -> None:
        """
        Set a fact with provenance tracking.
        
        Args:
            key: The fact key (from FactKey enum)
            value: The fact value
            source_rule: Rule that produced this fact (None = system)
            evidence_level: Evidence level when fact was produced
            db_query: DB query used (will be stored for debugging)
        """
        provenance = FactProvenance(
            source_rule=source_rule,
            evidence_level=evidence_level,
            db_query=db_query,
        )
        self._facts[key] = Fact(key=key, value=value, provenance=provenance)
    
    def get(self, key: FactKey, default: T | None = None) -> T | None:
        """
        Get a fact value.
        
        Args:
            key: The fact key
            default: Default value if fact doesn't exist
            
        Returns:
            The fact value, or default if not found
        """
        fact = self._facts.get(key)
        if fact is None:
            return default
        return fact.value
    
    def get_required(self, key: FactKey) -> Any:
        """
        Get a required fact value.
        
        Raises:
            KeyError: If fact doesn't exist
        """
        fact = self._facts.get(key)
        if fact is None:
            raise KeyError(f"Required fact not found: {key.value}")
        return fact.value
    
    def get_fact(self, key: FactKey) -> Fact[Any] | None:
        """Get the full Fact object including provenance."""
        return self._facts.get(key)
    
    def has(self, key: FactKey) -> bool:
        """Check if a fact exists."""
        return key in self._facts
    
    def keys(self) -> set[FactKey]:
        """Get all fact keys."""
        return set(self._facts.keys())
    
    # Capability management
    
    def add_capability(self, capability: Capability) -> None:
        """Add a capability to the store."""
        self._capabilities.add(capability)
    
    def add_capabilities(self, capabilities: set[Capability]) -> None:
        """Add multiple capabilities."""
        self._capabilities.update(capabilities)
    
    def has_capability(self, capability: Capability) -> bool:
        """Check if a capability is available."""
        return capability in self._capabilities
    
    def has_capabilities(self, capabilities: set[Capability]) -> bool:
        """Check if all capabilities are available."""
        return capabilities.issubset(self._capabilities)
    
    def missing_capabilities(self, required: set[Capability]) -> set[Capability]:
        """Get capabilities that are required but missing."""
        return required - self._capabilities
    
    @property
    def capabilities(self) -> frozenset[Capability]:
        """Get all available capabilities."""
        return frozenset(self._capabilities)
    
    def derive_capabilities_from_facts(self) -> None:
        """
        Derive capabilities from facts present.
        
        This implements the principle that capabilities should be
        derived from facts + environment, not set manually.
        """
        # SQL capabilities
        if self.has(FactKey.SQL_AST):
            self.add_capability(Capability.SQL_AST)
            confidence = self.get(FactKey.SQL_CONFIDENCE)
            if confidence == "high":
                self.add_capability(Capability.SQL_AST_HIGH)
        
        if self.has(FactKey.NORMALIZED_SQL):
            self.add_capability(Capability.SQL_NORMALIZED)
        
        if self.has(FactKey.SQL_TABLES):
            self.add_capability(Capability.SQL_TABLES)
        
        # Database capabilities
        if self.has(FactKey.DB_SETTINGS):
            self.add_capability(Capability.DB_CONNECTED)
            self.add_capability(Capability.DB_SETTINGS)
        
        if self.has(FactKey.TABLE_STATS):
            self.add_capability(Capability.DB_STATS)
        
        if self.has(FactKey.TABLE_INDEXES):
            self.add_capability(Capability.DB_INDEXES)
    
    def to_dict(self) -> dict[str, Any]:
        """Export facts as dictionary for debugging/serialization."""
        return {
            "facts": {
                key.value: {
                    "value": str(fact.value)[:100],  # Truncate for display
                    "source": fact.provenance.source_rule,
                    "evidence": fact.provenance.evidence_level,
                }
                for key, fact in self._facts.items()
            },
            "capabilities": sorted(c.value for c in self._capabilities),
        }


def capabilities_from_strings(strings: tuple[str, ...] | set[str]) -> set[Capability]:
    """
    Convert string capability names to Capability enum values.
    
    For backward compatibility with existing rules that use string capabilities.
    Unknown strings are logged and ignored.
    """
    result: set[Capability] = set()
    for s in strings:
        try:
            result.add(Capability(s))
        except ValueError:
            # Unknown capability - could be a custom rule-provided capability
            # Log but don't fail (allows extensibility)
            pass
    return result


def capability_to_string(capability: Capability) -> str:
    """Convert Capability enum to string for backward compatibility."""
    return capability.value


def check_requirements(
    rule: Any,
    capabilities: set[Capability] | frozenset[Capability],
) -> tuple[bool, list[str]]:
    """
    Check if a rule's requirements are met.
    
    Args:
        rule: Rule instance with requires attribute
        capabilities: Set of available Capability enums
        
    Returns:
        Tuple of (can_run, list of missing capability names)
    """
    if not hasattr(rule, 'requires') or not rule.requires:
        return True, []
    
    # Convert rule's string requirements to Capability enum
    required = capabilities_from_strings(rule.requires)
    
    # Check what's missing
    missing = required - set(capabilities)
    
    if missing:
        return False, sorted(c.value for c in missing)
    
    return True, []


# =============================================================================
# DAG Validation and Rule Dependency Checking
# =============================================================================

class CapabilityError(Exception):
    """Base class for capability-related errors."""
    pass


class CycleDetectedError(CapabilityError):
    """Raised when a cycle is detected in the rule dependency DAG."""
    
    def __init__(self, cycle: list[str]) -> None:
        self.cycle = cycle
        super().__init__(f"Cycle detected in rule dependencies: {' -> '.join(cycle)}")


class UnknownCapabilityError(CapabilityError):
    """Raised when a rule requires an unknown capability."""
    
    def __init__(self, rule_id: str, capability: str) -> None:
        self.rule_id = rule_id
        self.capability = capability
        super().__init__(f"Rule {rule_id} requires unknown capability: {capability}")


def validate_capability(cap: str | Capability) -> Capability | None:
    """
    Validate and convert a capability to the enum type.
    
    Returns None if the capability is not recognized (allows custom capabilities).
    """
    if isinstance(cap, Capability):
        return cap
    
    try:
        return Capability(cap)
    except ValueError:
        return None  # Unknown capability - allow for extensibility


def build_rule_dag(rules: list[Any]) -> list[Any]:
    """
    Build and validate the rule dependency DAG.
    
    Returns rules in topological order (dependencies before dependents).
    Raises CycleDetectedError if a cycle is detected.
    
    Algorithm: Kahn's algorithm for topological sorting.
    
    Args:
        rules: List of Rule objects to sort
        
    Returns:
        Rules in topological order
        
    Raises:
        CycleDetectedError: If dependencies form a cycle
    """
    if not rules:
        return []
    
    # Build adjacency list and in-degree count
    rule_map = {r.rule_id: r for r in rules}
    provides_map: dict[str, set[str]] = {}  # capability -> rules that provide it
    
    # First pass: build provides_map
    for rule in rules:
        for cap in rule.provides:
            cap_str = cap.value if isinstance(cap, Capability) else str(cap)
            if cap_str not in provides_map:
                provides_map[cap_str] = set()
            provides_map[cap_str].add(rule.rule_id)
    
    # Build edges: for each rule, find rules that provide what it requires
    edges: dict[str, set[str]] = {r.rule_id: set() for r in rules}
    in_degree: dict[str, int] = {r.rule_id: 0 for r in rules}
    
    for rule in rules:
        for cap in rule.requires:
            cap_str = cap.value if isinstance(cap, Capability) else str(cap)
            
            # Find rules that provide this capability
            providers = provides_map.get(cap_str, set())
            for provider_id in providers:
                if provider_id != rule.rule_id:
                    # Edge: provider -> rule (provider must run first)
                    if rule.rule_id not in edges[provider_id]:
                        edges[provider_id].add(rule.rule_id)
                        in_degree[rule.rule_id] += 1
    
    # Kahn's algorithm
    queue = [rule_id for rule_id, degree in in_degree.items() if degree == 0]
    sorted_ids: list[str] = []
    
    while queue:
        rule_id = queue.pop(0)
        sorted_ids.append(rule_id)
        
        for dependent_id in edges[rule_id]:
            in_degree[dependent_id] -= 1
            if in_degree[dependent_id] == 0:
                queue.append(dependent_id)
    
    # Check for cycle
    if len(sorted_ids) != len(rules):
        # Find the cycle for error message
        remaining = set(rule_map.keys()) - set(sorted_ids)
        cycle = _find_cycle(remaining, edges)
        raise CycleDetectedError(cycle)
    
    return [rule_map[rule_id] for rule_id in sorted_ids]


def _find_cycle(remaining: set[str], edges: dict[str, set[str]]) -> list[str]:
    """Find a cycle in the remaining nodes for error reporting."""
    for start in remaining:
        visited: set[str] = set()
        path: list[str] = []
        
        if _dfs_find_cycle(start, remaining, edges, visited, path):
            return path
    
    return list(remaining)[:5] + ["..."]


def _dfs_find_cycle(
    node: str,
    remaining: set[str],
    edges: dict[str, set[str]],
    visited: set[str],
    path: list[str],
) -> bool:
    """DFS helper to find cycle."""
    if node in visited:
        cycle_start = path.index(node) if node in path else 0
        path[:] = path[cycle_start:] + [node]
        return True
    
    if node not in remaining:
        return False
    
    visited.add(node)
    path.append(node)
    
    for neighbor in edges.get(node, set()):
        if neighbor in remaining:
            if _dfs_find_cycle(neighbor, remaining, edges, visited, path):
                return True
    
    path.pop()
    return False


def check_requirements(
    rule: Any,
    available: set[Capability],
) -> tuple[bool, list[str]]:
    """
    Check if a rule's requirements are satisfied.
    
    Args:
        rule: The rule to check (must have .requires attribute)
        available: Set of available Capability enums
        
    Returns:
        Tuple of (can_run, missing_capabilities_as_strings)
    """
    if not rule.requires:
        return True, []
    
    # Convert available to string set for comparison
    available_strings = {cap.value for cap in available}
    
    # Check each requirement
    missing: list[str] = []
    for cap in rule.requires:
        cap_str = cap.value if isinstance(cap, Capability) else str(cap)
        if cap_str not in available_strings:
            missing.append(cap_str)
    
    if missing:
        return False, missing
    
    return True, []
