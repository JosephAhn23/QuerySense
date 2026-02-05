"""Query plan analyzer module - simple rule engine."""

from querysense.analyzer.analyzer import Analyzer
from querysense.analyzer.comparator import (
    AnalysisComparison,
    FindingDelta,
    compare_analyses,
    compare_explains,
)
from querysense.analyzer.errors import AnalyzerError, ConfigurationError, RuleError
from querysense.analyzer.fingerprint import (
    AnalysisCache,
    CachedAnalysis,
    PlanDiff,
    PlanFingerprint,
)
from querysense.analyzer.index_advisor import (
    CostEstimator,
    IndexRecommendation,
    IndexRecommender,
    recommend_indexes,
)
from querysense.analyzer.sql_parser import (
    ColumnInfo,
    QueryInfo,
    SQLQueryAnalyzer,
    analyze_sql,
    suggest_indexes_for_query,
)
from querysense.analyzer.models import (
    AnalysisResult,
    ExecutionMetadata,
    Finding,
    NodeContext,
    RulePhase,
    Severity,
)
from querysense.analyzer.path import NodePath, traverse_with_path
from querysense.analyzer.registry import (
    RuleRegistry,
    get_registry,
    register_rule,
    reset_registry,
)
from querysense.analyzer.rules.base import Rule, RuleConfig
from querysense.analyzer.safety import (
    QuerySafetyChecker,
    QueryType,
    SafetyCheckResult,
    UnsafeQueryError,
)

# Import rules to register them
from querysense.analyzer.rules import bad_row_estimate as _bad_estimate  # noqa: F401
from querysense.analyzer.rules import correlated_subquery as _subquery  # noqa: F401
from querysense.analyzer.rules import excessive_seq_scans as _excessive  # noqa: F401
from querysense.analyzer.rules import missing_buffers as _buffers  # noqa: F401
from querysense.analyzer.rules import nested_loop_large_table as _nested_loop  # noqa: F401
from querysense.analyzer.rules import parallel_query_not_used as _parallel  # noqa: F401
from querysense.analyzer.rules import seq_scan_large_table as _seq_scan  # noqa: F401
from querysense.analyzer.rules import spilling_to_disk as _spilling  # noqa: F401

__all__ = [
    # Main orchestrator
    "Analyzer",
    # Models
    "Finding",
    "Severity",
    "AnalysisResult",
    "ExecutionMetadata",
    "NodeContext",
    "RulePhase",
    # Path handling
    "NodePath",
    "traverse_with_path",
    # Registry
    "RuleRegistry",
    "get_registry",
    "register_rule",
    "reset_registry",
    # Rules
    "Rule",
    "RuleConfig",
    # Errors
    "AnalyzerError",
    "RuleError",
    "ConfigurationError",
    # Fingerprinting and caching
    "PlanFingerprint",
    "PlanDiff",
    "AnalysisCache",
    "CachedAnalysis",
    # Safety
    "QuerySafetyChecker",
    "SafetyCheckResult",
    "QueryType",
    "UnsafeQueryError",
    # Comparison
    "AnalysisComparison",
    "FindingDelta",
    "compare_analyses",
    "compare_explains",
    # Index Advisor
    "IndexRecommender",
    "IndexRecommendation",
    "CostEstimator",
    "recommend_indexes",
    # SQL Parser
    "SQLQueryAnalyzer",
    "QueryInfo",
    "ColumnInfo",
    "analyze_sql",
    "suggest_indexes_for_query",
]
