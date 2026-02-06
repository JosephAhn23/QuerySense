"""QuerySense - Database query performance analyzer for PostgreSQL and MySQL."""

__version__ = "0.5.2"
__license__ = "MIT"

# Public API exports
from querysense.analyzer.analyzer import (
    Analyzer,
    AnalyzerMetrics,
    get_current_query_info,
)
from querysense.analyzer.comparator import (
    AnalysisComparison,
    PlanComparison,
    compare_analyses,
    compare_plans,
)
from querysense.analyzer.models import (
    AnalysisResult,
    EvidenceLevel,
    ExecutionMetadata,
    Finding,
    ImpactBand,
    NodeContext,
    RulePhase,
    RuleRun,
    RuleRunStatus,
    Severity,
    SQLConfidence,
)
from querysense.config import (
    Config,
    Environment,
    get_config,
)
from querysense.parser.parser import parse_explain

__all__ = [
    # Core
    "Analyzer",
    "parse_explain",
    # Models
    "AnalysisResult",
    "ExecutionMetadata",
    "Finding",
    "NodeContext",
    "RulePhase",
    "RuleRun",
    "RuleRunStatus",
    "Severity",
    # Evidence & Impact
    "EvidenceLevel",
    "ImpactBand",
    "SQLConfidence",
    # Comparison
    "AnalysisComparison",
    "PlanComparison",
    "compare_analyses",
    "compare_plans",
    # Configuration
    "Config",
    "Environment",
    "get_config",
    # Observability
    "AnalyzerMetrics",
    # Utilities
    "get_current_query_info",
    # Metadata
    "__version__",
    "__license__",
]
