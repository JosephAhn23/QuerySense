"""QuerySense - Database query performance analyzer for PostgreSQL and MySQL."""

__version__ = "0.4.0"
__license__ = "MIT"

# Public API exports
from querysense.analyzer.analyzer import (
    Analyzer,
    AnalyzerMetrics,
    get_current_query_info,
)
from querysense.analyzer.models import (
    AnalysisResult,
    ExecutionMetadata,
    Finding,
    NodeContext,
    RulePhase,
    Severity,
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
    "Severity",
    # Observability
    "AnalyzerMetrics",
    # Utilities
    "get_current_query_info",
    # Metadata
    "__version__",
    "__license__",
]
