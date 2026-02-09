"""QuerySense - Database query performance analyzer for PostgreSQL and MySQL."""

__version__ = "0.5.2"
__license__ = "MIT"

# Exception hierarchy (import first so other modules can use it)
from querysense.exceptions import (
    QuerySenseError,
    AnalyzerError,
    RuleError,
    ConfigurationError,
    ParseError,
    IRConversionError,
    BaselineError,
    PolicyError,
    CloudError,
)

# Plan IR (Intermediate Representation) - engine-agnostic plan algebra
from querysense.ir import (
    IRNode,
    IRPlan,
    IROperator,
    AggregateStrategy,
    ScanMethod,
    JoinAlgorithm,
    SortVariant,
)
from querysense.ir.node import EngineType

# Public API exports
from querysense.analyzer.analyzer import (
    Analyzer,
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
from querysense.analyzer.observability import AnalyzerMetrics
from querysense.baseline import (
    BaselineDiff,
    BaselineStore,
    RegressionSeverity,
    RegressionVerdict,
)
from querysense.config import (
    Config,
    Environment,
    get_config,
)
from querysense.engine import (
    AnalysisReport,
    AnalysisService,
    BatchReport,
    UpgradeReport,
)
from querysense.parser.parser import parse_explain
from querysense.policy import (
    Policy,
    PolicyViolation,
    load_policy,
)
from querysense.scorecard import (
    LeverageScorecard,
    score_problem,
)

__all__ = [
    # Exception hierarchy
    "QuerySenseError",
    "AnalyzerError",
    "RuleError",
    "ConfigurationError",
    "ParseError",
    "IRConversionError",
    "BaselineError",
    "PolicyError",
    "CloudError",
    # Core
    "Analyzer",
    "AnalysisService",
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
    # Baseline & Regression Prevention (primary product surface)
    "BaselineDiff",
    "BaselineStore",
    "RegressionSeverity",
    "RegressionVerdict",
    # Engine & Orchestration
    "AnalysisReport",
    "BatchReport",
    "UpgradeReport",
    # Policy Enforcement (CI gating distribution channel)
    "Policy",
    "PolicyViolation",
    "load_policy",
    # Domain Leverage Scorecard
    "LeverageScorecard",
    "score_problem",
    # Configuration
    "Config",
    "Environment",
    "get_config",
    # Observability
    "AnalyzerMetrics",
    # Utilities
    "get_current_query_info",
    # Plan IR (Intermediate Representation)
    "IRNode",
    "IRPlan",
    "IROperator",
    "EngineType",
    "AggregateStrategy",
    "ScanMethod",
    "JoinAlgorithm",
    "SortVariant",
    # Metadata
    "__version__",
    "__license__",
]