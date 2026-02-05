"""
Data models for the analyzer module.

These models represent the output of analysis rules - the issues detected
in query plans. They're designed to be:
- Immutable (frozen=True): Findings don't change after creation
- Serializable: Easy JSON output for --json flag
- Hashable: Can be used in sets for deduplication
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from querysense.analyzer.path import NodePath

if TYPE_CHECKING:
    from querysense.analyzer.errors import RuleError
    from querysense.parser.models import PlanNode


class RulePhase(IntEnum):
    """
    Execution phases for rules.
    
    PER_NODE: Analyze individual nodes (default, runs first)
    AGGREGATE: Analyze patterns across entire query (runs second, sees prior findings)
    """
    PER_NODE = 1
    AGGREGATE = 2


class Severity(str, Enum):
    """
    Severity levels for findings.
    
    CRITICAL: Query will fail, cause outage, or has severe performance impact
    WARNING: Significant performance issue that should be addressed
    INFO: Optimization opportunity, nice-to-have improvement
    """
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    
    def __lt__(self, other: object) -> bool:
        """Enable sorting by severity (CRITICAL > WARNING > INFO)."""
        if not isinstance(other, Severity):
            return NotImplemented
        order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        return order[self] < order[other]


@dataclass(frozen=True)
class NodeContext:
    """
    Complete context about a problematic node.
    
    Captures all relevant information from a PlanNode so that:
    - The explainer has full context for generating explanations
    - We avoid storing the entire PlanNode (circular refs, size)
    - Findings remain serializable and hashable
    
    Attributes:
        path: Location in the plan tree
        node_type: The PostgreSQL node type (e.g., "Seq Scan")
        relation_name: Table being accessed, if applicable
        actual_rows: Actual rows processed (from ANALYZE)
        plan_rows: Estimated rows (planner's guess)
        total_cost: Total cost estimate
        filter: Filter condition if present
        index_name: Index being used, if applicable
        parent_node_type: Parent node's type for context
        depth: Depth in the plan tree (0 = root)
    """
    
    path: NodePath
    node_type: str
    relation_name: str | None = None
    actual_rows: int | None = None
    plan_rows: int | None = None
    total_cost: float = 0.0
    startup_cost: float = 0.0
    filter: str | None = None
    index_name: str | None = None
    index_cond: str | None = None
    parent_node_type: str | None = None
    depth: int = 0
    rows_removed_by_filter: int | None = None
    
    @classmethod
    def from_node(
        cls,
        node: "PlanNode",
        path: NodePath,
        parent: "PlanNode | None" = None,
    ) -> "NodeContext":
        """
        Extract relevant context from a PlanNode.
        
        Args:
            node: The plan node to extract context from
            path: Path to this node in the tree
            parent: Parent node for additional context
            
        Returns:
            NodeContext with all relevant fields populated
        """
        return cls(
            path=path,
            node_type=node.node_type,
            relation_name=node.relation_name,
            actual_rows=node.actual_rows,
            plan_rows=node.plan_rows,
            total_cost=node.total_cost,
            startup_cost=node.startup_cost,
            filter=node.filter,
            index_name=node.index_name,
            index_cond=node.index_cond,
            parent_node_type=parent.node_type if parent else None,
            depth=path.depth,
            rows_removed_by_filter=node.rows_removed_by_filter,
        )
    
    @classmethod
    def root(cls, node_type: str = "Query") -> "NodeContext":
        """Create a root context for aggregate findings."""
        return cls(path=NodePath.root(), node_type=node_type)
    
    @property
    def row_estimate_ratio(self) -> float | None:
        """Ratio of actual to estimated rows (indicates statistics accuracy)."""
        if self.actual_rows is None or self.plan_rows is None or self.plan_rows == 0:
            return None
        return self.actual_rows / self.plan_rows
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "path": list(self.path.segments),
            "node_type": self.node_type,
            "relation_name": self.relation_name,
            "actual_rows": self.actual_rows,
            "plan_rows": self.plan_rows,
            "total_cost": self.total_cost,
            "filter": self.filter,
            "index_name": self.index_name,
            "parent_node_type": self.parent_node_type,
            "depth": self.depth,
        }


class Finding(BaseModel):
    """
    A single issue detected in a query plan.
    
    Findings are the output of analyzer rules. Each finding represents
    a specific performance issue at a specific location in the plan tree.
    
    Attributes:
        rule_id: Unique identifier for the rule that generated this finding.
            Convention: UPPER_SNAKE_CASE (e.g., "SEQ_SCAN_LARGE_TABLE").
        severity: How serious the issue is.
        context: Full context about the problematic node (type, rows, filter, etc.)
        title: Human-readable one-line summary.
        description: Detailed explanation of why this is a problem.
        suggestion: Actionable fix recommendation, if applicable.
        metrics: Quantitative data about the issue for programmatic use.
        explanation: LLM-generated explanation (populated by explainer).
        explanation_error: Error message if explanation generation failed.
    
    Example:
        Finding(
            rule_id="SEQ_SCAN_LARGE_TABLE",
            severity=Severity.WARNING,
            context=NodeContext.from_node(node, path),
            title="Sequential scan on orders (1,234,567 rows)",
            description="Scanning over 1M rows sequentially is expensive...",
            suggestion="Consider adding an index on orders(status)",
            metrics={"rows_scanned": 1234567, "total_cost": 45000.0},
        )
    """
    
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    
    rule_id: str = Field(
        ...,
        description="Unique identifier for the rule (UPPER_SNAKE_CASE)",
    )
    
    severity: Severity = Field(
        ...,
        description="Severity level of the finding",
    )
    
    context: NodeContext = Field(
        ...,
        description="Full context about the problematic node",
    )
    
    title: str = Field(
        ...,
        min_length=1,
        description="Human-readable one-line summary",
    )
    
    description: str = Field(
        ...,
        min_length=1,
        description="Detailed explanation of the issue",
    )
    
    suggestion: str | None = Field(
        default=None,
        description="Actionable fix recommendation",
    )
    
    metrics: dict[str, int | float] = Field(
        default_factory=dict,
        description="Quantitative data about the issue",
    )
    
    # LLM explanation (populated by explainer if enabled)
    explanation: str | None = Field(
        default=None,
        description="LLM-generated explanation of the issue",
    )
    
    explanation_error: str | None = Field(
        default=None,
        description="Error message if explanation generation failed",
    )
    
    # Backward compatibility: expose path from context
    @property
    def node_path(self) -> NodePath:
        """Path to the node (for backward compatibility)."""
        return self.context.path
    
    def cache_key(self, model: str, rule_version: str) -> str:
        """
        Generate a deterministic cache key for LLM explanations.
        
        The key includes:
        - LLM model name (explanations differ by model quality)
        - Rule ID and version (logic changes invalidate cache)
        - Context details (filter, rows, etc.)
        
        Args:
            model: The LLM model name (e.g., "claude-sonnet-4-20250514")
            rule_version: Version of the rule that generated this finding
            
        Returns:
            16-character hex string suitable as a cache key
        """
        context_data = {
            "node_type": self.context.node_type,
            "relation_name": self.context.relation_name,
            "actual_rows": self.context.actual_rows,
            "plan_rows": self.context.plan_rows,
            "filter": self.context.filter,
        }
        context_json = json.dumps(context_data, sort_keys=True)
        metrics_json = json.dumps(self.metrics, sort_keys=True)
        content = f"{model}:{self.rule_id}:{rule_version}:{context_json}:{metrics_json}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def with_explanation(
        self,
        explanation: str | None,
        error: str | None = None,
    ) -> "Finding":
        """
        Create a copy of this finding with explanation added.
        
        Since Finding is frozen, this returns a new instance.
        
        Args:
            explanation: The LLM-generated explanation
            error: Error message if explanation failed
            
        Returns:
            New Finding with explanation populated
        """
        return self.model_copy(update={
            "explanation": explanation,
            "explanation_error": error,
        })
    
    def __lt__(self, other: "Finding") -> bool:
        """
        Enable deterministic sorting of findings.
        
        Sort order: severity (CRITICAL first), then rule_id, then path.
        This ensures consistent output across runs.
        """
        return (self.severity, self.rule_id, self.context.path.segments) < (
            other.severity, other.rule_id, other.context.path.segments
        )
    
    def __hash__(self) -> int:
        """Enable use in sets for deduplication."""
        return hash((
            self.rule_id,
            self.severity,
            self.context.path.segments,
            self.context.node_type,
            self.context.relation_name,
            tuple(sorted(self.metrics.items())),
        ))


class ExecutionMetadata(BaseModel):
    """
    Metadata about analysis execution.
    
    Separated from AnalysisResult to keep the results clean and allow
    execution metadata to grow independently (timing, caching stats, etc.)
    """
    
    model_config = ConfigDict(frozen=True)
    
    node_count: int = Field(
        default=0,
        description="Total number of nodes in the plan",
    )
    
    execution_time_ms: float | None = Field(
        default=None,
        description="Query execution time from EXPLAIN ANALYZE",
    )
    
    rules_run: int = Field(
        default=0,
        description="Number of rules that were executed",
    )
    
    rules_failed: int = Field(
        default=0,
        description="Number of rules that failed with errors",
    )
    
    # Future fields can be added here without changing AnalysisResult interface:
    # analysis_duration_ms: float | None = None
    # cache_hits: int = 0
    # llm_calls: int = 0
    
    @property
    def success_rate(self) -> float:
        """Fraction of rules that completed successfully."""
        if self.rules_run == 0:
            return 1.0
        return (self.rules_run - self.rules_failed) / self.rules_run


class AnalysisResult(BaseModel):
    """
    Complete result of analyzing an EXPLAIN output.
    
    Contains:
    - findings: All detected issues, sorted by severity
    - errors: Any rule execution errors (analysis continues despite errors)
    - metadata: Execution statistics (node count, timing, etc.)
    """
    
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    
    findings: tuple[Finding, ...] = Field(
        default_factory=tuple,
        description="All findings, sorted by severity",
    )
    
    errors: tuple[Any, ...] = Field(
        default_factory=tuple,
        description="Errors from rules that failed (RuleError instances)",
    )
    
    metadata: ExecutionMetadata = Field(
        default_factory=ExecutionMetadata,
        description="Execution metadata (timing, counts)",
    )
    
    # Convenience properties that delegate to metadata
    @property
    def node_count(self) -> int:
        """Total number of nodes in the plan."""
        return self.metadata.node_count
    
    @property
    def rules_run(self) -> int:
        """Number of rules executed."""
        return self.metadata.rules_run
    
    @property
    def rules_failed(self) -> int:
        """Number of rules that failed."""
        return self.metadata.rules_failed
    
    @property
    def has_critical(self) -> bool:
        """Check if any critical issues were found."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)
    
    @property
    def has_warnings(self) -> bool:
        """Check if any warnings were found."""
        return any(f.severity == Severity.WARNING for f in self.findings)
    
    @property
    def has_errors(self) -> bool:
        """Check if any rules failed during analysis."""
        return len(self.errors) > 0
    
    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def summary(self) -> dict[str, int | float]:
        """Get a summary count by severity and success rate."""
        return {
            "total": len(self.findings),
            "critical": len(self.findings_by_severity(Severity.CRITICAL)),
            "warning": len(self.findings_by_severity(Severity.WARNING)),
            "info": len(self.findings_by_severity(Severity.INFO)),
            "errors": len(self.errors),
            "success_rate": self.metadata.success_rate,
        }
