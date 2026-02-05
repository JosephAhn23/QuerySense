"""
Query plan comparison and diff analysis.

Enables before/after comparison of query optimizations:
- Which issues were fixed?
- What new issues appeared?
- How did metrics change?

This is essential for the optimization workflow where users want
to verify their changes actually improved the query.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding


@dataclass(frozen=True)
class FindingDelta:
    """
    Change in a finding between two analyses.
    
    Tracks how a finding changed:
    - new: Finding appeared in after, not in before
    - fixed: Finding was in before, not in after
    - changed: Finding exists in both but metrics changed
    - unchanged: Finding is identical in both
    """
    
    finding: "Finding"
    status: Literal["new", "fixed", "changed", "unchanged"]
    before_metrics: dict[str, int | float] | None = None
    after_metrics: dict[str, int | float] | None = None
    
    @property
    def is_improvement(self) -> bool:
        """True if this delta represents an improvement."""
        if self.status == "fixed":
            return True
        if self.status == "changed" and self.before_metrics and self.after_metrics:
            # Check if key metrics improved (lower is better for most)
            before_rows = self.before_metrics.get("rows_scanned", 0)
            after_rows = self.after_metrics.get("rows_scanned", 0)
            return after_rows < before_rows
        return False
    
    @property
    def is_regression(self) -> bool:
        """True if this delta represents a regression."""
        if self.status == "new":
            return True
        if self.status == "changed" and self.before_metrics and self.after_metrics:
            before_rows = self.before_metrics.get("rows_scanned", 0)
            after_rows = self.after_metrics.get("rows_scanned", 0)
            return after_rows > before_rows
        return False
    
    def metric_delta(self, metric_name: str) -> float | None:
        """
        Get the change in a specific metric.
        
        Args:
            metric_name: Name of the metric to compare
            
        Returns:
            after - before value, or None if metric missing
        """
        if not self.before_metrics or not self.after_metrics:
            return None
        
        before = self.before_metrics.get(metric_name)
        after = self.after_metrics.get(metric_name)
        
        if before is None or after is None:
            return None
        
        return after - before


@dataclass
class AnalysisComparison:
    """
    Comparison of two analysis results (before vs after optimization).
    
    Provides a complete picture of what changed between two query plans,
    enabling users to verify their optimization efforts.
    
    Example:
        before = analyzer.analyze(explain_before)
        after = analyzer.analyze(explain_after)
        
        comparison = compare_analyses(before, after)
        
        print(f"Fixed: {len(comparison.fixed_issues)}")
        print(f"New: {len(comparison.new_issues)}")
        print(f"Net improvement: {comparison.net_improvement:+d}")
    """
    
    before: "AnalysisResult"
    after: "AnalysisResult"
    
    fixed_issues: list["Finding"] = field(default_factory=list)
    new_issues: list["Finding"] = field(default_factory=list)
    unchanged_issues: list["Finding"] = field(default_factory=list)
    changed_issues: list[FindingDelta] = field(default_factory=list)
    
    @property
    def net_improvement(self) -> int:
        """
        Net change in issue count.
        
        Positive = fewer issues (better)
        Negative = more issues (worse)
        """
        return len(self.fixed_issues) - len(self.new_issues)
    
    @property
    def is_improvement(self) -> bool:
        """True if overall the query improved."""
        return self.net_improvement > 0
    
    @property
    def is_regression(self) -> bool:
        """True if overall the query got worse."""
        return self.net_improvement < 0
    
    @property
    def total_cost_delta(self) -> float:
        """
        Change in total cost across all findings.
        
        Negative = lower cost (better)
        Positive = higher cost (worse)
        """
        before_cost = sum(
            f.metrics.get("total_cost", 0) for f in self.before.findings
        )
        after_cost = sum(
            f.metrics.get("total_cost", 0) for f in self.after.findings
        )
        return after_cost - before_cost
    
    @property
    def total_rows_delta(self) -> int:
        """
        Change in total rows scanned across all findings.
        
        Negative = fewer rows (better)
        Positive = more rows (worse)
        """
        before_rows = sum(
            int(f.metrics.get("rows_scanned", 0)) for f in self.before.findings
        )
        after_rows = sum(
            int(f.metrics.get("rows_scanned", 0)) for f in self.after.findings
        )
        return after_rows - before_rows
    
    @property
    def severity_improvement(self) -> dict[str, int]:
        """
        Change in issue count by severity.
        
        Returns:
            Dict with severity -> delta (negative = fewer issues)
        """
        from querysense.analyzer.models import Severity
        
        before_counts = {s: 0 for s in Severity}
        after_counts = {s: 0 for s in Severity}
        
        for f in self.before.findings:
            before_counts[f.severity] += 1
        for f in self.after.findings:
            after_counts[f.severity] += 1
        
        return {
            s.value: after_counts[s] - before_counts[s]
            for s in Severity
        }
    
    def summary(self) -> dict[str, int | float | bool]:
        """
        Get a summary of the comparison.
        
        Returns:
            Dict with key metrics about the comparison
        """
        return {
            "fixed_count": len(self.fixed_issues),
            "new_count": len(self.new_issues),
            "unchanged_count": len(self.unchanged_issues),
            "changed_count": len(self.changed_issues),
            "net_improvement": self.net_improvement,
            "is_improvement": self.is_improvement,
            "total_cost_delta": self.total_cost_delta,
            "total_rows_delta": self.total_rows_delta,
        }
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": self.summary(),
            "fixed_issues": [f.model_dump(mode="json") for f in self.fixed_issues],
            "new_issues": [f.model_dump(mode="json") for f in self.new_issues],
            "unchanged_count": len(self.unchanged_issues),
            "changed_issues": [
                {
                    "finding": d.finding.model_dump(mode="json"),
                    "status": d.status,
                    "before_metrics": d.before_metrics,
                    "after_metrics": d.after_metrics,
                }
                for d in self.changed_issues
            ],
            "severity_changes": self.severity_improvement,
        }


def _finding_key(finding: "Finding") -> str:
    """
    Generate a key for matching findings across analyses.
    
    Uses rule_id + node path + relation name for stable matching
    even when metrics change.
    """
    return f"{finding.rule_id}:{finding.context.path}:{finding.context.relation_name}"


def compare_analyses(
    before: "AnalysisResult",
    after: "AnalysisResult",
) -> AnalysisComparison:
    """
    Compare two analysis results to identify what changed.
    
    Matches findings by rule_id and node path, then categorizes
    them as fixed, new, changed, or unchanged.
    
    Args:
        before: Analysis result before optimization
        after: Analysis result after optimization
        
    Returns:
        AnalysisComparison with categorized findings
        
    Example:
        comparison = compare_analyses(before_result, after_result)
        
        if comparison.is_improvement:
            print(f"Great! Fixed {len(comparison.fixed_issues)} issues")
        else:
            print(f"Warning: {len(comparison.new_issues)} new issues")
    """
    # Build lookup maps by key
    before_map = {_finding_key(f): f for f in before.findings}
    after_map = {_finding_key(f): f for f in after.findings}
    
    # Find fixed issues (in before, not in after)
    fixed_issues = [
        f for key, f in before_map.items()
        if key not in after_map
    ]
    
    # Find new issues (in after, not in before)
    new_issues = [
        f for key, f in after_map.items()
        if key not in before_map
    ]
    
    # Find unchanged and changed issues
    unchanged_issues: list["Finding"] = []
    changed_issues: list[FindingDelta] = []
    
    common_keys = set(before_map.keys()) & set(after_map.keys())
    
    for key in common_keys:
        before_finding = before_map[key]
        after_finding = after_map[key]
        
        if before_finding.metrics == after_finding.metrics:
            unchanged_issues.append(after_finding)
        else:
            changed_issues.append(FindingDelta(
                finding=after_finding,
                status="changed",
                before_metrics=dict(before_finding.metrics),
                after_metrics=dict(after_finding.metrics),
            ))
    
    return AnalysisComparison(
        before=before,
        after=after,
        fixed_issues=fixed_issues,
        new_issues=new_issues,
        unchanged_issues=unchanged_issues,
        changed_issues=changed_issues,
    )


def compare_explains(
    before_explain: "ExplainOutput",
    after_explain: "ExplainOutput",
    analyzer: "Analyzer",
) -> AnalysisComparison:
    """
    Convenience function to compare two EXPLAIN outputs.
    
    Runs analysis on both and returns the comparison.
    
    Args:
        before_explain: EXPLAIN output before optimization
        after_explain: EXPLAIN output after optimization
        analyzer: Analyzer instance to use
        
    Returns:
        AnalysisComparison with categorized findings
    """
    # Import here to avoid circular import
    from querysense.parser.models import ExplainOutput
    
    before_result = analyzer.analyze(before_explain)
    after_result = analyzer.analyze(after_explain)
    
    return compare_analyses(before_result, after_result)
