"""
Rule: Bad Row Estimate

Detects severe mismatches between planner estimates and actual row counts.
This is one of the most important issues to catch - stale statistics cause
more real-world performance issues than missing indexes.

Why it matters:
- PostgreSQL plans queries based on row estimates
- Wrong estimates → wrong join strategies, wrong index choices, wrong memory allocation
- A 1000x error means the planner is making decisions based on lies

When it happens:
- After bulk INSERT/UPDATE/DELETE without ANALYZE
- Tables with uneven data distribution
- Tables with many NULLs
- After schema changes
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


@register_rule
class BadRowEstimate(Rule):
    """
    Detect severe row estimation errors.
    
    Severity based on ratio:
    - > 1000x: CRITICAL (production emergency)
    - > 100x: WARNING (needs attention)
    - > 10x: INFO (worth investigating)
    """
    
    rule_id = "BAD_ROW_ESTIMATE"
    version = "1.0.0"
    severity = Severity.WARNING  # Default, overridden based on ratio
    description = "Detects severe mismatches between estimated and actual rows"
    phase = RulePhase.PER_NODE
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find nodes with severe estimation errors."""
        findings: list[Finding] = []
        
        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Need both estimate and actual to compare
            if node.plan_rows is None or node.actual_rows is None:
                continue
            
            # Skip tiny tables (noise)
            if node.actual_rows < 100:
                continue
            
            # Calculate ratio (handle division by zero)
            estimated = max(node.plan_rows, 1)
            actual = node.actual_rows
            
            # Ratio can be in either direction
            if actual > estimated:
                ratio = actual / estimated
                direction = "underestimated"
            else:
                ratio = estimated / actual
                direction = "overestimated"
            
            # Skip small errors
            if ratio < 10:
                continue
            
            # Determine severity based on ratio
            if ratio >= 1000:
                severity = Severity.CRITICAL
            elif ratio >= 100:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO
            
            # Build context
            context = NodeContext.from_node(node, path, parent)
            table_name = node.relation_name or "unknown table"
            
            finding = Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Row estimation error on {table_name} ({ratio:,.0f}x off)",
                description=self._build_description(node, ratio, direction),
                suggestion=self._build_suggestion(node, ratio),
                metrics={
                    "estimated_rows": node.plan_rows,
                    "actual_rows": actual,
                    "ratio": ratio,
                },
            )
            findings.append(finding)
        
        return findings
    
    def _build_description(self, node, ratio: float, direction: str) -> str:
        """Build description explaining the impact."""
        table = node.relation_name or "this table"
        
        parts = [
            f"Planner {direction} by {ratio:,.0f}x.",
            f"Estimated: {node.plan_rows:,} rows. Actual: {node.actual_rows:,} rows.",
        ]
        
        if ratio >= 100:
            parts.append(
                "When estimates are this wrong, PostgreSQL makes bad decisions: "
                "picks wrong join strategies, disables helpful indexes, "
                "allocates insufficient memory."
            )
        
        return " ".join(parts)
    
    def _build_suggestion(self, node, ratio: float) -> str:
        """Build actionable suggestion."""
        table = node.relation_name
        docs_url = "https://www.postgresql.org/docs/current/routine-vacuuming.html#VACUUM-FOR-STATISTICS"
        
        if table:
            sql = f"ANALYZE {table};"
        else:
            sql = "ANALYZE;"
        
        lines = [
            sql,
            "-- Run ANALYZE after bulk inserts/updates/deletes",
            "-- Consider: CREATE STATISTICS for correlated columns",
            f"-- Docs: {docs_url}",
        ]
        
        return "\n".join(lines)
