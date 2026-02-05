"""
Rule: Spilling to Disk

Detects Sort and Hash operations that exceed work_mem and spill to disk,
causing significant performance degradation.

Why it matters:
- In-memory operations are 10-100x faster than disk-based ones
- Sort spilling uses external merge sort (much slower)
- Hash spilling uses multiple batches with disk I/O
- Indicates work_mem is too low for the workload

When to fix:
- Increase work_mem (per-operation setting)
- Add indexes to avoid sorts
- Reduce result set size before sorting
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput, PlanNode


@register_rule
class SpillingToDisk(Rule):
    """
    Detect Sort and Hash operations spilling to disk.
    
    Checks for:
    - Sort nodes with sort_space_type = "Disk"
    - Sort nodes with sort_method containing "external"
    - Hash nodes with hash_batches > 1
    """
    
    rule_id = "SPILLING_TO_DISK"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects operations spilling to disk due to insufficient work_mem"
    phase = RulePhase.PER_NODE
    
    # Node types that can spill
    SORT_TYPES = {"Sort", "Incremental Sort"}
    HASH_TYPES = {"Hash", "HashAggregate"}
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Find operations that spilled to disk.
        
        Args:
            explain: Parsed EXPLAIN output
            prior_findings: Not used (PER_NODE rule)
            
        Returns:
            List of findings for spilling operations
        """
        findings: list[Finding] = []
        
        for path, node, parent in self.iter_nodes_with_parent(explain):
            finding = None
            
            if node.node_type in self.SORT_TYPES:
                finding = self._check_sort_spill(node, path, parent)
            elif node.node_type in self.HASH_TYPES:
                finding = self._check_hash_spill(node, path, parent)
            
            if finding:
                findings.append(finding)
        
        return findings
    
    def _check_sort_spill(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
    ) -> Finding | None:
        """Check if a Sort node spilled to disk."""
        # Check sort_space_type (most reliable)
        is_disk = node.sort_space_type == "Disk"
        
        # Check sort_method for external sort
        is_external = node.sort_method and "external" in node.sort_method.lower()
        
        if not (is_disk or is_external):
            return None
        
        space_kb = node.sort_space_used or 0
        space_mb = space_kb / 1024
        
        # Escalate to CRITICAL for large spills (> 100MB)
        severity = Severity.CRITICAL if space_mb > 100 else self.severity
        
        context = NodeContext.from_node(node, path, parent)
        
        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=f"Sort spilled {space_mb:.1f}MB to disk",
            description=self._build_sort_description(node, space_mb),
            suggestion=self._build_sort_suggestion(node, space_mb),
            metrics={
                "space_used_kb": space_kb,
                "space_used_mb": space_mb,
            },
        )
    
    def _check_hash_spill(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
    ) -> Finding | None:
        """Check if a Hash node spilled to multiple batches."""
        # hash_batches > 1 means data didn't fit in work_mem
        if node.hash_batches is None or node.hash_batches <= 1:
            return None
        
        batches = node.hash_batches
        memory_kb = node.peak_memory_usage or 0
        memory_mb = memory_kb / 1024
        
        # More batches = more severity
        if batches > 16:
            severity = Severity.CRITICAL
        elif batches > 4:
            severity = Severity.WARNING
        else:
            severity = Severity.INFO
        
        context = NodeContext.from_node(node, path, parent)
        
        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=f"Hash used {batches} batches (spilled to disk)",
            description=self._build_hash_description(node, batches, memory_mb),
            suggestion=self._build_hash_suggestion(node, batches, memory_mb),
            metrics={
                "hash_batches": batches,
                "hash_buckets": node.hash_buckets or 0,
                "peak_memory_kb": memory_kb,
                "peak_memory_mb": memory_mb,
            },
        )
    
    def _build_sort_description(self, node: "PlanNode", space_mb: float) -> str:
        """Build description for sort spill."""
        parts = [
            f"Sort operation exceeded work_mem and spilled {space_mb:.1f}MB to disk."
        ]
        
        if node.sort_method:
            parts.append(f"Using {node.sort_method} algorithm.")
        
        if node.sort_key:
            keys = ", ".join(node.sort_key[:3])
            if len(node.sort_key) > 3:
                keys += f" (+{len(node.sort_key) - 3} more)"
            parts.append(f"Sorting on: {keys}.")
        
        parts.append(
            "External sorts are 10-100x slower than in-memory sorts "
            "due to disk I/O overhead."
        )
        
        return " ".join(parts)
    
    def _build_hash_description(
        self,
        node: "PlanNode",
        batches: int,
        memory_mb: float,
    ) -> str:
        """Build description for hash spill."""
        parts = [
            f"Hash operation used {batches} batches because data exceeded work_mem."
        ]
        
        if memory_mb > 0:
            parts.append(f"Peak memory usage: {memory_mb:.1f}MB.")
        
        parts.append(
            f"Each additional batch requires disk I/O, significantly slowing the operation. "
            f"With {batches} batches, data is being read/written multiple times."
        )
        
        return " ".join(parts)
    
    def _build_sort_suggestion(self, node: "PlanNode", space_mb: float) -> str:
        """Build suggestion for sort spill."""
        # Recommend work_mem at least 2x the spill size
        recommended_mb = int(max(space_mb * 2, 64))
        
        lines = [
            f"SET work_mem = '{recommended_mb}MB';  -- Increase from default 4MB",
            "",
            "-- Or set per-session for heavy queries:",
            f"SET LOCAL work_mem = '{recommended_mb}MB';",
            "",
        ]
        
        if node.sort_key:
            lines.append("-- Consider adding an index to avoid sorting:")
            keys_str = ", ".join(node.sort_key[:3])
            lines.append(f"CREATE INDEX idx_sort ON <table>({keys_str});")
            lines.append("")
        
        lines.append("-- Docs: https://www.postgresql.org/docs/current/runtime-config-resource.html#GUC-WORK-MEM")
        
        return "\n".join(lines)
    
    def _build_hash_suggestion(
        self,
        node: "PlanNode",
        batches: int,
        memory_mb: float,
    ) -> str:
        """Build suggestion for hash spill."""
        # work_mem should be large enough to fit hash in one batch
        # Rule of thumb: double the memory per batch reduction needed
        current = max(memory_mb, 4)  # Assume at least default 4MB
        recommended_mb = int(current * batches * 1.5)
        recommended_mb = min(recommended_mb, 4096)  # Cap at 4GB
        
        lines = [
            f"SET work_mem = '{recommended_mb}MB';  -- Fit hash table in memory",
            "",
            "-- Note: work_mem is per-operation, not per-query",
            "-- A complex query may use work_mem multiple times",
            "",
            "-- For a single heavy query, use LOCAL:",
            f"SET LOCAL work_mem = '{recommended_mb}MB';",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/runtime-config-resource.html#GUC-WORK-MEM",
        ]
        
        return "\n".join(lines)
