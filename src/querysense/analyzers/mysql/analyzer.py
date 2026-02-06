"""
MySQL EXPLAIN analyzer.

Analyzes parsed MySQL EXPLAIN output and detects performance issues.
"""

from __future__ import annotations

from typing import Any

from querysense.analyzer.models import Finding, NodeContext, Severity
from querysense.analyzer.path import NodePath
from querysense.analyzers.base import BaseAnalyzer
from querysense.analyzers.mysql.parser import MySQLParser, MySQLExplainOutput, MySQLPlanNode


class MySQLAnalyzer(BaseAnalyzer):
    """
    Analyzer for MySQL EXPLAIN output.
    
    Detects common MySQL performance issues:
    - Full table scans (type='ALL')
    - Missing indexes (key=NULL with possible_keys)
    - Filesort operations
    - Temporary table usage
    - Inefficient join types
    """
    
    # Thresholds
    LARGE_TABLE_THRESHOLD = 10_000
    
    def __init__(self) -> None:
        self.parser = MySQLParser()
        self._rules: list = []  # Will be populated with rule instances
    
    @property
    def database_name(self) -> str:
        return "MySQL"
    
    def parse_plan(self, plan: dict[str, Any] | list[dict[str, Any]]) -> MySQLExplainOutput:
        """Parse MySQL EXPLAIN output."""
        return self.parser.parse(plan)
    
    def detect_issues(self, parsed_plan: MySQLExplainOutput) -> list[Finding]:
        """
        Detect performance issues in MySQL EXPLAIN output.
        
        Args:
            parsed_plan: Parsed MySQLExplainOutput
            
        Returns:
            List of Finding objects
        """
        findings: list[Finding] = []
        
        for i, node in enumerate(parsed_plan.nodes):
            # Full table scan on large table
            if node.is_full_table_scan and node.rows >= self.LARGE_TABLE_THRESHOLD:
                findings.append(self._finding_full_table_scan(node, i))
            
            # Possible index not used (but indexes exist)
            if node.has_unused_index:
                findings.append(self._finding_missing_index(node, i))
            
            # No index available at all
            elif self._is_no_index_used(node):
                findings.append(self._finding_no_index(node, i))
            
            # Using filesort
            if node.is_using_filesort and node.rows >= 1000:
                findings.append(self._finding_filesort(node, i))
            
            # Using temporary
            if node.is_using_temporary:
                findings.append(self._finding_temporary(node, i))
        
        return findings
    
    def _is_no_index_used(self, node: MySQLPlanNode) -> bool:
        """Check if no index is available for this query."""
        has_where = "where" in node.extra.lower()
        return (
            not node.possible_keys 
            and node.key is None 
            and node.rows >= 1000
            and has_where
        )
    
    def suggest_fix(self, finding: Finding) -> str:
        """Generate SQL fix for a finding."""
        # Fixes are embedded in finding.suggestion
        return finding.suggestion
    
    def _create_context(self, node: MySQLPlanNode, index: int = 0) -> NodeContext:
        """Create a NodeContext from a MySQLPlanNode."""
        # Create path based on node index in the plan
        path = NodePath.root()
        for _ in range(index):
            path = path.child(0)
        
        return NodeContext(
            path=path,
            node_type=f"MySQL {node.access_type}",
            relation_name=node.table,
            actual_rows=node.rows,
            plan_rows=node.rows,
            total_cost=0.0,  # MySQL traditional EXPLAIN doesn't show cost
            filter=node.extra if "where" in node.extra.lower() else None,
            index_name=node.key,
            depth=index,
        )
    
    def _finding_full_table_scan(self, node: MySQLPlanNode, index: int = 0) -> Finding:
        """Create finding for full table scan."""
        return Finding(
            rule_id="MYSQL_FULL_TABLE_SCAN",
            severity=Severity.WARNING if node.rows < 100_000 else Severity.CRITICAL,
            context=self._create_context(node, index),
            title=f"Full table scan on {node.table} ({node.rows:,} rows)",
            description=(
                f"MySQL is scanning all {node.rows:,} rows in '{node.table}'. "
                f"Access type 'ALL' indicates no index is being used for this table."
            ),
            suggestion=self._suggest_index(node),
            metrics={
                "rows": node.rows,
                "filtered": int(node.filtered),
            },
        )
    
    def _finding_missing_index(self, node: MySQLPlanNode, index: int = 0) -> Finding:
        """Create finding for unused possible index."""
        return Finding(
            rule_id="MYSQL_MISSING_INDEX",
            severity=Severity.WARNING,
            context=self._create_context(node, index),
            title=f"Index available but not used on {node.table}",
            description=(
                f"MySQL identified possible indexes ({', '.join(node.possible_keys)}) "
                f"but chose not to use any. This often indicates the query doesn't "
                f"match the index columns or statistics are stale."
            ),
            suggestion=f"-- Analyze table to update statistics\nANALYZE TABLE {node.table};\n\n"
                       f"-- Or force index usage (use cautiously)\n"
                       f"SELECT ... FROM {node.table} FORCE INDEX ({node.possible_keys[0]}) WHERE ...;",
            metrics={
                "rows": node.rows,
                "possible_keys_count": len(node.possible_keys),
            },
        )
    
    def _finding_filesort(self, node: MySQLPlanNode, index: int = 0) -> Finding:
        """Create finding for filesort operation."""
        return Finding(
            rule_id="MYSQL_USING_FILESORT",
            severity=Severity.WARNING,
            context=self._create_context(node, index),
            title=f"Filesort on {node.table} ({node.rows:,} rows)",
            description=(
                f"MySQL must sort {node.rows:,} rows in memory or on disk. "
                f"'Using filesort' in Extra indicates an ORDER BY that can't use an index."
            ),
            suggestion=f"-- Add index to support ORDER BY\n"
                       f"CREATE INDEX idx_{node.table}_sort ON {node.table}(column_in_order_by);\n\n"
                       f"-- Or increase sort buffer\nSET sort_buffer_size = 4194304;  -- 4MB",
            metrics={
                "rows": node.rows,
            },
        )
    
    def _finding_temporary(self, node: MySQLPlanNode, index: int = 0) -> Finding:
        """Create finding for temporary table usage."""
        return Finding(
            rule_id="MYSQL_USING_TEMPORARY",
            severity=Severity.WARNING,
            context=self._create_context(node, index),
            title=f"Temporary table created for {node.table}",
            description=(
                f"MySQL created a temporary table to process this query. "
                f"This happens with GROUP BY, DISTINCT, or UNION operations "
                f"that can't use an index."
            ),
            suggestion=f"-- Add covering index for GROUP BY columns\n"
                       f"CREATE INDEX idx_{node.table}_group ON {node.table}(group_by_columns);\n\n"
                       f"-- Or increase temp table size\n"
                       f"SET tmp_table_size = 67108864;  -- 64MB\n"
                       f"SET max_heap_table_size = 67108864;",
            metrics={
                "rows": node.rows,
            },
        )
    
    def _finding_no_index(self, node: MySQLPlanNode, index: int = 0) -> Finding:
        """Create finding for no index available."""
        return Finding(
            rule_id="MYSQL_NO_INDEX_USED",
            severity=Severity.WARNING if node.rows < 50_000 else Severity.CRITICAL,
            context=self._create_context(node, index),
            title=f"No index available for {node.table} ({node.rows:,} rows)",
            description=(
                f"MySQL couldn't find any index to use for this query on '{node.table}'. "
                f"This results in a full table scan of {node.rows:,} rows."
            ),
            suggestion=self._suggest_index(node),
            metrics={
                "rows": node.rows,
                "filtered": int(node.filtered),
            },
        )
    
    def _suggest_index(self, node: MySQLPlanNode) -> str:
        """Generate index suggestion for a table."""
        return (
            f"-- Add index on filtered columns\n"
            f"CREATE INDEX idx_{node.table}_<column> ON {node.table}(<where_column>);\n\n"
            f"-- Update statistics\n"
            f"ANALYZE TABLE {node.table};"
        )
