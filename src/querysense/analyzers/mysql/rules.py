"""
MySQL-specific detection rules.

Each rule follows the same pattern as PostgreSQL rules but adapted
for MySQL's EXPLAIN output format and terminology.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.analyzers.mysql.parser import MySQLPlanNode


class MySQLRule(ABC):
    """Base class for MySQL rules."""
    
    rule_id: str
    description: str
    
    @abstractmethod
    def check(self, node: "MySQLPlanNode") -> bool:
        """Check if this rule applies to the given node."""
        pass


class FullTableScan(MySQLRule):
    """
    Detect full table scans (type='ALL') on large tables.
    
    In MySQL EXPLAIN:
    - type='ALL' means scanning every row in the table
    - This is the worst access type for large tables
    
    Fix: Add an index on the WHERE clause columns.
    """
    
    rule_id = "MYSQL_FULL_TABLE_SCAN"
    description = "Full table scan detected (type='ALL')"
    
    def __init__(self, min_rows: int = 10_000):
        self.min_rows = min_rows
    
    def check(self, node: MySQLPlanNode) -> bool:
        return node.access_type == "ALL" and node.rows >= self.min_rows


class MissingIndex(MySQLRule):
    """
    Detect when possible_keys exists but key is NULL.
    
    This means MySQL found indexes that could potentially help,
    but decided not to use any of them.
    
    Causes:
    - Query doesn't match index columns properly
    - Statistics are stale (run ANALYZE TABLE)
    - Small table where full scan is faster
    
    Fix: ANALYZE TABLE or restructure query to use index.
    """
    
    rule_id = "MYSQL_MISSING_INDEX"
    description = "Possible index not used"
    
    def check(self, node: MySQLPlanNode) -> bool:
        return bool(node.possible_keys) and node.key is None


class UsingFilesort(MySQLRule):
    """
    Detect filesort operations.
    
    'Using filesort' in Extra means MySQL must sort results
    without using an index. For large result sets, this can
    spill to disk and be very slow.
    
    Fix: Add index that covers ORDER BY columns.
    """
    
    rule_id = "MYSQL_USING_FILESORT"
    description = "Query requires filesort"
    
    def __init__(self, min_rows: int = 1_000):
        self.min_rows = min_rows
    
    def check(self, node: MySQLPlanNode) -> bool:
        return "Using filesort" in node.extra and node.rows >= self.min_rows


class UsingTemporary(MySQLRule):
    """
    Detect temporary table usage.
    
    'Using temporary' in Extra means MySQL created a temporary
    table to hold intermediate results. Common with:
    - GROUP BY on non-indexed columns
    - ORDER BY with different columns than GROUP BY
    - DISTINCT on non-indexed columns
    - UNION operations
    
    Fix: Add covering index for GROUP BY/ORDER BY columns.
    """
    
    rule_id = "MYSQL_USING_TEMPORARY"
    description = "Query creates temporary table"
    
    def check(self, node: MySQLPlanNode) -> bool:
        return "Using temporary" in node.extra


class BadJoinType(MySQLRule):
    """
    Detect inefficient join access types.
    
    In joins, type='ALL' is particularly bad because it means
    a full table scan for every row in the driving table.
    
    Access type hierarchy (best to worst):
    - system/const: Single row lookup
    - eq_ref: Unique index lookup per row
    - ref: Non-unique index lookup
    - range: Index range scan
    - index: Full index scan
    - ALL: Full table scan (worst)
    
    Fix: Add index on join column.
    """
    
    rule_id = "MYSQL_BAD_JOIN_TYPE"
    description = "Inefficient join access type"
    
    BAD_TYPES = {"ALL", "index"}
    
    def __init__(self, min_rows: int = 1_000):
        self.min_rows = min_rows
    
    def check(self, node: "MySQLPlanNode") -> bool:
        # Check if this is likely a join (not the first table)
        is_join = node.id > 1 or node.select_type in ("DEPENDENT SUBQUERY", "DERIVED")
        return (
            is_join 
            and node.access_type in self.BAD_TYPES 
            and node.rows >= self.min_rows
        )


class NoIndexUsed(MySQLRule):
    """
    Detect queries where no index could be used.
    
    This is different from MissingIndex - here possible_keys is NULL,
    meaning MySQL couldn't find any index that could help with the query.
    
    This usually means:
    - No indexes exist on the filtered columns
    - The query uses functions on indexed columns (breaks index usage)
    - LIKE pattern starts with wildcard (LIKE '%foo')
    
    Fix: Create an index on the WHERE clause columns.
    """
    
    rule_id = "MYSQL_NO_INDEX_USED"
    description = "No index available for query"
    
    def __init__(self, min_rows: int = 1_000):
        self.min_rows = min_rows
    
    def check(self, node: "MySQLPlanNode") -> bool:
        # No possible keys and scanning significant rows with a filter
        has_where = "where" in node.extra.lower()
        return (
            not node.possible_keys 
            and node.key is None 
            and node.rows >= self.min_rows
            and has_where
        )
