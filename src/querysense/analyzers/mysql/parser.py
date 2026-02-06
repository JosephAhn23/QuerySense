"""
MySQL EXPLAIN output parser.

Supports:
- Traditional EXPLAIN format (tabular)
- EXPLAIN FORMAT=JSON
- EXPLAIN ANALYZE (MySQL 8.0.18+)

MySQL EXPLAIN fields:
- id: SELECT identifier
- select_type: SIMPLE, PRIMARY, UNION, SUBQUERY, etc.
- table: Table name
- partitions: Matching partitions
- type: Access type (ALL, index, range, ref, eq_ref, const, system, NULL)
- possible_keys: Indexes that could be used
- key: Index actually used
- key_len: Length of key used
- ref: Columns compared to index
- rows: Estimated rows to examine
- filtered: Percentage of rows filtered by condition
- Extra: Additional information
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MySQLPlanNode:
    """Represents a single row in MySQL EXPLAIN output."""
    
    id: int
    select_type: str
    table: str | None
    partitions: str | None
    access_type: str  # 'type' in MySQL, renamed to avoid Python keyword
    possible_keys: list[str]
    key: str | None
    key_len: int | None
    ref: str | None
    rows: int
    filtered: float
    extra: str
    
    # Nested subqueries or unions
    children: list[MySQLPlanNode] = field(default_factory=list)
    
    # Original raw data
    raw: dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_full_table_scan(self) -> bool:
        """Check if this is a full table scan (type='ALL')."""
        return self.access_type == "ALL"
    
    @property
    def is_using_filesort(self) -> bool:
        """Check if query requires filesort."""
        return "Using filesort" in self.extra
    
    @property
    def is_using_temporary(self) -> bool:
        """Check if query requires temporary table."""
        return "Using temporary" in self.extra
    
    @property
    def has_unused_index(self) -> bool:
        """Check if possible index exists but isn't used."""
        return self.possible_keys and self.key is None


@dataclass 
class MySQLExplainOutput:
    """Parsed MySQL EXPLAIN output."""
    
    nodes: list[MySQLPlanNode]
    format: str  # 'traditional', 'json', 'analyze'
    raw: dict[str, Any] | list[dict[str, Any]]
    
    @property
    def total_rows(self) -> int:
        """Total estimated rows across all nodes."""
        return sum(node.rows for node in self.nodes)


class MySQLParser:
    """Parser for MySQL EXPLAIN output."""
    
    # Access type severity (worst to best)
    ACCESS_TYPE_ORDER = [
        "ALL",      # Full table scan
        "index",    # Full index scan
        "range",    # Index range scan
        "index_merge",
        "ref_or_null",
        "ref",      # Non-unique index lookup
        "eq_ref",   # Unique index lookup
        "const",    # Single row (constant)
        "system",   # System table with one row
        "NULL",     # No table access needed
    ]
    
    def parse(self, explain_output: dict[str, Any] | list[dict[str, Any]]) -> MySQLExplainOutput:
        """
        Parse MySQL EXPLAIN output.
        
        Args:
            explain_output: Raw EXPLAIN output (JSON or traditional format)
            
        Returns:
            MySQLExplainOutput with parsed nodes
            
        Raises:
            NotImplementedError: MySQL parsing coming in v0.3.0
        """
        # Detect format
        if isinstance(explain_output, list):
            # Traditional format (list of rows)
            return self._parse_traditional(explain_output)
        elif "query_block" in explain_output:
            # JSON format
            return self._parse_json(explain_output)
        else:
            raise ValueError(f"Unknown MySQL EXPLAIN format: {type(explain_output)}")
    
    def _parse_traditional(self, rows: list[dict[str, Any]]) -> MySQLExplainOutput:
        """Parse traditional tabular EXPLAIN output."""
        nodes = []
        
        for row in rows:
            node = MySQLPlanNode(
                id=row.get("id", 1),
                select_type=row.get("select_type", "SIMPLE"),
                table=row.get("table"),
                partitions=row.get("partitions"),
                access_type=row.get("type", "ALL"),
                possible_keys=self._parse_keys(row.get("possible_keys")),
                key=row.get("key"),
                key_len=self._parse_int(row.get("key_len")),
                ref=row.get("ref"),
                rows=row.get("rows", 0),
                filtered=row.get("filtered", 100.0),
                extra=row.get("Extra", ""),
                raw=row,
            )
            nodes.append(node)
        
        return MySQLExplainOutput(nodes=nodes, format="traditional", raw=rows)
    
    def _parse_json(self, json_output: dict[str, Any]) -> MySQLExplainOutput:
        """
        Parse EXPLAIN FORMAT=JSON output.
        
        MySQL JSON EXPLAIN has nested structure:
        - query_block: Root of the plan
        - table: Single table access
        - nested_loop: Array of joined tables
        - ordering_operation: ORDER BY handling
        - grouping_operation: GROUP BY handling
        """
        nodes: list[MySQLPlanNode] = []
        
        query_block = json_output.get("query_block", {})
        select_id = query_block.get("select_id", 1)
        
        # Handle single table
        if "table" in query_block:
            node = self._parse_json_table(query_block["table"], select_id)
            nodes.append(node)
        
        # Handle nested loop (joins)
        if "nested_loop" in query_block:
            for item in query_block["nested_loop"]:
                if "table" in item:
                    node = self._parse_json_table(item["table"], select_id)
                    nodes.append(node)
        
        # Handle ordering operation (wraps table or nested_loop)
        if "ordering_operation" in query_block:
            ordering = query_block["ordering_operation"]
            filesort = ordering.get("using_filesort", False)
            
            # Parse tables inside ordering operation
            if "table" in ordering:
                node = self._parse_json_table(ordering["table"], select_id)
                if filesort:
                    node = MySQLPlanNode(
                        id=node.id,
                        select_type=node.select_type,
                        table=node.table,
                        partitions=node.partitions,
                        access_type=node.access_type,
                        possible_keys=node.possible_keys,
                        key=node.key,
                        key_len=node.key_len,
                        ref=node.ref,
                        rows=node.rows,
                        filtered=node.filtered,
                        extra=f"{node.extra}; Using filesort".strip("; "),
                        raw=node.raw,
                    )
                nodes.append(node)
            
            if "nested_loop" in ordering:
                for item in ordering["nested_loop"]:
                    if "table" in item:
                        node = self._parse_json_table(item["table"], select_id)
                        if filesort:
                            node = MySQLPlanNode(
                                id=node.id,
                                select_type=node.select_type,
                                table=node.table,
                                partitions=node.partitions,
                                access_type=node.access_type,
                                possible_keys=node.possible_keys,
                                key=node.key,
                                key_len=node.key_len,
                                ref=node.ref,
                                rows=node.rows,
                                filtered=node.filtered,
                                extra=f"{node.extra}; Using filesort".strip("; "),
                                raw=node.raw,
                            )
                        nodes.append(node)
        
        # Handle grouping operation
        if "grouping_operation" in query_block:
            grouping = query_block["grouping_operation"]
            using_temp = grouping.get("using_temporary_table", False)
            
            if "table" in grouping:
                node = self._parse_json_table(grouping["table"], select_id)
                if using_temp:
                    node = MySQLPlanNode(
                        id=node.id,
                        select_type=node.select_type,
                        table=node.table,
                        partitions=node.partitions,
                        access_type=node.access_type,
                        possible_keys=node.possible_keys,
                        key=node.key,
                        key_len=node.key_len,
                        ref=node.ref,
                        rows=node.rows,
                        filtered=node.filtered,
                        extra=f"{node.extra}; Using temporary".strip("; "),
                        raw=node.raw,
                    )
                nodes.append(node)
            
            if "nested_loop" in grouping:
                for item in grouping["nested_loop"]:
                    if "table" in item:
                        node = self._parse_json_table(item["table"], select_id)
                        if using_temp:
                            node = MySQLPlanNode(
                                id=node.id,
                                select_type=node.select_type,
                                table=node.table,
                                partitions=node.partitions,
                                access_type=node.access_type,
                                possible_keys=node.possible_keys,
                                key=node.key,
                                key_len=node.key_len,
                                ref=node.ref,
                                rows=node.rows,
                                filtered=node.filtered,
                                extra=f"{node.extra}; Using temporary".strip("; "),
                                raw=node.raw,
                            )
                        nodes.append(node)
        
        return MySQLExplainOutput(nodes=nodes, format="json", raw=json_output)
    
    def _parse_json_table(self, table_data: dict[str, Any], select_id: int = 1) -> MySQLPlanNode:
        """Parse a single table from JSON EXPLAIN output."""
        # Build Extra field from various JSON flags
        extra_parts: list[str] = []
        
        if table_data.get("using_filesort"):
            extra_parts.append("Using filesort")
        if table_data.get("using_temporary_table"):
            extra_parts.append("Using temporary")
        if table_data.get("attached_condition"):
            extra_parts.append("Using where")
        if table_data.get("using_index"):
            extra_parts.append("Using index")
        if table_data.get("using_join_buffer"):
            extra_parts.append(f"Using join buffer ({table_data.get('using_join_buffer')})")
        
        # Get rows - JSON format uses different field names
        rows = (
            table_data.get("rows_examined_per_scan")
            or table_data.get("rows_produced_per_join")
            or table_data.get("rows", 0)
        )
        
        # Get filtered percentage
        filtered = table_data.get("filtered", 100.0)
        if isinstance(filtered, str):
            filtered = float(filtered)
        
        return MySQLPlanNode(
            id=select_id,
            select_type="SIMPLE",  # JSON format doesn't always include this
            table=table_data.get("table_name"),
            partitions=table_data.get("partitions"),
            access_type=table_data.get("access_type", "ALL"),
            possible_keys=self._parse_keys(table_data.get("possible_keys")),
            key=table_data.get("key"),
            key_len=self._parse_int(table_data.get("key_length")),
            ref=table_data.get("ref"),
            rows=rows if isinstance(rows, int) else int(rows) if rows else 0,
            filtered=filtered,
            extra="; ".join(extra_parts) if extra_parts else "",
            raw=table_data,
        )
    
    def _parse_keys(self, keys: str | list | None) -> list[str]:
        """Parse possible_keys field."""
        if keys is None:
            return []
        if isinstance(keys, list):
            return keys
        if isinstance(keys, str):
            return [k.strip() for k in keys.split(",") if k.strip()]
        return []
    
    def _parse_int(self, value: Any) -> int | None:
        """Parse integer field that might be string or None."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
