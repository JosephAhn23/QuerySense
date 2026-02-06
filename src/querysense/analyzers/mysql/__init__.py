"""
MySQL EXPLAIN analyzer.

Supports:
- EXPLAIN (traditional tabular format)
- EXPLAIN FORMAT=JSON
- EXPLAIN ANALYZE (MySQL 8.0.18+)
"""

from querysense.analyzers.mysql.parser import MySQLParser
from querysense.analyzers.mysql.analyzer import MySQLAnalyzer
from querysense.analyzers.mysql.rules import (
    FullTableScan,
    MissingIndex,
    UsingFilesort,
    UsingTemporary,
    BadJoinType,
    NoIndexUsed,
)

__all__ = [
    "MySQLParser",
    "MySQLAnalyzer",
    "FullTableScan",
    "MissingIndex",
    "UsingFilesort",
    "UsingTemporary",
    "BadJoinType",
    "NoIndexUsed",
]
