"""
Database probe module for Level 3 analysis.

Provides read-only database access to validate recommendations:
- Check if indexes already exist
- Verify table statistics freshness
- Get table size and row counts
- Query pg_stat_statements for query frequency (optional)

Design principle: Recommendations must be validated when possible.
"""

from querysense.db.probe import (
    DBProbe,
    IndexInfo,
    TableStats,
    get_probe,
    is_db_available,
)

__all__ = [
    "DBProbe",
    "IndexInfo",
    "TableStats",
    "get_probe",
    "is_db_available",
]
