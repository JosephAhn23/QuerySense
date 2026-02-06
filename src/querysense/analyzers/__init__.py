"""
Multi-database analyzer support.

QuerySense supports analyzing EXPLAIN output from multiple databases:
- PostgreSQL (default, v0.1.0+)
- MySQL (v0.3.0+)
"""

from querysense.analyzers.base import BaseAnalyzer

__all__ = ["BaseAnalyzer"]
