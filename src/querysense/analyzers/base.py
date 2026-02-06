"""
Base analyzer interface for database-specific EXPLAIN analyzers.

All database-specific analyzers must implement this interface to ensure
consistent behavior across PostgreSQL, MySQL, and future databases.
"""

from abc import ABC, abstractmethod
from typing import Any

from querysense.analyzer.models import Finding


class BaseAnalyzer(ABC):
    """Base class for database-specific EXPLAIN analyzers."""
    
    @property
    @abstractmethod
    def database_name(self) -> str:
        """Return the database name (e.g., 'PostgreSQL', 'MySQL')."""
        pass
    
    @abstractmethod
    def parse_plan(self, plan: dict[str, Any]) -> dict[str, Any]:
        """
        Parse database-specific EXPLAIN output into normalized format.
        
        Args:
            plan: Raw EXPLAIN output (JSON format)
            
        Returns:
            Normalized plan structure
        """
        pass
    
    @abstractmethod
    def detect_issues(self, parsed_plan: dict[str, Any]) -> list[Finding]:
        """
        Detect performance issues in parsed plan.
        
        Args:
            parsed_plan: Normalized plan from parse_plan()
            
        Returns:
            List of Finding objects describing detected issues
        """
        pass
    
    @abstractmethod
    def suggest_fix(self, finding: Finding) -> str:
        """
        Generate SQL fix for detected issue.
        
        Args:
            finding: A Finding object from detect_issues()
            
        Returns:
            SQL statement(s) to fix the issue
        """
        pass
