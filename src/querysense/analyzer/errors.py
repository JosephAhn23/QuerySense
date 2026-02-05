"""
Error types for the analyzer module.

These provide rich context when things go wrong, making debugging
much easier than generic exceptions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.analyzer.path import NodePath


class AnalyzerError(Exception):
    """Base class for analyzer errors."""
    pass


class RuleError(AnalyzerError):
    """
    Error during rule execution.
    
    Captures which rule failed and optionally which node it was processing.
    This context is essential for debugging rule issues.
    
    Attributes:
        rule_id: The ID of the rule that failed
        rule_version: Version of the rule
        node_path: Path to the node being processed (if known)
        original_error: The underlying exception
    """
    
    def __init__(
        self,
        rule_id: str,
        rule_version: str,
        original_error: Exception,
        node_path: "NodePath | None" = None,
    ) -> None:
        self.rule_id = rule_id
        self.rule_version = rule_version
        self.node_path = node_path
        self.original_error = original_error
        
        # Build context string
        context = f"Rule '{rule_id}' v{rule_version}"
        if node_path:
            context += f" at {node_path}"
        
        message = (
            f"{context} failed: "
            f"{original_error.__class__.__name__}: {original_error}"
        )
        
        super().__init__(message)
    
    def to_dict(self) -> dict[str, str | list[str] | None]:
        """Serialize for JSON output / logging."""
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "node_path": list(self.node_path.segments) if self.node_path else None,
            "error_type": self.original_error.__class__.__name__,
            "error_message": str(self.original_error),
        }


class ConfigurationError(AnalyzerError):
    """Error in analyzer configuration."""
    
    def __init__(self, message: str, config_key: str | None = None) -> None:
        self.config_key = config_key
        super().__init__(message)
