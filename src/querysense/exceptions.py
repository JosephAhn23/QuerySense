"""
Package-level exception hierarchy for QuerySense.

All exceptions inherit from QuerySenseError, enabling:
- Catching all QuerySense errors with a single except clause
- Rich context fields for debugging (rule_id, node_path, config_key, etc.)
- Structured serialization via to_dict() for JSON error responses

Hierarchy:
    QuerySenseError
    ├── AnalyzerError          – Errors during analysis orchestration
    │   ├── RuleError          – A specific rule failed during execution
    │   └── ConfigurationError – Invalid analyzer configuration
    ├── ParseError             – Failed to parse EXPLAIN JSON input
    ├── IRConversionError      – Failed to convert plan to IR representation
    ├── BaselineError          – Errors in baseline storage / comparison
    ├── PolicyError            – Policy evaluation failures
    └── CloudError             – Errors in the cloud / API layer
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.path import NodePath


class QuerySenseError(Exception):
    """
    Base exception for all QuerySense errors.

    All QuerySense-specific exceptions inherit from this class,
    enabling callers to catch all library errors with a single handler.

    Attributes:
        message: Human-readable error description.
    """

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON error responses."""
        return {
            "error_type": type(self).__name__,
            "message": self.message,
        }


# ── Analysis Errors ──────────────────────────────────────────────────────


class AnalyzerError(QuerySenseError):
    """Errors during analysis orchestration."""
    pass


class RuleError(AnalyzerError):
    """
    Error during rule execution.

    Captures which rule failed and optionally which node it was processing.
    This context is essential for debugging rule issues.

    Attributes:
        rule_id: The ID of the rule that failed.
        rule_version: Version of the rule.
        node_path: Path to the node being processed (if known).
        original_error: The underlying exception.
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

        context = f"Rule '{rule_id}' v{rule_version}"
        if node_path:
            context += f" at {node_path}"

        message = (
            f"{context} failed: "
            f"{original_error.__class__.__name__}: {original_error}"
        )
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output / logging."""
        return {
            "error_type": type(self).__name__,
            "message": self.message,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "node_path": list(self.node_path.segments) if self.node_path else None,
            "original_error_type": self.original_error.__class__.__name__,
            "original_error_message": str(self.original_error),
        }


class ConfigurationError(AnalyzerError):
    """
    Error in analyzer configuration.

    Attributes:
        config_key: The configuration key that caused the error (if known).
    """

    def __init__(self, message: str, config_key: str | None = None) -> None:
        self.config_key = config_key
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result["config_key"] = self.config_key
        return result


# ── Parse Errors ─────────────────────────────────────────────────────────


class ParseError(QuerySenseError):
    """
    Failed to parse EXPLAIN JSON input.

    Raised when the input is not valid EXPLAIN JSON, is too large,
    too deeply nested, or otherwise cannot be interpreted.

    Attributes:
        source: Description of the input source (file path, "stdin", etc.).
    """

    def __init__(self, message: str, source: str | None = None) -> None:
        self.source = source
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result["source"] = self.source
        return result


# ── IR Errors ────────────────────────────────────────────────────────────


class IRConversionError(QuerySenseError):
    """
    Failed to convert a plan to the IR (Intermediate Representation).

    Raised when the engine-specific adapter cannot translate a plan
    node into the universal IR format.

    Attributes:
        engine: The source engine (e.g., "postgresql", "mysql").
        node_type: The plan node type that failed conversion.
    """

    def __init__(
        self,
        message: str,
        engine: str | None = None,
        node_type: str | None = None,
    ) -> None:
        self.engine = engine
        self.node_type = node_type
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result["engine"] = self.engine
        result["node_type"] = self.node_type
        return result


# ── Baseline Errors ──────────────────────────────────────────────────────


class BaselineError(QuerySenseError):
    """
    Errors in baseline storage or comparison.

    Raised when baseline files are corrupt, schema versions are
    incompatible, or comparison fails.
    """
    pass


# ── Policy Errors ────────────────────────────────────────────────────────


class PolicyError(QuerySenseError):
    """
    Policy evaluation failure.

    Raised when a policy file cannot be loaded, parsed, or evaluated.
    NOT raised for policy violations (those return PolicyViolation objects).
    """
    pass


# ── Cloud Errors ─────────────────────────────────────────────────────────


class CloudError(QuerySenseError):
    """
    Errors in the cloud / API layer.

    Covers authentication failures, rate limiting, and service errors.
    """
    pass
