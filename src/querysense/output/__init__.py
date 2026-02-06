"""
Output module - Separates rendering from analysis.

Design principle: Presentation ≠ domain logic.

Provides multiple output formats:
- render_text: Rich terminal output for CLI
- render_json: Stable JSON schema for API
- render_markdown: GitHub/Slack-friendly format

Usage:
    from querysense.output import render_text, render_json, render_markdown
    
    result = analyzer.analyze(explain)
    
    # CLI output
    print(render_text(result))
    
    # API response
    return render_json(result)
    
    # Slack notification
    send_message(render_markdown(result))
"""

from querysense.output.renderers import (
    OutputFormat,
    render,
    render_json,
    render_markdown,
    render_text,
)
from querysense.output.schema import (
    AnalysisResultSchema,
    FindingSchema,
    get_json_schema,
)

__all__ = [
    "OutputFormat",
    "render",
    "render_text",
    "render_json",
    "render_markdown",
    "AnalysisResultSchema",
    "FindingSchema",
    "get_json_schema",
]
