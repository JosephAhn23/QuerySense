"""
Business logic service layer for QuerySense Cloud.

Uses AnalysisService as the single orchestration entry point —
the same service that CLI and CI use. This ensures consistent
behavior across all delivery mechanisms.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import querysense
from querysense.analyzer.comparator import compare_analyses
from querysense.engine import AnalysisService
from querysense.output.renderers import OutputFormat, render

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult

logger = logging.getLogger(__name__)

# Shared AnalysisService instance (thread-safe, stateless)
_service: AnalysisService | None = None


def get_service() -> AnalysisService:
    """Get or create the shared AnalysisService instance."""
    global _service
    if _service is None:
        _service = AnalysisService()
    return _service


def analyze_plan(
    plan_json: str,
    sql_text: str | None = None,
) -> tuple["AnalysisResult", str]:
    """
    Analyze an EXPLAIN plan and return the result.

    Args:
        plan_json: Raw EXPLAIN JSON string.
        sql_text: Optional SQL query text for enhanced analysis.

    Returns:
        (AnalysisResult, result_json_string)
    """
    plan_data = json.loads(plan_json)
    explain = querysense.parse_explain(plan_data)

    service = get_service()
    result = service.analyze(explain, sql=sql_text)

    result_json = render(result, format=OutputFormat.JSON)
    return result, result_json


def analyze_plan_to_dict(
    plan_json: str,
    sql_text: str | None = None,
) -> dict[str, Any]:
    """
    Analyze an EXPLAIN plan and return a JSON-serializable dict.

    Convenience wrapper for API responses.
    """
    _result, result_json = analyze_plan(plan_json, sql_text)
    return json.loads(result_json)


def compare_plans_service(
    before_json: str,
    after_json: str,
    before_sql: str | None = None,
    after_sql: str | None = None,
) -> dict[str, Any]:
    """
    Compare two EXPLAIN plans and return the comparison.

    Args:
        before_json: EXPLAIN JSON for the "before" plan.
        after_json: EXPLAIN JSON for the "after" plan.
        before_sql: Optional SQL for the before plan.
        after_sql: Optional SQL for the after plan.

    Returns:
        Comparison result as a JSON-serializable dict.
    """
    before_result, _ = analyze_plan(before_json, before_sql)
    after_result, _ = analyze_plan(after_json, after_sql)

    comparison = compare_analyses(before_result, after_result)
    return comparison.to_dict()


def get_summary_counts(result_json: str) -> dict[str, int]:
    """
    Extract summary counts from a stored result JSON.

    Returns dict with: findings_count, critical_count, warning_count, info_count
    """
    try:
        data = json.loads(result_json)
        summary = data.get("summary", {})
        return {
            "findings_count": summary.get("total", 0),
            "critical_count": summary.get("critical", 0),
            "warning_count": summary.get("warning", 0),
            "info_count": summary.get("info", 0),
        }
    except (json.JSONDecodeError, KeyError):
        return {
            "findings_count": 0,
            "critical_count": 0,
            "warning_count": 0,
            "info_count": 0,
        }


def render_analysis_markdown(result_json: str) -> str:
    """
    Re-render a stored analysis result as Markdown.

    Useful for share pages and PR comments.
    """
    # We stored the JSON output; parse and re-render is not straightforward
    # because we don't re-create the AnalysisResult object.
    # Instead, render a simplified markdown from the JSON dict.
    data = json.loads(result_json)
    lines: list[str] = []

    summary = data.get("summary", {})
    lines.append("# QuerySense Analysis Report")
    lines.append("")

    total = summary.get("total", 0)
    critical = summary.get("critical", 0)
    warning = summary.get("warning", 0)

    if critical:
        lines.append("**Critical issues found**")
    elif warning:
        lines.append("**Warnings found**")
    elif total == 0:
        lines.append("**No issues found**")
    lines.append("")

    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Evidence Level | `{data.get('evidence_level', 'PLAN')}` |")
    lines.append(f"| Total Findings | {total} |")
    lines.append(f"| Critical | {critical} |")
    lines.append(f"| Warnings | {warning} |")
    lines.append(f"| Info | {summary.get('info', 0)} |")
    lines.append("")

    findings = data.get("findings", [])
    if findings:
        lines.append("## Findings")
        lines.append("")
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info")
            icon = {"critical": "!!!", "warning": "!", "info": "i"}.get(sev, "")
            lines.append(f"### {i}. [{icon}] {f.get('title', 'Finding')}")
            lines.append("")
            lines.append(f"**Rule:** `{f.get('rule_id', '')}`  ")
            ctx = f.get("context", {})
            lines.append(f"**Location:** `{ctx.get('path', '')}`  ")
            impact = f.get("impact_band", "UNKNOWN")
            if impact != "UNKNOWN":
                lines.append(f"**Expected Impact:** {impact}")
            lines.append("")
            lines.append(f.get("description", ""))
            lines.append("")
            suggestion = f.get("suggestion")
            if suggestion:
                lines.append("**Suggestion:**")
                lines.append("")
                lines.append("```sql")
                lines.append(suggestion)
                lines.append("```")
                lines.append("")

    return "\n".join(lines)
