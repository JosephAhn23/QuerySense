"""CI/CD integration commands: ci analyze, ci report, ci discover."""

from __future__ import annotations

import glob as globmod
import json
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.table import Table

from querysense.engine import AnalysisService
from querysense.output.pr_comment import CIResult, render_ci_summary_json, render_pr_comment
from querysense.output.renderers import render_text
from querysense.parser import ParseError, parse_explain
from querysense.parser.parser import validate_has_analyze

console = Console()
error_console = Console(stderr=True)


def register(ci_app: typer.Typer) -> None:
    """Register CI commands on the given Typer sub-app."""

    @ci_app.command("analyze")
    def ci_analyze(
        plan_pattern: Annotated[
            str,
            typer.Argument(
                help="Glob pattern for EXPLAIN JSON files (e.g., 'plans/**/*.json')",
            ),
        ],
        fail_on: Annotated[
            str,
            typer.Option("--fail-on", help="Severity level to fail CI: critical, warning, info, none"),
        ] = "warning",
        baseline_file: Annotated[
            str,
            typer.Option("--baseline", help="Path to baseline file for regression detection"),
        ] = ".querysense/baselines.json",
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: json, markdown, text"),
        ] = "text",
        output_file: Annotated[
            Optional[str],
            typer.Option("--output", "-o", help="Write output to file instead of stdout"),
        ] = None,
        allow_plain: Annotated[
            bool,
            typer.Option("--allow-plain", help="Allow EXPLAIN output without ANALYZE data"),
        ] = False,
        policy_file: Annotated[
            Optional[str],
            typer.Option("--policy", "-p", help="Path to policy file for enforcement"),
        ] = None,
    ) -> None:
        """
        Analyze EXPLAIN plans for CI/CD pipeline gating.

        Examples:

            $ querysense ci analyze "plans/**/*.json"
            $ querysense ci analyze "plans/*.json" --fail-on critical --format markdown -o comment.md
        """
        plan_files = sorted(globmod.glob(plan_pattern, recursive=True))

        if not plan_files:
            error_console.print(f"[yellow]No files matching '{plan_pattern}'[/yellow]")
            raise typer.Exit(code=0)

        console.print(f"[dim]Found {len(plan_files)} plan file(s)[/dim]")

        service = AnalysisService()

        parsed_plans: list[tuple[str, Any, str]] = []
        for plan_file in plan_files:
            try:
                explain = parse_explain(plan_file)
                if not allow_plain:
                    validate_has_analyze(explain)
                query_id = Path(plan_file).stem
                parsed_plans.append((query_id, explain, plan_file))
            except ParseError as e:
                error_console.print(f"[red]Error parsing {plan_file}:[/red] {e.message}")
            except Exception as e:
                error_console.print(f"[red]Error analyzing {plan_file}:[/red] {e}")

        if not parsed_plans:
            error_console.print("[red]No plans could be analyzed[/red]")
            raise typer.Exit(code=1)

        # Resolve policy path
        resolved_policy: str | None = policy_file
        if resolved_policy is None:
            default_policy = Path(".querysense/policy.yml")
            if default_policy.exists():
                resolved_policy = str(default_policy)

        batch_report = service.analyze_batch(
            plans=parsed_plans,
            baseline_path=baseline_file,
            fail_on=fail_on,
            policy_path=resolved_policy,
        )

        ci_results: list[CIResult] = []
        for report in batch_report.reports:
            ci_results.append(
                CIResult(
                    file_path=report.file_path or "",
                    result=report.result,
                    baseline_diff=report.baseline_diff,
                )
            )

        if not ci_results:
            error_console.print("[red]No plans could be analyzed[/red]")
            raise typer.Exit(code=1)

        # Generate output
        if output_format == "markdown":
            output_text = render_pr_comment(ci_results, fail_on=fail_on)
        elif output_format == "json":
            summary = render_ci_summary_json(ci_results, fail_on=fail_on)
            output_text = json.dumps(summary, indent=2)
        else:
            parts: list[str] = []
            for report, cr in zip(batch_report.reports, ci_results):
                parts.append(f"--- {cr.file_path} ---")
                parts.append(render_text(cr.result))
                if report.verdict:
                    parts.append(report.verdict.format_summary())
                elif cr.baseline_diff and cr.baseline_diff.status == "CHANGED":
                    parts.append(cr.baseline_diff.summary())
                if report.policy_violations:
                    parts.append("  Policy violations:")
                    for pv in report.policy_violations:
                        parts.append(f"    [{pv.severity.upper()}] {pv.message}")
                parts.append("")
            output_text = "\n".join(parts)

        _write_output(output_text, output_file, output_format)

        # Determine exit code
        summary = render_ci_summary_json(ci_results, fail_on=fail_on)
        has_failures = summary["summary"]["has_failures"]

        s = summary["summary"]
        if has_failures:
            error_console.print(
                f"\n[red bold]FAILED:[/red bold] "
                f"{s['critical_count']} critical, {s['warning_count']} warnings, "
                f"{s['regression_count']} regressions"
            )
            raise typer.Exit(code=1)
        else:
            console.print(
                f"\n[green bold]PASSED:[/green bold] "
                f"{s['total_plans']} plans analyzed, no issues at '{fail_on}' level or above"
            )

    @ci_app.command("report")
    def ci_report(
        results_file: Annotated[
            Path,
            typer.Argument(help="Path to CI results JSON file", exists=True, readable=True),
        ],
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: markdown, text"),
        ] = "markdown",
        output_file: Annotated[
            Optional[str],
            typer.Option("--output", "-o", help="Write output to file"),
        ] = None,
    ) -> None:
        """
        Generate a report from CI results JSON.

        Examples:

            $ querysense ci report results.json --format markdown -o comment.md
        """
        data = json.loads(results_file.read_text(encoding="utf-8"))

        if output_format == "markdown":
            lines: list[str] = []
            summary = data.get("summary", {})

            if summary.get("has_failures"):
                lines.append("## 🔴 QuerySense found performance issues")
            else:
                lines.append("## ✅ QuerySense: all checks passed")

            lines.append("")
            lines.append(
                f"**{summary.get('total_plans', 0)} plans analyzed** | "
                f"🔴 {summary.get('critical_count', 0)} critical | "
                f"🟡 {summary.get('warning_count', 0)} warnings | "
                f"🔵 {summary.get('info_count', 0)} info"
            )
            lines.append("")

            for finding in data.get("findings", []):
                sev = finding.get("severity", "info")
                icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(sev, "⚪")
                lines.append(f"### {icon} {finding.get('title', 'Unknown')}")
                lines.append(
                    f"  File: `{finding.get('file', '')}`  "
                    f"Rule: `{finding.get('rule_id', '')}`"
                )
                lines.append("")
                lines.append(f"> {finding.get('description', '')[:200]}")
                lines.append("")

                if finding.get("suggestion"):
                    lines.append("```sql")
                    lines.append(finding["suggestion"])
                    lines.append("```")
                    lines.append("")

            lines.append("---")
            lines.append(
                "*Powered by [QuerySense](https://github.com/JosephAhn23/Query-Sense)*"
            )
            output_text = "\n".join(lines)
        else:
            output_text = json.dumps(data, indent=2)

        _write_output(output_text, output_file, output_format)

    @ci_app.command("discover")
    def ci_discover(
        root_dir: Annotated[
            str,
            typer.Argument(help="Root directory to scan for migrations"),
        ] = ".",
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: text, json"),
        ] = "text",
    ) -> None:
        """
        Discover SQL migration files across frameworks.

        Auto-detects Flyway, Prisma, Django, Alembic, Rails, and raw SQL migrations.

        Examples:

            $ querysense ci discover .
            $ querysense ci discover --format json
        """
        from querysense.migrations import discover_migrations

        migrations = discover_migrations(root_dir)

        if not migrations:
            console.print("[yellow]No migration files found[/yellow]")
            return

        if output_format == "json":
            output_data = [
                {
                    "path": m.path,
                    "framework": m.framework,
                    "version": m.version,
                    "description": m.description,
                    "has_ddl": m.has_ddl,
                    "has_dml": m.has_dml,
                    "statement_count": len(m.sql_statements),
                }
                for m in migrations
            ]
            console.print_json(json.dumps(output_data, indent=2))
        else:
            table = Table()
            table.add_column("Path", style="cyan")
            table.add_column("Framework")
            table.add_column("Version")
            table.add_column("DDL")
            table.add_column("DML")
            table.add_column("Statements")

            for m in migrations:
                table.add_row(
                    m.path,
                    m.framework,
                    m.version or "-",
                    "[green]yes[/green]" if m.has_ddl else "[dim]no[/dim]",
                    "[green]yes[/green]" if m.has_dml else "[dim]no[/dim]",
                    str(len(m.sql_statements)),
                )

            console.print(table)
            console.print(f"\n[dim]{len(migrations)} migration(s) discovered[/dim]")


def _write_output(text: str, output_file: str | None, output_format: str) -> None:
    """Write output to file or stdout."""
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_text(text, encoding="utf-8")
        error_console.print(f"[dim]Output written to {output_file}[/dim]")
    elif output_format in ("markdown", "json"):
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
    else:
        console.print(text)
