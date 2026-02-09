"""Core analysis commands: analyze, fix, rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from querysense.analyzer import Severity
from querysense.engine import AnalysisService
from querysense.output.renderers import OutputFormat, render
from querysense.parser import ParseError, parse_explain
from querysense.parser.parser import validate_has_analyze

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register core commands on the given Typer app."""

    @app.command()
    def analyze(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        require_analyze: Annotated[
            bool,
            typer.Option(
                "--require-analyze/--allow-plain",
                help="Require EXPLAIN ANALYZE output",
            ),
        ] = True,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output results as JSON"),
        ] = False,
        threshold: Annotated[
            int,
            typer.Option(
                "--threshold",
                "-t",
                help="Minimum rows to trigger sequential scan warning",
            ),
        ] = 10_000,
    ) -> None:
        """
        Analyze PostgreSQL EXPLAIN output for performance issues.

        Examples:

            $ psql -c "EXPLAIN (ANALYZE, FORMAT JSON) SELECT * FROM users" > explain.json
            $ querysense analyze explain.json
        """
        try:
            output = parse_explain(explain_file)

            if require_analyze:
                validate_has_analyze(output)

            service = AnalysisService()
            result = service.analyze(output)
            findings = result.findings

            # JSON output via unified renderer
            if json_output:
                console.print_json(render(result, format=OutputFormat.JSON))
                return

            # Pretty output
            if not findings:
                console.print(
                    Panel(
                        "[green]No performance issues found![/green]\n\n"
                        f"Analyzed {result.metadata.node_count} nodes.",
                        title="QuerySense",
                        border_style="green",
                    )
                )
                return

            # Show findings
            console.print(f"[bold]Found {len(findings)} issue(s):[/bold]\n")

            for finding in findings:
                if finding.severity == Severity.CRITICAL:
                    severity_style = "red bold"
                elif finding.severity == Severity.WARNING:
                    severity_style = "yellow"
                else:
                    severity_style = "blue"

                console.print(
                    f"[{severity_style}][{finding.severity.value.upper()}]"
                    f"[/{severity_style}] {finding.title}"
                )
                console.print(f"   [dim]{finding.description}[/dim]")

                if finding.suggestion:
                    console.print(f"\n   [bold]Fix:[/bold]")
                    for line in finding.suggestion.split("\n"):
                        if line.startswith("--"):
                            console.print(f"   [dim]{line}[/dim]")
                        else:
                            console.print(f"   [green]{line}[/green]")

                console.print()

            console.print(
                f"[dim]Analyzed {result.metadata.node_count} nodes "
                f"with {result.metadata.rules_run} rule(s)[/dim]"
            )

        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            if e.detail:
                error_console.print(f"\n[dim]{e.detail}[/dim]")
            raise typer.Exit(code=1)

    @app.command()
    def fix(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        require_analyze: Annotated[
            bool,
            typer.Option(
                "--require-analyze/--allow-plain",
                help="Require EXPLAIN ANALYZE output",
            ),
        ] = True,
    ) -> None:
        """
        Output copy-paste SQL fixes for performance issues.

        Unlike 'analyze', this outputs ONLY the SQL statements
        needed to fix detected issues.

        Examples:

            $ querysense fix slow_query.json | psql
            $ querysense fix slow_query.json > fixes.sql
        """
        try:
            output = parse_explain(explain_file)

            if require_analyze:
                validate_has_analyze(output)

            service = AnalysisService()
            result = service.analyze(output)
            findings = result.findings

            if not findings:
                console.print("-- No performance issues found. Nothing to fix.")
                return

            console.print("-- QuerySense Fixes")
            console.print(f"-- {len(findings)} issue(s) detected\n")

            seen_fixes: set[str] = set()

            for finding in findings:
                if not finding.suggestion:
                    continue

                sql_lines: list[str] = []
                for line in finding.suggestion.split("\n"):
                    stripped = line.strip()
                    if stripped and not stripped.startswith("--"):
                        sql_lines.append(stripped)

                if not sql_lines:
                    continue

                fix_key = "\n".join(sql_lines)
                if fix_key in seen_fixes:
                    continue
                seen_fixes.add(fix_key)

                console.print(
                    f"-- [{finding.severity.value.upper()}] {finding.title}"
                )

                for line in finding.suggestion.split("\n"):
                    if line.strip():
                        console.print(line)

                console.print()

            console.print("-- End of fixes")
            console.print("-- Run with: psql < fixes.sql")

        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            if e.detail:
                error_console.print(f"\n[dim]{e.detail}[/dim]")
            raise typer.Exit(code=1)

    @app.command()
    def rules() -> None:
        """List all available detection rules."""
        from querysense.analyzer.registry import get_registry

        console.print("[bold]PostgreSQL Rules:[/bold]\n")

        registry = get_registry()
        all_rules = registry.all()

        table = Table()
        table.add_column("Rule ID", style="cyan")
        table.add_column("Severity")
        table.add_column("Description")

        for rule_cls in sorted(all_rules, key=lambda r: r.rule_id):
            severity = rule_cls.severity.value.upper()
            if severity == "CRITICAL":
                sev_style = "red bold"
            elif severity == "WARNING":
                sev_style = "yellow"
            else:
                sev_style = "blue"

            table.add_row(
                rule_cls.rule_id,
                f"[{sev_style}]{severity}[/{sev_style}]",
                rule_cls.description,
            )

        console.print(table)
        console.print(f"\n[dim]{len(all_rules)} rules available[/dim]")
