"""
QuerySense CLI - PostgreSQL query performance analyzer.

Usage:
    querysense analyze explain.json
    querysense analyze --help
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from querysense import __version__
from querysense.analyzer import Analyzer, Severity
from querysense.parser import parse_explain, ParseError
from querysense.parser.parser import validate_has_analyze

app = typer.Typer(
    name="querysense",
    help="PostgreSQL query performance analyzer",
    no_args_is_help=True,
)

console = Console()
error_console = Console(stderr=True)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"QuerySense version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """QuerySense - PostgreSQL query performance analyzer."""
    pass


@app.command()
def analyze(
    explain_file: Annotated[
        Path,
        typer.Argument(
            help="Path to EXPLAIN (FORMAT JSON) output file",
            exists=True,
            readable=True,
            resolve_path=True,
        ),
    ],
    require_analyze: Annotated[
        bool,
        typer.Option(
            "--require-analyze/--allow-plain",
            help="Require EXPLAIN ANALYZE output (recommended)",
        ),
    ] = True,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="Output results as JSON",
        ),
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
    Analyze a PostgreSQL EXPLAIN output for performance issues.
    
    Example:
    
        $ psql -c "EXPLAIN (ANALYZE, FORMAT JSON) SELECT * FROM users" > explain.json
        $ querysense analyze explain.json
    """
    try:
        # Parse the EXPLAIN output
        output = parse_explain(explain_file)
        
        # Validate ANALYZE data if required
        if require_analyze:
            validate_has_analyze(output)
        
        # Run the analyzer
        analyzer = Analyzer()
        result = analyzer.analyze(output)
        
        # JSON output mode
        if json_output:
            output_data = {
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "title": f.title,
                        "description": f.description,
                        "suggestion": f.suggestion,
                        "table": f.context.relation_name,
                        "rows": f.context.actual_rows,
                    }
                    for f in result.findings
                ],
                "summary": {
                    "findings_count": len(result.findings),
                    "nodes_analyzed": result.metadata.node_count,
                    "rules_run": result.metadata.rules_run,
                },
            }
            console.print_json(json.dumps(output_data, indent=2))
            return
        
        # Pretty output
        if not result.findings:
            console.print(Panel(
                "[green]No performance issues found![/green]\n\n"
                f"Analyzed {result.metadata.node_count} nodes.",
                title="QuerySense",
                border_style="green",
            ))
            return
        
        # Show findings
        console.print(f"\n[bold]Found {len(result.findings)} issue(s):[/bold]\n")
        
        for i, finding in enumerate(result.findings, 1):
            # Severity color
            if finding.severity == Severity.CRITICAL:
                severity_style = "red bold"
            elif finding.severity == Severity.WARNING:
                severity_style = "yellow"
            else:
                severity_style = "blue"
            
            # Print finding
            console.print(f"[{severity_style}][{finding.severity.value.upper()}][/{severity_style}] {finding.title}")
            console.print(f"   [dim]{finding.description}[/dim]")
            
            if finding.suggestion:
                console.print(f"\n   [bold]Fix:[/bold]")
                for line in finding.suggestion.split("\n"):
                    if line.startswith("--"):
                        console.print(f"   [dim]{line}[/dim]")
                    else:
                        console.print(f"   [green]{line}[/green]")
            
            console.print()
        
        # Summary
        console.print(f"[dim]Analyzed {result.metadata.node_count} nodes in {result.metadata.rules_run} rule(s)[/dim]")
        
    except ParseError as e:
        error_console.print(f"[red]Error:[/red] {e.message}")
        if e.detail:
            error_console.print(f"\n[dim]{e.detail}[/dim]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
