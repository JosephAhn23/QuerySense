"""
QuerySense CLI - Database query performance analyzer.

Supports PostgreSQL and MySQL EXPLAIN output.

Usage:
    querysense analyze explain.json
    querysense analyze --database mysql mysql_explain.json
    querysense analyze --help
"""

from __future__ import annotations

import json
from enum import Enum
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


class DatabaseType(str, Enum):
    """Supported database types."""
    postgres = "postgres"
    mysql = "mysql"
    auto = "auto"


app = typer.Typer(
    name="querysense",
    help="Database query performance analyzer (PostgreSQL & MySQL)",
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
    """QuerySense - Database query performance analyzer."""
    pass


def detect_database_type(data: dict | list) -> DatabaseType:
    """Auto-detect database type from EXPLAIN output."""
    # PostgreSQL format: list with Plan object
    if isinstance(data, list) and len(data) > 0:
        first = data[0]
        if isinstance(first, dict):
            # PostgreSQL has "Plan" key with "Node Type"
            if "Plan" in first and "Node Type" in first.get("Plan", {}):
                return DatabaseType.postgres
            # MySQL traditional format has "type" and "select_type"
            if "type" in first and "select_type" in first:
                return DatabaseType.mysql
    
    # MySQL JSON format has "query_block"
    if isinstance(data, dict) and "query_block" in data:
        return DatabaseType.mysql
    
    # Default to PostgreSQL
    return DatabaseType.postgres


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
    database: Annotated[
        DatabaseType,
        typer.Option(
            "--database",
            "-d",
            help="Database type (auto-detected if not specified)",
        ),
    ] = DatabaseType.auto,
    require_analyze: Annotated[
        bool,
        typer.Option(
            "--require-analyze/--allow-plain",
            help="Require EXPLAIN ANALYZE output (PostgreSQL only)",
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
    Analyze database EXPLAIN output for performance issues.
    
    Supports PostgreSQL and MySQL.
    
    Examples:
    
        # PostgreSQL
        $ psql -c "EXPLAIN (ANALYZE, FORMAT JSON) SELECT * FROM users" > explain.json
        $ querysense analyze explain.json
        
        # MySQL
        $ mysql -e "EXPLAIN FORMAT=JSON SELECT * FROM users" > explain.json
        $ querysense analyze --database mysql explain.json
    """
    try:
        # Read the file
        raw_content = explain_file.read_text()
        data = json.loads(raw_content)
        
        # Auto-detect database type if needed
        db_type = database
        if db_type == DatabaseType.auto:
            db_type = detect_database_type(data)
            console.print(f"[dim]Detected database: {db_type.value}[/dim]\n")
        
        # Route to appropriate analyzer
        if db_type == DatabaseType.mysql:
            # MySQL analyzer
            from querysense.analyzers.mysql import MySQLAnalyzer
            
            mysql_analyzer = MySQLAnalyzer()
            parsed = mysql_analyzer.parse_plan(data)
            findings = mysql_analyzer.detect_issues(parsed)
            node_count = len(parsed.nodes)
            rules_run = 5  # Number of MySQL rules
            
        else:
            # PostgreSQL analyzer (default)
            output = parse_explain(explain_file)
            
            if require_analyze:
                validate_has_analyze(output)
            
            analyzer = Analyzer()
            result = analyzer.analyze(output)
            findings = result.findings
            node_count = result.metadata.node_count
            rules_run = result.metadata.rules_run
        
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
                        "table": f.context.relation_name if f.context else None,
                        "rows": f.context.actual_rows if f.context else None,
                    }
                    for f in findings
                ],
                "summary": {
                    "findings_count": len(findings),
                    "nodes_analyzed": node_count,
                    "rules_run": rules_run,
                    "database": db_type.value,
                },
            }
            console.print_json(json.dumps(output_data, indent=2))
            return
        
        # Pretty output
        if not findings:
            console.print(Panel(
                "[green]No performance issues found![/green]\n\n"
                f"Analyzed {node_count} nodes ({db_type.value}).",
                title="QuerySense",
                border_style="green",
            ))
            return
        
        # Show findings
        console.print(f"[bold]Found {len(findings)} issue(s):[/bold]\n")
        
        for i, finding in enumerate(findings, 1):
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
        console.print(f"[dim]Analyzed {node_count} nodes with {rules_run} rule(s) ({db_type.value})[/dim]")
        
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
    database: Annotated[
        DatabaseType,
        typer.Option(
            "--database",
            "-d",
            help="Database type (auto-detected if not specified)",
        ),
    ] = DatabaseType.auto,
    require_analyze: Annotated[
        bool,
        typer.Option(
            "--require-analyze/--allow-plain",
            help="Require EXPLAIN ANALYZE output (PostgreSQL only)",
        ),
    ] = True,
) -> None:
    """
    Output copy-paste SQL fixes for performance issues.
    
    Unlike 'analyze', this command outputs ONLY the SQL statements
    needed to fix detected issues - ready to copy-paste into your
    database client.
    
    Examples:
    
        # Get fixes and apply directly
        $ querysense fix slow_query.json | psql
        
        # Review fixes first
        $ querysense fix slow_query.json > fixes.sql
        $ cat fixes.sql
        $ psql < fixes.sql
    """
    try:
        # Read the file
        raw_content = explain_file.read_text()
        data = json.loads(raw_content)
        
        # Auto-detect database type if needed
        db_type = database
        if db_type == DatabaseType.auto:
            db_type = detect_database_type(data)
        
        # Route to appropriate analyzer
        if db_type == DatabaseType.mysql:
            from querysense.analyzers.mysql import MySQLAnalyzer
            
            mysql_analyzer = MySQLAnalyzer()
            parsed = mysql_analyzer.parse_plan(data)
            findings = mysql_analyzer.detect_issues(parsed)
            
        else:
            # PostgreSQL analyzer (default)
            output = parse_explain(explain_file)
            
            if require_analyze:
                validate_has_analyze(output)
            
            analyzer = Analyzer()
            result = analyzer.analyze(output)
            findings = result.findings
        
        if not findings:
            console.print("-- No performance issues found. Nothing to fix.")
            return
        
        # Output SQL header
        console.print(f"-- QuerySense Fixes ({db_type.value})")
        console.print(f"-- {len(findings)} issue(s) detected\n")
        
        seen_fixes: set[str] = set()  # Deduplicate identical fixes
        
        for finding in findings:
            if not finding.suggestion:
                continue
            
            # Extract just the SQL statements (lines not starting with --)
            sql_lines: list[str] = []
            for line in finding.suggestion.split("\n"):
                stripped = line.strip()
                # Skip comments and empty lines for the dedup check
                if stripped and not stripped.startswith("--"):
                    sql_lines.append(stripped)
            
            if not sql_lines:
                continue
            
            # Create unique key for dedup
            fix_key = "\n".join(sql_lines)
            if fix_key in seen_fixes:
                continue
            seen_fixes.add(fix_key)
            
            # Output with context comment
            console.print(f"-- [{finding.severity.value.upper()}] {finding.title}")
            
            # Output the full suggestion with proper formatting
            for line in finding.suggestion.split("\n"):
                if line.strip():
                    console.print(line)
            
            console.print()
        
        # Footer
        console.print("-- End of fixes")
        console.print(f"-- Run with: psql < fixes.sql" if db_type == DatabaseType.postgres else "-- Run in MySQL client")
        
    except ParseError as e:
        error_console.print(f"[red]Error:[/red] {e.message}")
        if e.detail:
            error_console.print(f"\n[dim]{e.detail}[/dim]")
        raise typer.Exit(code=1)


@app.command()
def rules(
    database: Annotated[
        DatabaseType,
        typer.Option(
            "--database",
            "-d",
            help="Show rules for specific database",
        ),
    ] = DatabaseType.postgres,
) -> None:
    """
    List all available detection rules.
    
    Shows rule IDs, descriptions, and severity levels.
    """
    from querysense.analyzer.registry import get_registry
    
    if database == DatabaseType.mysql or database == DatabaseType.auto:
        # Show MySQL rules
        console.print("[bold]MySQL Rules:[/bold]\n")
        mysql_rules = [
            ("FULL_TABLE_SCAN", "CRITICAL", "Detects type='ALL' on large tables"),
            ("MISSING_INDEX", "WARNING", "key=NULL when possible_keys exists"),
            ("USING_FILESORT", "WARNING", "Query requires filesort operation"),
            ("USING_TEMPORARY", "WARNING", "Query uses temporary tables"),
            ("BAD_JOIN_TYPE", "WARNING", "Suboptimal join access type"),
            ("NO_INDEX_USED", "INFO", "Query not using any index"),
        ]
        
        table = Table()
        table.add_column("Rule ID", style="cyan")
        table.add_column("Severity")
        table.add_column("Description")
        
        for rule_id, severity, desc in mysql_rules:
            if severity == "CRITICAL":
                sev_style = "red bold"
            elif severity == "WARNING":
                sev_style = "yellow"
            else:
                sev_style = "blue"
            
            table.add_row(rule_id, f"[{sev_style}]{severity}[/{sev_style}]", desc)
        
        console.print(table)
        console.print()
    
    if database == DatabaseType.postgres or database == DatabaseType.auto:
        # Show PostgreSQL rules
        console.print("[bold]PostgreSQL Rules:[/bold]\n")
        
        registry = get_registry()
        rules = registry.all()
        
        table = Table()
        table.add_column("Rule ID", style="cyan")
        table.add_column("Severity")
        table.add_column("Description")
        
        for rule_cls in sorted(rules, key=lambda r: r.rule_id):
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


if __name__ == "__main__":
    app()
