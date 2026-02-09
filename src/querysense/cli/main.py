"""
QuerySense CLI - PostgreSQL query performance analyzer.

Thin entry point that wires up Typer apps and delegates
to command modules. All business logic lives in AnalysisService;
all rendering logic lives in querysense.output.

Usage:
    querysense analyze explain.json
    querysense fix explain.json
    querysense rules
    querysense ci analyze plans/**/*.json
    querysense ci baseline update plans/**/*.json
"""

from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console

from querysense import __version__

# ── Typer app hierarchy ──────────────────────────────────────────────────

app = typer.Typer(
    name="querysense",
    help="PostgreSQL query performance analyzer",
    no_args_is_help=True,
)

ci_app = typer.Typer(
    name="ci",
    help="CI/CD integration commands for pipeline gating",
    no_args_is_help=True,
)

baseline_app = typer.Typer(
    name="baseline",
    help="Manage plan baselines for regression detection",
    no_args_is_help=True,
)

policy_app = typer.Typer(
    name="policy",
    help="Manage query performance policies for enforcement",
    no_args_is_help=True,
)

upgrade_app = typer.Typer(
    name="upgrade",
    help="Post-upgrade plan validation commands",
    no_args_is_help=True,
)

compliance_app = typer.Typer(
    name="compliance",
    help="Compliance enforcement and audit commands",
    no_args_is_help=True,
)

app.add_typer(ci_app, name="ci")
app.add_typer(baseline_app, name="baseline")
app.add_typer(upgrade_app, name="upgrade")
app.add_typer(compliance_app, name="compliance")
app.add_typer(policy_app, name="policy")
app.add_typer(upgrade_app, name="upgrade-check")

console = Console()

# ── Register command modules ──────────────────────────────────────────────

from querysense.cli.commands.analyze import register as register_analyze
from querysense.cli.commands.baseline import register as register_baseline
from querysense.cli.commands.ci import register as register_ci
from querysense.cli.commands.compliance import register as register_compliance
from querysense.cli.commands.policy import register as register_policy
from querysense.cli.commands.upgrade import register as register_upgrade
from querysense.cli.commands.watch import register as register_watch
from querysense.cli.commands.ir import register as register_ir

register_analyze(app)
register_ci(ci_app)
register_baseline(baseline_app)
register_policy(policy_app)
register_upgrade(upgrade_app)
register_compliance(compliance_app)
register_watch(app)
register_ir(app)


# ── Version callback ──────────────────────────────────────────────────────


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


if __name__ == "__main__":
    app()
