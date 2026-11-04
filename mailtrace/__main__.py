"""Main entry point for MailTrace - dual-mode TUI and CLI."""

import sys

import typer
from rich.console import Console

from mailtrace.cli import (
    breach_app,
    case_app,
    config_app,
    domain_app,
    exposure_app,
    history_app,
    report,
    scan,
    sources_app,
)
from mailtrace.tui.app import MailTraceApp

console = Console()
app = typer.Typer(
    name="mailtrace",
    help="Cross-platform email exposure intelligence CLI/TUI",
    add_completion=False,
    no_args_is_help=False,
)

# Add CLI commands
app.command()(scan)
app.add_typer(breach_app, name="breach")
app.add_typer(exposure_app, name="exposure")
app.add_typer(domain_app, name="domain")
app.add_typer(sources_app, name="sources")
app.add_typer(history_app, name="history")
app.add_typer(case_app, name="case")
app.command()(report)
app.add_typer(config_app, name="config")


def cli_main() -> None:
    """Entry point for console script."""
    # Check if any args provided
    if len(sys.argv) == 1:
        # No args - launch TUI
        try:
            MailTraceApp().run()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/yellow]")
            sys.exit(130)
        except Exception as e:
            console.print(f"[red]Fatal error:[/red] {e}")
            sys.exit(1)
    else:
        # Args provided - run CLI
        # Handle --version before subcommand parsing
        if "--version" in sys.argv or "-v" in sys.argv:
            from mailtrace import __version__
            console.print(f"MailTrace v{__version__}")
            sys.exit(0)
        app()


if __name__ == "__main__":
    cli_main()
