"""CLI entrypoint for agent-guard using Typer and Rich."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure workspace root is in sys.path when running cli.py directly
ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer
import uvicorn

from src.proxy import state

cli_app = typer.Typer(
    name="agent-guard",
    help="Local lightweight proxy-firewall for AI agents protecting against secret leaks and infinite loops.",
    no_args_is_help=False,
)

console = Console()


def render_dashboard(host: str, port: int, upstream: str) -> None:
    """Render a beautiful Rich dashboard with status, filters, and metrics."""
    table = Table.grid(padding=(0, 2))
    table.add_column("Category", style="bold cyan", justify="right")
    table.add_column("Details", style="white")

    table.add_row("Proxy Address", f"[bold green]http://{host}:{port}[/bold green]")
    table.add_row("Upstream API", f"[bold yellow]{upstream}[/bold yellow]")
    table.add_row("Status", "[bold green]ONLINE[/bold green] (Listening for /v1/chat/completions)")
    table.add_row("", "")

    # Filters section
    table.add_row(
        "Active Filters",
        "[bold cyan]1. SecretRedactor[/bold cyan] [green]ACTIVE[/green]\n"
        "   └─ OpenAI (sk-*), Anthropic (sk-ant-*), Google AI, AWS, JWT, .env (KEY=VALUE)\n"
        "[bold cyan]2. LoopDetector[/bold cyan]   [green]ACTIVE[/green]\n"
        "   └─ 3x Consecutive Tool Calls, Repeating Terminal/Compiler Errors, Cycling Requests",
    )
    table.add_row("", "")

    # Metrics section
    table.add_row(
        "Live Metrics",
        f"• Loops Killed    : [bold red]{state.loops_killed}[/bold red]\n"
        f"• Secrets Masked  : [bold green]{state.secrets_redacted_total}[/bold green]\n"
        f"• Total Requests  : [bold blue]{state.requests_total}[/bold blue]",
    )

    panel = Panel(
        table,
        title="[bold blue]🛡️  AgentGuard Firewall & Loop Killer[/bold blue]",
        subtitle="[dim]Press CTRL+C to stop[/dim]",
        border_style="bright_blue",
        padding=(1, 2),
    )

    console.print()
    console.print(panel)
    console.print()


@cli_app.command(name="start")
def start(
    port: int = typer.Option(8085, "--port", "-p", help="Port to run proxy on"),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host interface to bind"),
    upstream: str = typer.Option(
        os.getenv("UPSTREAM_URL", "https://api.openai.com"),
        "--upstream",
        "-u",
        help="Upstream LLM API base URL",
    ),
) -> None:
    """Start the agent-guard proxy server."""
    state.upstream_url = upstream
    render_dashboard(host, port, upstream)
    uvicorn.run("src.proxy:app", host=host, port=port, reload=False)


@cli_app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    port: int = typer.Option(8085, "--port", "-p", help="Port to run proxy on"),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host interface to bind"),
    upstream: str = typer.Option(
        os.getenv("UPSTREAM_URL", "https://api.openai.com"),
        "--upstream",
        "-u",
        help="Upstream LLM API base URL",
    ),
) -> None:
    """Default entrypoint when running agent-guard without a subcommand."""
    if ctx.invoked_subcommand is None:
        start(port=port, host=host, upstream=upstream)


if __name__ == "__main__":
    cli_app()
