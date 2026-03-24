"""CLI entry point for ai-secrets-guard."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console
from rich.table import Table

import ai_secrets_guard
from ai_secrets_guard.core.config import AppConfig
from ai_secrets_guard.core.models import Finding
from ai_secrets_guard.core.severity import Severity

if TYPE_CHECKING:
    from ai_secrets_guard.core.models import ProbePayload

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.option(
    "--config", "-c", type=click.Path(exists=True), default=None, help="Path to config YAML."
)
@click.version_option(version=ai_secrets_guard.__version__, prog_name="ai-secrets-guard")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config: str | None) -> None:
    """ai-secrets-guard — security scanner for AI/LLM projects."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config"] = AppConfig.from_yaml(config) if config else AppConfig()


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table"
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="high",
    help="Exit with code 1 if findings reach this severity.",
)
@click.pass_context
def scan(ctx: click.Context, path: str, output_format: str, fail_on: str) -> None:
    """Scan a project for security issues (static analysis)."""
    from ai_secrets_guard.scan.scanner import run_scan

    app_config: AppConfig = ctx.obj["config"]
    verbose: bool = ctx.obj["verbose"]

    if verbose:
        err_console.print(f"[dim]Scanning {path}...[/dim]")

    result = run_scan(path, config=app_config.scan)

    if output_format == "json":
        click.echo(result.model_dump_json(indent=2))
    else:
        _print_table(result.findings)

    threshold = Severity[fail_on.upper()]
    if result.max_severity >= threshold:
        sys.exit(1)


@cli.command()
@click.option("--target", "-t", required=True, help="Target LLM API endpoint URL.")
@click.option("--model", "-m", default=None, help="Target model name.")
@click.option("--judge/--no-judge", default=True, help="Use LLM as vulnerability judge.")
@click.option(
    "--category", type=click.Choice(["all", "injection", "jailbreak", "extraction"]), default="all"
)
@click.pass_context
def probe(ctx: click.Context, target: str, model: str | None, judge: bool, category: str) -> None:
    """Probe live AI endpoints with injection payloads (dynamic testing)."""
    import asyncio

    from ai_secrets_guard.probe.payloads import (
        EXFILTRATION_PAYLOADS,
        INJECTION_PAYLOADS,
        JAILBREAK_CHAINS,
        get_all_payloads,
    )
    from ai_secrets_guard.probe.runner import run_probes

    app_config: AppConfig = ctx.obj["config"]
    probe_config = app_config.probe
    if model:
        probe_config.judge_model = model

    payload_map: dict[str, Callable[[], list[ProbePayload]]] = {
        "all": get_all_payloads,
        "injection": lambda: INJECTION_PAYLOADS,
        "jailbreak": lambda: JAILBREAK_CHAINS,
        "extraction": lambda: EXFILTRATION_PAYLOADS,
    }
    payloads = payload_map[category]()

    with console.status("[bold cyan]Probing endpoint..."):
        result = asyncio.run(
            run_probes(
                target,
                payloads=payloads,
                config=probe_config,
                judge_enabled=judge,
            )
        )

    vuln_count = result.vulnerable_count
    total = len(result.responses)
    color = "red" if vuln_count > 0 else "green"

    console.print(f"\n[bold {color}]{vuln_count}/{total} payloads triggered vulnerabilities[/]")

    for resp in result.responses:
        icon = "🔴" if resp.is_vulnerable else "🟢"
        console.print(f"  {icon} {resp.payload_name}: {resp.judge_verdict[:80]}")

    if vuln_count > 0:
        sys.exit(1)


@cli.command()
@click.option(
    "--input",
    "-i",
    "input_path",
    required=True,
    type=click.Path(exists=True),
    help="JSON scan results file.",
)
@click.option("--output", "-o", "output_dir", default="reports", help="Output directory.")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["html", "json", "markdown", "all"]),
    default="all",
)
@click.option("--title", default="AI Secrets Guard Report")
@click.pass_context
def report(
    ctx: click.Context, input_path: str, output_dir: str, output_format: str, title: str
) -> None:
    """Generate reports from scan results."""
    from ai_secrets_guard.core.models import ScanResult
    from ai_secrets_guard.report.html import write_html
    from ai_secrets_guard.report.json_report import write_json
    from ai_secrets_guard.report.markdown import write_markdown

    raw = Path(input_path).read_text()
    result = ScanResult.model_validate_json(raw)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    formats = ["html", "json", "markdown"] if output_format == "all" else [output_format]

    for fmt in formats:
        if fmt == "html":
            p = write_html(result, out / "report.html", title=title)
            console.print(f"  [green]✓[/] HTML:     {p}")
        elif fmt == "json":
            p = write_json(result, out / "report.json")
            console.print(f"  [green]✓[/] JSON:     {p}")
        elif fmt == "markdown":
            p = write_markdown(result, out / "report.md", title=title)
            console.print(f"  [green]✓[/] Markdown: {p}")


def _print_table(findings: list[Finding]) -> None:
    if not findings:
        console.print("[bold green]✅ No security issues found![/]")
        return

    table = Table(title="Security Findings", border_style="dim")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", style="cyan", width=20)
    table.add_column("Title", width=35)
    table.add_column("Location", style="dim", width=40)

    sorted_findings = sorted(findings, key=lambda f: f.severity, reverse=True)
    for f in sorted_findings:
        sev_style = f"[{f.severity.color}]{f.severity.label}[/]"
        loc = ""
        if f.file_path:
            loc = f.file_path
            if f.line_number:
                loc += f":{f.line_number}"
        table.add_row(sev_style, f.rule_id, f.title, loc)

    console.print(table)
    console.print(f"\n[bold]Total: {len(findings)} findings[/]")
