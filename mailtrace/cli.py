"""CLI commands for MailTrace."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import typer
from rich.console import Console
from rich.table import Table

from mailtrace.core.configuration import get_config
from mailtrace.core.orchestrator import run_investigation as run_investigation_async
from mailtrace.reporting import ReportGenerator
from mailtrace.schemas.finding import (
    ExportFormat,
    Finding,
    Investigation,
    Profile,
    ReportOptions,
)
from mailtrace.storage import (
    close_database,
    get_database_manager,
    init_database,
)
from mailtrace.storage.repositories import FindingRepository, InvestigationRepository

console = Console()

_TERMINAL_SUCCESS = {"complete", "partial"}


def _mask_email(email: str) -> str:
    """Mask an email for display."""
    try:
        local, domain = email.split("@", 1)
    except ValueError:
        return "***@***"
    if len(local) <= 2:
        masked_local = local[:1] + "*" * max(len(local) - 1, 0)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def _mask_target(show_target: bool) -> bool:
    """Honor both the CLI flag and the configured privacy default."""
    return get_config().general.mask_output and not show_target


def _authorize(prompt: str, no_confirm: bool) -> None:
    """Require confirmation before external calls unless explicitly skipped."""
    if no_confirm or not get_config().general.confirm_external:
        return
    if not typer.confirm(prompt):
        console.print("[yellow]Cancelled[/yellow]")
        raise typer.Exit(0)


def _report_options(
    format: ExportFormat,
    output: Path | None,
    *,
    show_target: bool = False,
    include_evidence: bool = True,
) -> ReportOptions:
    return ReportOptions(
        format=format,
        output_path=str(output) if output else None,
        include_evidence=include_evidence,
        mask_target=_mask_target(show_target),
    )


def _write_report(
    investigation: Investigation,
    format: ExportFormat,
    output: Path | None,
    *,
    show_target: bool = False,
    include_evidence: bool = True,
) -> None:
    """Generate and emit a report, handling text and binary formats."""
    options = _report_options(
        format, output, show_target=show_target, include_evidence=include_evidence
    )
    try:
        content = ReportGenerator(investigation).generate(options)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            output.write_bytes(content)
        else:
            output.write_text(content, encoding="utf-8")
        console.print(f"[green]Report saved to {output}[/green]")
        return

    if isinstance(content, bytes):
        console.print("[red]PDF output requires --output <file>[/red]")
        raise typer.Exit(1)

    console.print(content.rstrip("\n"), markup=False, highlight=False)


def _normalize_domain(value: str) -> str:
    """Validate and normalize a domain argument."""
    domain = value.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc
    domain = domain.rstrip(".")
    pattern = r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    if not re.fullmatch(pattern, domain):
        raise typer.BadParameter(f"Invalid domain: {value}")
    return domain


def _source_name(value: str) -> str:
    """Normalize source aliases used on the command line."""
    aliases = {
        "brave": "brave_search",
        "vt": "virustotal",
        "breach": "breachdirectory",
        "emailrep.io": "emailrep",
    }
    return aliases.get(value.lower(), value.lower())


def _provider_config(name: str) -> dict[str, Any]:
    """Build provider configuration from the current settings."""
    config = get_config()
    configs: dict[str, dict[str, Any]] = {
        "hibp": {
            "api_key": config.hibp.api_key,
            "base_url": config.hibp.base_url,
            "timeout": config.hibp.timeout,
            "rate_limit": config.hibp.rate_limit,
        },
        "breachdirectory": {
            "api_key": config.breachdirectory.api_key,
            "base_url": config.breachdirectory.base_url,
            "rapidapi_host": config.breachdirectory.rapidapi_host,
            "timeout": config.breachdirectory.timeout,
            "rate_limit": config.breachdirectory.rate_limit,
        },
        "emailrep": {
            "api_key": config.emailrep.api_key,
            "base_url": config.emailrep.base_url,
            "timeout": config.emailrep.timeout,
            "rate_limit": config.emailrep.rate_limit,
        },
        "github": {
            "token": config.github.token,
            "base_url": config.github.base_url,
            "timeout": config.github.timeout,
            "rate_limit": config.github.rate_limit,
        },
        "brave_search": {
            "api_key": config.brave_search.api_key,
            "base_url": config.brave_search.base_url,
            "timeout": config.brave_search.timeout,
            "rate_limit": config.brave_search.rate_limit,
        },
        "virustotal": {
            "api_key": config.virustotal.api_key,
            "base_url": config.virustotal.base_url,
            "timeout": config.virustotal.timeout,
            "rate_limit": config.virustotal.rate_limit,
        },
        "dns": {
            "resolvers": config.dns.resolvers,
            "timeout": config.dns.timeout,
            "rate_limit": config.dns.rate_limit,
        },
    }
    return {
        key: value for key, value in configs.get(name, {}).items() if value is not None
    }


# Scan command
def scan(
    email: str = typer.Argument(..., help="Target email address"),
    profile: Profile = typer.Option(
        Profile.FULL, "--profile", "-p", help="Investigation profile"
    ),
    format: ExportFormat = typer.Option(
        ExportFormat.TERMINAL, "--format", "-f", help="Output format"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    no_confirm: bool = typer.Option(
        False, "--no-confirm", help="Skip authorization confirmation"
    ),
    show_target: bool = typer.Option(
        False, "--show-target", help="Show the full email in output"
    ),
) -> None:
    """Run a full investigation on an email address."""
    console.print("[bold]MailTrace Scan[/bold]")
    console.print(f"Target: {email if show_target else _mask_email(email)}")
    console.print(f"Profile: {profile.value}")
    console.print(f"Format: {format.value}")

    _authorize(
        "This will send the email to configured external providers. Continue?",
        no_confirm,
    )
    console.print("[green]Starting investigation...[/green]")

    try:
        investigation = asyncio.run(
            run_investigation_async(email, profile, authorization_confirmed=True)
        )
    except Exception as exc:
        console.print(f"[red]Investigation failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    _write_report(investigation, format, output, show_target=show_target)


# Breach command
breach_app = typer.Typer(
    name="breach", help="Breach intelligence checks", add_completion=False
)


@breach_app.command("check")
def breach_check(
    email: str = typer.Argument(..., help="Target email address"),
    format: ExportFormat = typer.Option(
        ExportFormat.TERMINAL, "--format", "-f", help="Output format"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    no_confirm: bool = typer.Option(
        False, "--no-confirm", help="Skip authorization confirmation"
    ),
    show_target: bool = typer.Option(
        False, "--show-target", help="Show the full email in output"
    ),
) -> None:
    """Check an email against breach databases."""
    console.print(f"[bold]Breach Check[/bold]: {_mask_email(email)}")
    _authorize("This will send the email to breach providers. Continue?", no_confirm)

    try:
        investigation = asyncio.run(
            run_investigation_async(
                email, Profile.BREACH, authorization_confirmed=True
            )
        )
    except Exception as exc:
        console.print(f"[red]Breach check failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    _write_report(investigation, format, output, show_target=show_target)


# Exposure command
exposure_app = typer.Typer(
    name="exposure", help="Public exposure searches", add_completion=False
)


@exposure_app.command("search")
def exposure_search(
    email: str = typer.Argument(..., help="Target email address"),
    format: ExportFormat = typer.Option(
        ExportFormat.TERMINAL, "--format", "-f", help="Output format"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    no_confirm: bool = typer.Option(
        False, "--no-confirm", help="Skip authorization confirmation"
    ),
    show_target: bool = typer.Option(
        False, "--show-target", help="Show the full email in output"
    ),
) -> None:
    """Search public indexes for email exposure."""
    console.print(f"[bold]Exposure Search[/bold]: {_mask_email(email)}")
    _authorize(
        "This will send the email to public search providers. Continue?",
        no_confirm,
    )

    try:
        investigation = asyncio.run(
            run_investigation_async(
                email, Profile.PUBLIC, authorization_confirmed=True
            )
        )
    except Exception as exc:
        console.print(f"[red]Exposure search failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    _write_report(investigation, format, output, show_target=show_target)


# Domain command
domain_app = typer.Typer(
    name="domain", help="Domain intelligence", add_completion=False
)


@domain_app.command("inspect")
def domain_inspect(
    domain: str = typer.Argument(..., help="Target domain"),
    format: ExportFormat = typer.Option(
        ExportFormat.TERMINAL, "--format", "-f", help="Output format"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    no_confirm: bool = typer.Option(
        False, "--no-confirm", help="Skip authorization confirmation"
    ),
) -> None:
    """Inspect domain DNS records and reputation."""
    normalized_domain = _normalize_domain(domain)
    console.print(f"[bold]Domain Inspection[/bold]: {normalized_domain}")
    _authorize(
        "This will query DNS resolvers and configured domain providers. Continue?",
        no_confirm,
    )

    # Domain providers only consume the domain portion of the address. The
    # local-part is intentionally a fixed placeholder and is not persisted.
    email = f"postmaster@{normalized_domain}"

    try:
        investigation = asyncio.run(
            run_investigation_async(
                email, Profile.DOMAIN, authorization_confirmed=True
            )
        )
    except Exception as exc:
        console.print(f"[red]Domain inspection failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    _write_report(investigation, format, output)


# Sources command
sources_app = typer.Typer(
    name="sources", help="Manage and test sources", add_completion=False
)


@sources_app.command("list")
def sources_list() -> None:
    """List all configured sources."""
    config = get_config()
    table = Table(title="Configured Sources")
    table.add_column("Provider")
    table.add_column("Enabled")
    table.add_column("Credentials")
    table.add_column("Status")

    providers = [
        ("HIBP", config.hibp.enabled, bool(config.hibp.api_key), "API key"),
        (
            "BreachDirectory",
            config.breachdirectory.enabled,
            bool(config.breachdirectory.api_key),
            "API key",
        ),
        (
            "emailrep.io",
            config.emailrep.enabled,
            True,
            "No key required",
        ),
        ("GitHub", config.github.enabled, bool(config.github.token), "Token"),
        (
            "Brave Search",
            config.brave_search.enabled,
            bool(config.brave_search.api_key),
            "API key",
        ),
        (
            "VirusTotal",
            config.virustotal.enabled,
            bool(config.virustotal.api_key),
            "API key",
        ),
        ("DNS", config.dns.enabled, True, "No key required"),
    ]

    for name, enabled, configured, credential_type in providers:
        if not enabled:
            status = "Disabled"
        elif configured:
            status = "Ready"
        else:
            status = f"Missing {credential_type.lower()}"
        table.add_row(
            name,
            "Yes" if enabled else "No",
            "Yes" if configured else "No",
            status,
        )

    console.print(table)


async def _check_source(name: str) -> None:
    """Run a provider health check and print the result."""
    config_errors = get_config().configure_errors()
    if name in config_errors:
        console.print(f"[red]{name}: {config_errors[name]}[/red]")
        return

    from mailtrace.providers import get_provider_class

    provider_class = get_provider_class(name)
    if provider_class is None:
        console.print(f"[red]Unknown source: {name}[/red]")
        return

    provider = provider_class(_provider_config(name))
    try:
        await provider.initialize()
        health = await provider.health_check()
    finally:
        await provider.cleanup()

    if health["healthy"]:
        console.print(f"[green]{name}: {health['message']}[/green]")
    else:
        console.print(f"[red]{name}: {health['message']}[/red]")


@sources_app.command("status")
def sources_status() -> None:
    """Check the status of all enabled sources."""
    config = get_config()
    enabled = config.get_enabled_providers()
    if not enabled:
        console.print("[yellow]No sources are enabled[/yellow]")
        return

    console.print("[bold]Source Status Check[/bold]")

    async def _run() -> None:
        for name in enabled:
            await _check_source(name)

    asyncio.run(_run())


@sources_app.command("test")
def sources_test(
    source: str = typer.Argument(
        ..., help="Source to test (hibp, breachdirectory, emailrep, github, brave, virustotal, dns)"
    ),
) -> None:
    """Test a specific source."""
    name = _source_name(source)
    console.print(f"[bold]Testing {name}[/bold]")

    async def _run() -> None:
        await _check_source(name)

    asyncio.run(_run())


# History command
history_app = typer.Typer(
    name="history", help="Investigation history", add_completion=False
)


@history_app.command("list")
def history_list(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of results"),
) -> None:
    """List investigation history."""
    config = get_config()

    async def _run() -> None:
        await init_database(data_dir=config.general.data_dir)
        try:
            async with get_database_manager().session() as session:
                inv_repo = InvestigationRepository(session)
                finding_repo = FindingRepository(session)
                investigations = await inv_repo.list(limit=limit)

                if not investigations:
                    console.print("[yellow]No investigations found[/yellow]")
                    return

                table = Table(title="Investigation History")
                table.add_column("Date")
                table.add_column("Target")
                table.add_column("Profile")
                table.add_column("Status")
                table.add_column("Findings")
                table.add_column("ID")

                for investigation in investigations:
                    finding_count = await finding_repo.count_by_investigation(
                        investigation.id
                    )
                    table.add_row(
                        investigation.created_at.strftime("%Y-%m-%d %H:%M"),
                        investigation.target_masked,
                        investigation.profile.value,
                        investigation.status.value,
                        str(finding_count),
                        str(investigation.id),
                    )
            console.print(table)
        finally:
            await close_database()

    asyncio.run(_run())


@history_app.command("compare")
def history_compare(
    case_a: str = typer.Argument(..., help="First case ID"),
    case_b: str = typer.Argument(..., help="Second case ID"),
) -> None:
    """Compare the findings of two investigations."""
    try:
        first_id = UUID(case_a)
        second_id = UUID(case_b)
    except ValueError as exc:
        console.print("[red]Invalid case ID format[/red]")
        raise typer.Exit(1) from exc

    config = get_config()

    async def _run() -> None:
        await init_database(data_dir=config.general.data_dir)
        try:
            async with get_database_manager().session() as session:
                inv_repo = InvestigationRepository(session)
                first = await inv_repo.get_schema(first_id)
                second = await inv_repo.get_schema(second_id)
        finally:
            await close_database()

        if first is None or second is None:
            missing = case_a if first is None else case_b
            console.print(f"[red]Case not found: {missing}[/red]")
            return

        def signature(finding: Finding) -> tuple[str, str, str, str]:
            return (
                finding.finding_type.value,
                finding.title,
                finding.service_name or "",
                finding.domain or "",
            )

        first_findings = {signature(finding) for finding in first.findings}
        second_findings = {signature(finding) for finding in second.findings}
        added = second_findings - first_findings
        removed = first_findings - second_findings

        console.print(
            f"[bold]Comparing[/bold] {str(first.id)[:8]} vs {str(second.id)[:8]}"
        )
        console.print(
            f"Findings: {len(first.findings)} → {len(second.findings)} "
            f"({len(added)} added, {len(removed)} removed)"
        )

        table = Table(title="Finding Changes")
        table.add_column("Change")
        table.add_column("Type")
        table.add_column("Title")
        table.add_column("Service")
        table.add_column("Domain")
        for change, items in (("Added", added), ("Removed", removed)):
            for finding_type, title, service, domain in sorted(items):
                table.add_row(change, finding_type, title, service, domain)
        if added or removed:
            console.print(table)
        else:
            console.print("[green]No finding changes detected[/green]")

    asyncio.run(_run())


# Case command
case_app = typer.Typer(name="case", help="Case management", add_completion=False)


@case_app.command("show")
def case_show(
    case_id: str = typer.Argument(..., help="Case ID"),
    format: ExportFormat = typer.Option(
        ExportFormat.TERMINAL, "--format", "-f", help="Output format"
    ),
    show_target: bool = typer.Option(
        False, "--show-target", help="Show the full email when available"
    ),
) -> None:
    """Show case details."""
    _require_case(case_id, lambda investigation: _write_report(
        investigation, format, None, show_target=show_target
    ))


@case_app.command("delete")
def case_delete(
    case_id: str = typer.Argument(..., help="Case ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a case and all related records."""
    try:
        investigation_id = UUID(case_id)
    except ValueError as exc:
        console.print("[red]Invalid case ID format[/red]")
        raise typer.Exit(1) from exc

    if not force and not typer.confirm(f"Delete case {case_id}?"):
        console.print("[yellow]Cancelled[/yellow]")
        return

    config = get_config()

    async def _run() -> None:
        await init_database(data_dir=config.general.data_dir)
        try:
            async with get_database_manager().session() as session:
                deleted = await InvestigationRepository(session).delete(
                    investigation_id
                )
        finally:
            await close_database()

        if deleted:
            console.print(f"[green]Case {case_id} deleted[/green]")
        else:
            console.print(f"[red]Case {case_id} not found[/red]")

    asyncio.run(_run())


def _require_case(case_id: str, callback: Callable[[Investigation], None]) -> None:
    """Load a case by ID and pass the Pydantic schema to a callback."""
    try:
        investigation_id = UUID(case_id)
    except ValueError as exc:
        console.print("[red]Invalid case ID format[/red]")
        raise typer.Exit(1) from exc

    config = get_config()

    async def _run() -> Investigation | None:
        await init_database(data_dir=config.general.data_dir)
        try:
            async with get_database_manager().session() as session:
                investigation = await InvestigationRepository(session).get_schema(
                    investigation_id
                )
        finally:
            await close_database()
        return investigation

    investigation = asyncio.run(_run())
    if investigation is None:
        console.print(f"[red]Case not found: {case_id}[/red]")
        raise typer.Exit(1)
    callback(investigation)


# Report command
def report(
    case_id: str = typer.Argument(..., help="Case ID"),
    format: ExportFormat = typer.Option(
        ExportFormat.TERMINAL, "--format", "-f", help="Output format"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    include_evidence: bool = typer.Option(
        True, "--evidence/--no-evidence", help="Include evidence"
    ),
    mask_target: bool = typer.Option(
        True, "--mask/--show-target", help="Mask the target email"
    ),
) -> None:
    """Generate a report for a case."""
    _require_case(
        case_id,
        lambda investigation: _write_report(
            investigation,
            format,
            output,
            show_target=not mask_target,
            include_evidence=include_evidence,
        ),
    )


# Config command
config_app = typer.Typer(
    name="config", help="Configuration management", add_completion=False
)


@config_app.command("show")
def config_show() -> None:
    """Show current configuration."""
    config = get_config()
    console.print("[bold]MailTrace Configuration[/bold]")
    console.print(f"Data directory: {config.general.data_dir}")
    console.print(f"Mask output: {config.general.mask_output}")
    console.print(f"Confirm external: {config.general.confirm_external}")
    console.print(f"Log level: {config.general.log_level}")
    console.print(f"Theme: {config.general.theme}")
    console.print("\n[bold]Providers:[/bold]")
    console.print(
        f"  HIBP: enabled={config.hibp.enabled}, "
        f"key={'set' if config.hibp.api_key else 'not set'}"
    )
    console.print(
        f"  BreachDirectory: enabled={config.breachdirectory.enabled}, "
        f"key={'set' if config.breachdirectory.api_key else 'not set'}"
    )
    console.print(
        f"  emailrep.io: enabled={config.emailrep.enabled}, "
        f"key={'set' if config.emailrep.api_key else 'not set'}"
    )
    console.print(
        f"  GitHub: enabled={config.github.enabled}, "
        f"token={'set' if config.github.token else 'not set'}"
    )
    console.print(
        f"  Brave Search: enabled={config.brave_search.enabled}, "
        f"key={'set' if config.brave_search.api_key else 'not set'}"
    )
    console.print(
        f"  VirusTotal: enabled={config.virustotal.enabled}, "
        f"key={'set' if config.virustotal.api_key else 'not set'}"
    )
    console.print(f"  DNS: enabled={config.dns.enabled}")


@config_app.command("validate")
def config_validate() -> None:
    """Validate configuration."""
    errors = get_config().configure_errors()

    if errors:
        console.print("[red]Configuration Errors:[/red]")
        for provider, error in errors.items():
            console.print(f"  {provider}: {error}")
        raise typer.Exit(1)

    console.print("[green]All enabled providers are configured[/green]")


@config_app.command("setup")
def config_setup() -> None:
    """Show configuration instructions."""
    console.print("[bold]MailTrace Configuration Setup[/bold]")
    console.print(
        "Copy [cyan].env.example[/cyan] to [cyan].env[/cyan] and fill in your keys, "
        "or export the variables below."
    )
    console.print("\nEnvironment variables:")
    console.print("  HIBP_API_KEY=your_key")
    console.print("  BREACHDIRECTORY_API_KEY=your_key")
    console.print("  EMAILREP_API_KEY=your_key (optional)")
    console.print("  GITHUB_TOKEN=your_token")
    console.print("  BRAVE_API_KEY=your_key")
    console.print("  VIRUSTOTAL_API_KEY=your_key")
    console.print("\nGeneral settings (optional):")
    console.print("  MAILTRACE_GENERAL_DATA_DIR=~/.local/share/mailtrace")
    console.print("  MAILTRACE_GENERAL_MASK_OUTPUT=true")
    console.print("  MAILTRACE_GENERAL_CONFIRM_EXTERNAL=true")
    console.print(
        "\nProvider TOML: copy config/providers.example.toml to "
        "~/.config/mailtrace/providers.toml"
    )


# Export all subcommand apps
__all__ = [
    "breach_app",
    "case_app",
    "config_app",
    "domain_app",
    "exposure_app",
    "history_app",
    "report",
    "scan",
    "sources_app",
]
