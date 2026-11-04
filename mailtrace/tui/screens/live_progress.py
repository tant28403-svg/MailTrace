"""Live progress screen for MailTrace TUI."""

import contextlib
from typing import Any, ClassVar

from textual import on, work
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, ProgressBar, RichLog, Static

from mailtrace.core.configuration import get_config
from mailtrace.core.orchestrator import Orchestrator
from mailtrace.schemas.finding import (
    Investigation,
    InvestigationStatus,
    Profile,
    ProviderStatus,
)
from mailtrace.storage import get_database_manager
from mailtrace.storage.repositories import ProviderRunRepository

# Provider statuses that mean the provider will not change again.
_TERMINAL_STATUSES = {
    ProviderStatus.COMPLETED_WITH_FINDINGS,
    ProviderStatus.COMPLETED_NO_MATCHES,
    ProviderStatus.FAILED,
    ProviderStatus.UNAUTHORIZED,
    ProviderStatus.RATE_LIMITED,
    ProviderStatus.UNAVAILABLE,
    ProviderStatus.TIMEOUT,
    ProviderStatus.CONFIGURATION_ERROR,
    ProviderStatus.UNSUPPORTED,
    ProviderStatus.PARTIAL,
}


class LiveProgressScreen(Screen[Any]):
    """Screen showing live investigation progress."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(self, email: str, profile: Profile):
        super().__init__()
        self._target_email = email
        self._profile = profile
        self.config = get_config()
        self.investigation: Investigation | None = None
        self.provider_runs: dict[str, Any] = {}
        self._orchestrator: Orchestrator | None = None
        self._poll_timer: Any = None
        self._last_status: dict[str, str] = {}
        self._finished = False
        self._cancelled = False

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Static(f"Investigation: {self._mask_email(self._target_email)}", id="inv-title"),
                Static(f"Profile: {self._profile.value}", id="inv-profile"),
                ProgressBar(total=100, show_eta=False, id="overall-progress"),
                Static("Providers:", id="providers-title"),
                DataTable(id="provider-table", cursor_type="row"),
                Static("Log:", id="log-title"),
                RichLog(id="progress-log", highlight=True, markup=True, wrap=True),
                Container(
                    Button("Cancel", id="btn-cancel", variant="error"),
                    id="button-row",
                ),
                id="progress-content",
            ),
            id="progress-container",
        )

    def _mask_email(self, email: str) -> str:
        """Mask email for display."""
        try:
            local, domain = email.split("@", 1)
            if len(local) <= 2:
                masked_local = local[0] + "*" * (len(local) - 1)
            else:
                masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
            return f"{masked_local}@{domain}"
        except ValueError:
            return "***@***"

    def on_mount(self) -> None:
        """Initialize progress screen."""
        self._setup_provider_table()
        self._poll_timer = self.set_interval(1.0, self._poll_provider_status)
        self._start_investigation()

    # ------------------------------------------------------------------
    # Investigation
    # ------------------------------------------------------------------

    def _start_investigation(self) -> None:
        """Start the investigation worker."""
        self._orchestrator = Orchestrator()
        self._log(
            f"[cyan]Starting investigation for {self._mask_email(self._target_email)}...[/cyan]"
        )
        self._run_investigation_worker(self._target_email, self._profile)

    @work(exclusive=True, thread=False, group="investigation")
    async def _run_investigation_worker(self, email: str, profile: Profile) -> None:
        """Run the investigation via the orchestrator.

        The orchestrator invokes ``_on_investigation_created`` as soon as the
        investigation and provider runs are persisted, which lets the polling
        timer query real-time progress while the providers are running.
        """
        try:
            assert self._orchestrator is not None
            self._log("[cyan]Initializing providers...[/cyan]")
            await self._orchestrator.initialize()

            if self._cancelled:
                return

            self._log("[cyan]Running provider checks...[/cyan]")
            investigation = await self._orchestrator.run_investigation(
                email=email,
                profile=profile,
                authorization_confirmed=True,
                on_investigation_created=self._on_investigation_created,
            )

            if self._cancelled:
                return

            self.investigation = investigation

            # Final refresh so the table matches the database exactly.
            await self._refresh_provider_status()
            self._investigation_done()

        except Exception as exc:
            self._investigation_error(str(exc))
        finally:
            if self._orchestrator is not None:
                await self._orchestrator.cleanup()

    def _on_investigation_created(self, investigation: Investigation) -> None:
        """Called by the orchestrator once the DB record exists."""
        self.investigation = investigation

        self._log(
            f"[cyan]Investigation {str(investigation.id)[:8]} started "
            f"({len(investigation.provider_runs)} providers).[/cyan]"
        )
        for run in investigation.provider_runs:
            self.provider_runs[run.provider] = run
            self._ensure_provider_row(run.provider)

    # ------------------------------------------------------------------
    # Live polling
    # ------------------------------------------------------------------

    def _poll_provider_status(self) -> None:
        """Poll the database for provider status changes."""
        if self._finished or self.investigation is None:
            return
        self._poll_provider_status_worker()

    @work(exclusive=True, thread=False, group="poll")
    async def _poll_provider_status_worker(self) -> None:
        """Worker that refreshes provider statuses from the database."""
        await self._refresh_provider_status()

    async def _refresh_provider_status(self) -> None:
        """Read provider runs from the DB and update the table/progress bar."""
        if self.investigation is None:
            return

        try:
            async with get_database_manager().session() as session:
                run_repo = ProviderRunRepository(session)
                runs = await run_repo.list_by_investigation(self.investigation.id)
        except Exception:
            # Polling must never crash the UI.
            return

        if not runs:
            return

        completed = 0
        for run in runs:
            self.provider_runs[run.provider] = run
            self._ensure_provider_row(run.provider)

            status_text = self._format_status(run.status)
            findings_text = str(run.result_count) if run.result_count else "—"
            duration_text = f"{run.duration_ms}ms" if run.duration_ms else "—"
            self._update_provider_row(
                run.provider, status_text, findings_text, duration_text
            )

            previous = self._last_status.get(run.provider)
            if previous != status_text and run.status != ProviderStatus.PENDING:
                self._log_provider_change(run)

            self._last_status[run.provider] = status_text

            if run.status in _TERMINAL_STATUSES:
                completed += 1

        total = len(runs)
        if total:
            self._set_progress(int((completed / total) * 100))

    def _log_provider_change(self, run: Any) -> None:
        """Write a provider status change to the progress log."""
        name = run.provider.replace("_", " ").title()
        status = self._format_status(run.status)

        if run.status == ProviderStatus.COMPLETED_WITH_FINDINGS:
            detail = f" — {run.result_count} finding(s)"
        elif run.error_message:
            detail = f" — {run.error_message}"
        else:
            detail = ""

        self._log(f"{name}: {status}{detail}")

    def _set_progress(self, value: int) -> None:
        """Safely update the overall progress bar."""
        try:
            progress = self.query_one("#overall-progress", ProgressBar)
            progress.update(progress=value)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Provider table helpers
    # ------------------------------------------------------------------

    def _format_status(self, status: ProviderStatus) -> str:
        """Format provider status for display."""
        status_map = {
            ProviderStatus.PENDING: "⏳ Pending",
            ProviderStatus.RUNNING: "🔄 Running",
            ProviderStatus.COMPLETED_WITH_FINDINGS: "✅ Completed (found)",
            ProviderStatus.COMPLETED_NO_MATCHES: "✅ Completed (none)",
            ProviderStatus.FAILED: "❌ Failed",
            ProviderStatus.UNAUTHORIZED: "🔒 Unauthorized",
            ProviderStatus.RATE_LIMITED: "⏱️ Rate Limited",
            ProviderStatus.UNAVAILABLE: "❌ Unavailable",
            ProviderStatus.TIMEOUT: "⏱️ Timeout",
            ProviderStatus.CONFIGURATION_ERROR: "⚙️ Config Error",
            ProviderStatus.UNSUPPORTED: "⚠️ Unsupported",
            ProviderStatus.PARTIAL: "⚠️ Partial",
        }
        return status_map.get(status, str(status.value))

    def _setup_provider_table(self) -> None:
        """Set up provider status table."""
        table = self.query_one("#provider-table", DataTable)
        table.add_columns(
            ("Provider", "provider"),
            ("Status", "status"),
            ("Findings", "findings"),
            ("Duration", "duration"),
        )
        table.zebra_stripes = True

        # Add rows for each enabled provider in this profile
        enabled = self.config.get_enabled_providers()
        profile_providers = self._get_providers_for_profile(self._profile)

        for provider in profile_providers:
            if provider in enabled:
                self._ensure_provider_row(provider)

    def _ensure_provider_row(self, provider: str) -> None:
        """Add a provider row if it does not exist yet."""
        try:
            table = self.query_one("#provider-table", DataTable)
            table.add_row(
                provider.replace("_", " ").title(),
                "⏳ Pending",
                "—",
                "—",
                key=provider,
            )
        except Exception:
            # Row already exists (or the table is gone); nothing to do.
            pass

    def _get_providers_for_profile(self, profile: Profile) -> list[str]:
        """Get providers for a profile. Must match orchestrator._get_providers_for_profile."""
        mapping = {
            Profile.BREACH: ["hibp", "breachdirectory", "emailrep"],
            Profile.PUBLIC: ["brave_search", "github", "emailrep"],
            Profile.DOMAIN: ["dns", "virustotal"],
            Profile.FULL: [
                "hibp",
                "breachdirectory",
                "emailrep",
                "brave_search",
                "github",
                "virustotal",
                "dns",
            ],
        }
        return mapping.get(profile, [])

    def _update_provider_row(
        self, provider: str, status: str, findings: str, duration: str
    ) -> None:
        """Update a provider row in the table."""
        try:
            table = self.query_one("#provider-table", DataTable)
            table.update_cell(provider, "status", status)
            table.update_cell(provider, "findings", findings)
            table.update_cell(provider, "duration", duration)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Completion / errors / cancellation
    # ------------------------------------------------------------------

    def _investigation_done(self) -> None:
        """Called when the investigation completes."""
        if self._finished:
            return
        self._finished = True

        if self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None

        if not self.is_mounted:
            return

        finding_count = len(self.investigation.findings) if self.investigation else 0
        self._log(
            f"[bold green]Investigation complete![/bold green] "
            f"{finding_count} finding(s)."
        )
        self._set_progress(100)

        try:
            button = self.query_one("#btn-cancel", Button)
            button.label = "View Results"
            button.variant = "primary"
        except Exception:
            pass

    def _investigation_error(self, error: str) -> None:
        """Called when the investigation fails."""
        if self._finished:
            return
        self._finished = True

        if self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None

        if not self.is_mounted:
            return

        self._log(f"[bold red]Investigation failed:[/bold red] {error}")

        try:
            button = self.query_one("#btn-cancel", Button)
            button.label = "Back"
            button.variant = "default"
        except Exception:
            pass

    def _log(self, message: str) -> None:
        """Write a line to the progress log if the screen is still alive."""
        with contextlib.suppress(Exception):
            self.query_one("#progress-log", RichLog).write(message)

    def _cancel_investigation(self) -> None:
        """Stop the running worker and the polling timer."""
        self._cancelled = True
        if self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        with contextlib.suppress(Exception):
            self.workers.cancel_group(self, "investigation")
            self.workers.cancel_group(self, "poll")

    @on(Button.Pressed, "#btn-cancel")
    def on_cancel_pressed(self) -> None:
        if self._finished and self.investigation is not None:
            self.dismiss(self.investigation)
        else:
            self._cancel_investigation()
            if self.investigation:
                self.investigation.status = InvestigationStatus.CANCELLED
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.on_cancel_pressed()
