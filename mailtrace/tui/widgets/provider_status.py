"""Provider status bar widget for MailTrace TUI."""

from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from mailtrace.schemas.finding import ProviderRun, ProviderStatus


class ProviderStatusBar(Horizontal):
    """Horizontal bar showing provider statuses."""

    def __init__(self, provider_runs: list[ProviderRun], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.provider_runs = provider_runs

    def compose(self) -> ComposeResult:
        for run in self.provider_runs:
            yield self._create_provider_badge(run)

    def _create_provider_badge(self, run: ProviderRun) -> Static:
        """Create a status badge for a provider."""
        status_colors = {
            ProviderStatus.COMPLETED_WITH_FINDINGS: "success",
            ProviderStatus.COMPLETED_NO_MATCHES: "success",
            ProviderStatus.UNAUTHORIZED: "error",
            ProviderStatus.RATE_LIMITED: "warning",
            ProviderStatus.UNAVAILABLE: "error",
            ProviderStatus.TIMEOUT: "warning",
            ProviderStatus.UNSUPPORTED: "warning",
            ProviderStatus.CONFIGURATION_ERROR: "error",
            ProviderStatus.PARTIAL: "warning",
            ProviderStatus.FAILED: "error",
            ProviderStatus.PENDING: "default",
            ProviderStatus.RUNNING: "primary",
        }

        status_icons = {
            ProviderStatus.COMPLETED_WITH_FINDINGS: "✅",
            ProviderStatus.COMPLETED_NO_MATCHES: "✅",
            ProviderStatus.UNAUTHORIZED: "🔒",
            ProviderStatus.RATE_LIMITED: "⏱️",
            ProviderStatus.UNAVAILABLE: "❌",
            ProviderStatus.TIMEOUT: "⏱️",
            ProviderStatus.UNSUPPORTED: "⚠️",
            ProviderStatus.CONFIGURATION_ERROR: "⚙️",
            ProviderStatus.PARTIAL: "⚠️",
            ProviderStatus.FAILED: "❌",
            ProviderStatus.PENDING: "⏳",
            ProviderStatus.RUNNING: "🔄",
        }

        color = status_colors.get(run.status, "default")
        icon = status_icons.get(run.status, "❓")

        badge = Static(
            f"{icon} {run.provider.replace('_', ' ').title()}: {run.status.value.replace('_', ' ').title()}",
            classes=f"provider-badge {color}",
        )
        return badge
