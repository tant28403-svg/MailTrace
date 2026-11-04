"""Results screen for MailTrace TUI."""

from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Static, TabbedContent, TabPane

from mailtrace.schemas.finding import Investigation, ProviderStatus
from mailtrace.tui.screens.export import ExportScreen
from mailtrace.tui.widgets.evidence_panel import EvidencePanel
from mailtrace.tui.widgets.findings_table import FindingsTable


class ResultsScreen(Screen[Any]):
    """Screen showing investigation results."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "back", "Back"),
        ("n", "new", "New Investigation"),
        ("e", "export", "Export"),
        ("h", "history", "History"),
    ]

    def __init__(self, investigation: Investigation):
        super().__init__()
        self.investigation = investigation
        self.selected_finding = None

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Horizontal(
                    Static(f"Results: {self.investigation.target_masked}", id="results-title"),
                    Static(f"Profile: {self.investigation.profile.value} • {len(self.investigation.findings)} findings", id="results-summary"),
                    id="results-header",
                ),
                TabbedContent(id="results-tabs"),
                Container(
                    Button("New Investigation", id="btn-new", variant="default"),
                    Button("Export", id="btn-export", variant="primary"),
                    Button("History", id="btn-history", variant="default"),
                    id="button-row",
                ),
                id="results-content",
            ),
            id="results-container",
        )

    async def on_mount(self) -> None:
        """Add tab panes now that the TabbedContent is mounted."""
        tabs = self.query_one("#results-tabs", TabbedContent)

        await tabs.add_pane(
            TabPane(
                "Findings",
                FindingsTable(investigation=self.investigation, id="findings-table"),
                id="tab-findings",
            )
        )
        await tabs.add_pane(
            TabPane(
                "Evidence",
                EvidencePanel(investigation=self.investigation, id="evidence-panel"),
                id="tab-evidence",
            )
        )
        await tabs.add_pane(
            TabPane(
                "Providers",
                self._build_provider_table(),
                id="tab-providers",
            )
        )
        await tabs.add_pane(
            TabPane(
                "Summary",
                self._build_summary(),
                id="tab-summary",
            )
        )

        tabs.active = "tab-findings"

    def _build_provider_table(self) -> DataTable[Any]:
        """Build provider status table."""
        table: DataTable[Any] = DataTable(
            id="provider-summary-table", cursor_type="row"
        )
        table.add_columns("Provider", "Status", "Findings", "Duration")
        table.zebra_stripes = True

        for run in self.investigation.provider_runs:
            status_icon = self._get_status_icon(run.status)
            table.add_row(
                run.provider.replace("_", " ").title(),
                f"{status_icon} {run.status.value}",
                str(run.result_count),
                f"{run.duration_ms}ms" if run.duration_ms else "—",
                key=str(run.id),
            )
        return table

    def _get_status_icon(self, status: ProviderStatus) -> str:
        """Get icon for provider status."""
        icons = {
            "completed_with_findings": "✅",
            "completed_no_matches": "✅",
            "unauthorized": "🔒",
            "rate_limited": "⏱️",
            "unavailable": "❌",
            "timeout": "⏱️",
            "unsupported": "⚠️",
            "configuration_error": "⚙️",
            "partial": "⚠️",
            "failed": "❌",
            "pending": "⏳",
            "running": "🔄",
        }
        return icons.get(status.value, "❓")

    def _build_summary(self) -> Static:
        """Build investigation summary."""
        severity_counts: dict[str, int] = {}
        confidence_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}

        for finding in self.investigation.findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            confidence_counts[finding.confidence.value] = confidence_counts.get(finding.confidence.value, 0) + 1
            type_counts[finding.finding_type.value] = type_counts.get(finding.finding_type.value, 0) + 1

        summary = f"""
# Investigation Summary

**Target:** {self.investigation.target_masked}
**Profile:** {self.investigation.profile.value}
**Status:** {self.investigation.status.value}
**Created:** {self.investigation.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
**Completed:** {self.investigation.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.investigation.completed_at else 'N/A'}

## Findings by Severity
"""
        for sev, count in sorted(severity_counts.items()):
            summary += f"- {sev.title()}: {count}\n"

        summary += "\n## Findings by Confidence\n"
        for conf, count in sorted(confidence_counts.items()):
            summary += f"- {conf.title()}: {count}\n"

        summary += "\n## Findings by Type\n"
        for ftype, count in sorted(type_counts.items()):
            summary += f"- {ftype.replace('_', ' ').title()}: {count}\n"

        summary += f"\n## Providers Run ({len(self.investigation.provider_runs)})\n"
        for run in self.investigation.provider_runs:
            summary += f"- {run.provider}: {run.status.value} ({run.result_count} findings)\n"

        return Static(summary, id="summary-content")

    @on(DataTable.RowSelected, "#findings-table")
    def on_finding_selected(self, event: DataTable.RowSelected) -> None:
        """Handle finding selection."""
        table = event.data_table
        row_key = event.row_key
        if row_key:
            finding_id = table.get_row(row_key)[-1]  # Last column is finding ID
            self.selected_finding = finding_id
            # Update evidence panel
            evidence_panel = self.query_one("#evidence-panel", EvidencePanel)
            evidence_panel.show_finding(finding_id)

    @on(Button.Pressed, "#btn-new")
    def on_new_pressed(self) -> None:
        self.dismiss("new")

    @on(Button.Pressed, "#btn-export")
    def on_export_pressed(self) -> None:
        self.app.push_screen(ExportScreen(self.investigation))

    @on(Button.Pressed, "#btn-history")
    def on_history_pressed(self) -> None:
        self.dismiss("history")

    def action_back(self) -> None:
        self.dismiss(None)

    def action_new(self) -> None:
        self.dismiss("new")

    def action_export(self) -> None:
        self.app.push_screen(ExportScreen(self.investigation))

    def action_history(self) -> None:
        self.dismiss("history")
