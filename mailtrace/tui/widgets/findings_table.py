"""Findings table widget for MailTrace TUI."""

from typing import Any

from textual.widgets import DataTable

from mailtrace.schemas.finding import Investigation, Severity


class FindingsTable(DataTable[Any]):
    """Table widget for displaying findings."""

    def __init__(self, investigation: Investigation, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.investigation = investigation
        self.cursor_type = "row"
        self.zebra_stripes = True

    def on_mount(self) -> None:
        """Initialize table."""
        self.add_columns(
            "Type",
            "Title",
            "Service",
            "Domain",
            "Severity",
            "Confidence",
            "Verified",
            "ID",  # Hidden, used for selection
        )
        self._populate()

    def _populate(self) -> None:
        """Populate table with findings."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }

        sorted_findings = sorted(
            self.investigation.findings,
            key=lambda f: severity_order.get(f.severity, 5),
        )

        for finding in sorted_findings:
            self.add_row(
                finding.finding_type.value.replace("_", " ").title(),
                finding.title[:60] + ("..." if len(finding.title) > 60 else ""),
                finding.service_name or "—",
                finding.domain or "—",
                self._severity_cell(finding.severity),
                finding.confidence.value.title(),
                "✅" if finding.verification_status.value == "verified" else "⏳",
                str(finding.id),
                key=str(finding.id),
            )

    def _severity_cell(self, severity: Severity) -> str:
        """Format severity cell with color."""
        icons = {
            Severity.CRITICAL: "🔴 Critical",
            Severity.HIGH: "🟠 High",
            Severity.MEDIUM: "🟡 Medium",
            Severity.LOW: "🟢 Low",
            Severity.INFORMATIONAL: "🔵 Info",
        }
        return icons.get(severity, severity.value)
