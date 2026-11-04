"""Evidence panel widget for MailTrace TUI."""

from typing import Any

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.widgets import DataTable, Static, TabbedContent, TabPane

from mailtrace.schemas.finding import Finding, Investigation


class EvidencePanel(Container):
    """Panel showing evidence for selected finding."""

    def __init__(self, investigation: Investigation, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.investigation = investigation
        self.current_finding: Finding | None = None

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Select a finding to view evidence", id="evidence-placeholder"),
            TabbedContent(id="evidence-tabs"),
            id="evidence-content",
        )

    async def on_mount(self) -> None:
        """Add tab panes now that the TabbedContent is mounted."""
        tabs = self.query_one("#evidence-tabs", TabbedContent)
        await tabs.add_pane(
            TabPane(
                "Evidence Records",
                DataTable(id="evidence-table", cursor_type="row"),
                id="tab-evidence-records",
            )
        )
        await tabs.add_pane(
            TabPane(
                "Details",
                Static("", id="evidence-details"),
                id="tab-evidence-details",
            )
        )
        tabs.active = "tab-evidence-records"

    def show_finding(self, finding_id: str) -> None:
        """Show evidence for a finding."""
        # Find the finding
        finding = None
        for f in self.investigation.findings:
            if str(f.id) == finding_id:
                finding = f
                break

        if not finding:
            return

        self.current_finding = finding
        placeholder = self.query_one("#evidence-placeholder", Static)
        placeholder.display = False

        # Update evidence table
        table = self.query_one("#evidence-table", DataTable)
        table.clear(columns=True)
        table.add_columns("Provider", "Type", "Status", "Source", "Collected", "Verified", "Hash")
        table.zebra_stripes = True

        for evidence in finding.evidence:
            table.add_row(
                evidence.provider,
                evidence.evidence_type.value.replace("_", " ").title(),
                evidence.verification_status.value.title(),
                evidence.source_reference or (str(evidence.source_url) if evidence.source_url else "—"),
                evidence.collected_at.strftime("%Y-%m-%d %H:%M:%S"),
                evidence.verified_at.strftime("%Y-%m-%d %H:%M:%S") if evidence.verified_at else "—",
                evidence.evidence_hash[:16] + "..." if evidence.evidence_hash else "—",
            )

        # Update details
        details = self.query_one("#evidence-details", Static)
        details.update(self._build_details(finding))

    def _build_details(self, finding: Finding) -> str:
        """Build finding details markdown."""
        md = f"""
# Finding Details

**ID:** {finding.id}
**Type:** {finding.finding_type.value.replace('_', ' ').title()}
**Title:** {finding.title}
**Service:** {finding.service_name or 'N/A'}
**Domain:** {finding.domain or 'N/A'}
**Severity:** {finding.severity.value.title()}
**Confidence:** {finding.confidence.value.title()}
**Verification:** {finding.verification_status.value.title()}
**First Observed:** {finding.first_observed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if finding.first_observed_at else 'N/A'}
**Collected:** {finding.collected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}

## Evidence Records ({len(finding.evidence)})
"""
        for i, evidence in enumerate(finding.evidence, 1):
            md += f"""
### Evidence {i}
- **Provider:** {evidence.provider}
- **Type:** {evidence.evidence_type.value.replace('_', ' ').title()}
- **Status:** {evidence.verification_status.value.title()}
- **Source URL:** {evidence.source_url or 'N/A'}
- **Source Ref:** {evidence.source_reference or 'N/A'}
- **Collected:** {evidence.collected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Verified:** {evidence.verified_at.strftime('%Y-%m-%d %H:%M:%S UTC') if evidence.verified_at else 'Not verified'}
- **Hash:** {evidence.evidence_hash or 'N/A'}
- **Notes:** {evidence.notes or 'None'}
"""
        return md
