"""MailTrace TUI widgets package."""

from mailtrace.tui.widgets.evidence_panel import EvidencePanel
from mailtrace.tui.widgets.findings_table import FindingsTable
from mailtrace.tui.widgets.provider_status import ProviderStatusBar

__all__ = [
    "EvidencePanel",
    "FindingsTable",
    "ProviderStatusBar",
]
