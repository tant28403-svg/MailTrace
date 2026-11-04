"""History screen for MailTrace TUI."""

from __future__ import annotations

from typing import Any, ClassVar
from uuid import UUID

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Static

from mailtrace.core.configuration import get_config
from mailtrace.schemas.finding import Finding, Investigation, InvestigationSummary
from mailtrace.storage import close_database, get_database_manager, init_database
from mailtrace.storage.repositories import FindingRepository, InvestigationRepository


class HistoryScreen(Screen[Any]):
    """Screen showing investigation history."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "back", "Back"),
        ("enter", "view", "View"),
        ("d", "delete", "Delete"),
        ("c", "compare", "Compare"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.investigations: list[InvestigationSummary] = []
        self.selected_ids: list[str] = []
        self._pending_delete: list[str] = []

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Static("Investigation History", id="screen-title"),
                DataTable(id="history-table", cursor_type="row"),
                Static("Select one to view, two to compare", id="history-hint"),
                Container(
                    Button("Back", id="btn-back", variant="default"),
                    Button("View", id="btn-view", variant="primary", disabled=True),
                    Button("Compare", id="btn-compare", variant="default", disabled=True),
                    Button("Delete", id="btn-delete", variant="error", disabled=True),
                    id="button-row",
                ),
                id="history-content",
            ),
            id="history-container",
        )

    async def on_mount(self) -> None:
        await self._load_history()
        self.query_one("#history-table", DataTable).focus()

    async def _load_history(self) -> None:
        """Load investigation history from the database."""
        table = self.query_one("#history-table", DataTable)
        table.clear(columns=True)
        table.add_columns("Date", "Target", "Profile", "Status", "Findings", "ID")
        table.zebra_stripes = True

        config = get_config()
        await init_database(data_dir=config.general.data_dir)
        try:
            async with get_database_manager().session() as session:
                inv_repo = InvestigationRepository(session)
                finding_repo = FindingRepository(session)
                rows = await inv_repo.list(limit=200)
                self.investigations = []
                for investigation in rows:
                    finding_count = await finding_repo.count_by_investigation(
                        investigation.id
                    )
                    self.investigations.append(
                        InvestigationSummary(
                            id=investigation.id,
                            target_masked=investigation.target_masked,
                            profile=investigation.profile,
                            status=investigation.status,
                            created_at=investigation.created_at,
                            completed_at=investigation.completed_at,
                            finding_count=finding_count,
                            provider_count=len(investigation.provider_runs),
                        )
                    )
        except Exception as exc:
            self.notify(f"Could not load history: {exc}", severity="error")
            return
        finally:
            await close_database()

        for summary in self.investigations:
            table.add_row(
                summary.created_at.strftime("%Y-%m-%d %H:%M"),
                summary.target_masked,
                summary.profile.value,
                summary.status.value,
                str(summary.finding_count),
                str(summary.id)[:8],
                key=str(summary.id),
            )

        self.selected_ids.clear()
        self._update_buttons()

    @on(DataTable.RowSelected, "#history-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Track selected case rows."""
        case_id = str(event.row_key.value)
        if case_id in self.selected_ids:
            self.selected_ids.remove(case_id)
        else:
            self.selected_ids.append(case_id)
        self._pending_delete.clear()
        self._update_buttons()

    def _update_buttons(self) -> None:
        """Enable actions that are valid for the current selection."""
        self.query_one("#btn-view", Button).disabled = len(self.selected_ids) != 1
        self.query_one("#btn-compare", Button).disabled = len(self.selected_ids) != 2
        self.query_one("#btn-delete", Button).disabled = len(self.selected_ids) == 0

    async def _load_case(self, case_id: str) -> Investigation | None:
        """Load a case as a domain schema."""
        config = get_config()
        await init_database(data_dir=config.general.data_dir)
        try:
            async with get_database_manager().session() as session:
                return await InvestigationRepository(session).get_schema(
                    UUID(case_id)
                )
        finally:
            await close_database()

    @on(Button.Pressed, "#btn-back")
    def on_back_pressed(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#btn-view")
    async def on_view_pressed(self) -> None:
        await self._view_selected()

    @on(Button.Pressed, "#btn-compare")
    async def on_compare_pressed(self) -> None:
        await self._compare_selected()

    @on(Button.Pressed, "#btn-delete")
    async def on_delete_pressed(self) -> None:
        await self._delete_selected()

    async def _view_selected(self) -> None:
        if len(self.selected_ids) != 1:
            return
        try:
            investigation = await self._load_case(self.selected_ids[0])
        except Exception as exc:
            self.notify(f"Could not load case: {exc}", severity="error")
            return
        if investigation is None:
            self.notify("Case not found", severity="error")
            await self._load_history()
            return
        self.dismiss(investigation)

    async def _compare_selected(self) -> None:
        if len(self.selected_ids) != 2:
            return
        try:
            first = await self._load_case(self.selected_ids[0])
            second = await self._load_case(self.selected_ids[1])
        except Exception as exc:
            self.notify(f"Could not compare cases: {exc}", severity="error")
            return
        if first is None or second is None:
            self.notify("One or both cases no longer exist", severity="error")
            await self._load_history()
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
        added = len(second_findings - first_findings)
        removed = len(first_findings - second_findings)
        self.notify(
            f"{str(first.id)[:8]} → {str(second.id)[:8]}: "
            f"{len(first.findings)} → {len(second.findings)} findings "
            f"({added} added, {removed} removed)",
            title="Case comparison",
            timeout=10,
        )

    async def _delete_selected(self) -> None:
        if not self.selected_ids:
            return

        # Destructive action: require a second key/button press.
        if self._pending_delete != self.selected_ids:
            self._pending_delete = list(self.selected_ids)
            self.notify(
                f"Press Delete again to permanently delete "
                f"{len(self.selected_ids)} case(s)",
                severity="warning",
            )
            return

        config = get_config()
        await init_database(data_dir=config.general.data_dir)
        deleted = 0
        try:
            async with get_database_manager().session() as session:
                inv_repo = InvestigationRepository(session)
                for case_id in self.selected_ids:
                    if await inv_repo.delete(UUID(case_id)):
                        deleted += 1
        except Exception as exc:
            self.notify(f"Delete failed: {exc}", severity="error")
            return
        finally:
            await close_database()
            self._pending_delete.clear()

        self.notify(f"Deleted {deleted} case(s)", severity="information")
        self.selected_ids.clear()
        await self._load_history()

    def action_back(self) -> None:
        self.dismiss(None)

    async def action_view(self) -> None:
        await self._view_selected()

    async def action_compare(self) -> None:
        await self._compare_selected()

    async def action_delete(self) -> None:
        await self._delete_selected()
