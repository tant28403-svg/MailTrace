"""Export screen for MailTrace TUI."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Select, Static

from mailtrace.core.configuration import get_config
from mailtrace.reporting import ReportGenerator
from mailtrace.schemas.finding import ExportFormat, Investigation, ReportOptions


class ExportScreen(Screen[Any]):
    """Choose an export format and destination for a completed case."""

    BINDINGS: ClassVar[list[BindingType]] = [("escape", "cancel", "Cancel")]

    def __init__(self, investigation: Investigation) -> None:
        super().__init__()
        self.investigation = investigation
        self.config = get_config()

    def _default_path(self, export_format: ExportFormat) -> Path:
        exports_dir = self.config.general.data_dir / "exports"
        return exports_dir / f"mailtrace-{str(self.investigation.id)[:8]}.{export_format.value}"

    def compose(self) -> ComposeResult:
        default = self._default_path(ExportFormat.JSON)
        yield Container(
            Vertical(
                Static("Export Investigation", id="screen-title"),
                Static(
                    "Choose a format and destination. The target address remains "
                    "masked unless masking is disabled in settings.",
                    id="instruction",
                ),
                Horizontal(
                    Label("Format:", classes="setting-label"),
                    Select(
                        [
                            ("JSON", ExportFormat.JSON.value),
                            ("CSV", ExportFormat.CSV.value),
                            ("PDF", ExportFormat.PDF.value),
                        ],
                        value=ExportFormat.JSON.value,
                        id="export-format",
                        allow_blank=False,
                    ),
                    id="export-format-row",
                ),
                Horizontal(
                    Label("Destination:", classes="setting-label"),
                    Input(value=str(default), id="export-path"),
                    id="export-path-row",
                ),
                Container(
                    Button("Cancel", id="btn-cancel", variant="default"),
                    Button("Export", id="btn-export", variant="primary"),
                    id="button-row",
                ),
                id="export-content",
            ),
            id="export-container",
        )

    @on(Select.Changed, "#export-format")
    def on_format_changed(self, event: Select.Changed) -> None:
        """Keep the destination extension in sync with the format."""
        if not isinstance(event.value, str):
            return
        try:
            export_format = ExportFormat(event.value)
        except ValueError:
            return
        path_input = self.query_one("#export-path", Input)
        current = Path(path_input.value).expanduser()
        path_input.value = str(current.with_suffix(f".{export_format.value}"))

    @on(Button.Pressed, "#btn-export")
    def on_export_pressed(self) -> None:
        """Generate the selected report."""
        value = self.query_one("#export-format", Select).value
        if not isinstance(value, str):
            self.notify("Select an export format", severity="error")
            return
        export_format = ExportFormat(value)

        raw_path = self.query_one("#export-path", Input).value.strip()
        if not raw_path:
            self.notify("Enter an output path", severity="error")
            return
        output = Path(raw_path).expanduser()
        if output.suffix.lower() != f".{export_format.value}":
            output = output.with_suffix(f".{export_format.value}")

        options = ReportOptions(
            format=export_format,
            output_path=str(output),
            include_evidence=True,
            mask_target=self.config.general.mask_output,
        )

        try:
            content = ReportGenerator(self.investigation).generate(options)
            output.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                output.write_bytes(content)
            else:
                output.write_text(content, encoding="utf-8")
        except (OSError, RuntimeError, ValueError) as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            return

        self.notify(f"Exported to {output}", severity="information")
        self.dismiss(str(output))

    @on(Button.Pressed, "#btn-cancel")
    def on_cancel_pressed(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
