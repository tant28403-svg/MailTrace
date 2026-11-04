"""Settings screen for MailTrace TUI."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Select, Static, Switch

from mailtrace.core.configuration import get_config, reload_config, save_general_settings


class SettingsScreen(Screen[Any]):
    """Settings screen for non-secret application preferences."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "back", "Back"),
        ("s", "save", "Save"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.config = get_config()

    def compose(self) -> ComposeResult:
        config = self.config
        yield Container(
            Vertical(
                Static("Settings", id="screen-title"),
                VerticalScroll(
                    Static("General", classes="section-title"),
                    Horizontal(
                        Label("Mask email in output:", classes="setting-label"),
                        Switch(value=config.general.mask_output, id="mask-output"),
                        id="mask-row",
                    ),
                    Horizontal(
                        Label("Confirm before external calls:", classes="setting-label"),
                        Switch(
                            value=config.general.confirm_external,
                            id="confirm-external",
                        ),
                        id="confirm-row",
                    ),
                    Horizontal(
                        Label("Log level:", classes="setting-label"),
                        Select(
                            [
                                ("DEBUG", "DEBUG"),
                                ("INFO", "INFO"),
                                ("WARNING", "WARNING"),
                                ("ERROR", "ERROR"),
                            ],
                            value=config.general.log_level,
                            id="log-level",
                            allow_blank=False,
                        ),
                        id="log-level-row",
                    ),
                    Horizontal(
                        Label("Theme:", classes="setting-label"),
                        Select(
                            [
                                ("Dark", "dark"),
                                ("Light", "light"),
                                ("System", "system"),
                            ],
                            value=config.general.theme,
                            id="theme",
                            allow_blank=False,
                        ),
                        id="theme-row",
                    ),
                    Horizontal(
                        Label("Data directory:", classes="setting-label"),
                        Input(
                            value=str(config.general.data_dir),
                            id="data-dir",
                        ),
                        id="data-dir-row",
                    ),
                    Static("Providers", classes="section-title"),
                    Static(
                        "API keys and tokens are secrets: set them with environment "
                        "variables or a .env file. Only enable/disable switches are "
                        "saved here.",
                        classes="setting-hint",
                    ),
                    self._provider_row("HIBP", "hibp", config.hibp.enabled),
                    self._provider_row(
                        "BreachDirectory",
                        "breachdirectory",
                        config.breachdirectory.enabled,
                    ),
                    self._provider_row(
                        "emailrep.io", "emailrep", config.emailrep.enabled
                    ),
                    self._provider_row("GitHub", "github", config.github.enabled),
                    self._provider_row(
                        "Brave Search", "brave_search", config.brave_search.enabled
                    ),
                    self._provider_row(
                        "VirusTotal", "virustotal", config.virustotal.enabled
                    ),
                    self._provider_row("DNS", "dns", config.dns.enabled),
                    id="settings-scroll",
                ),
                Container(
                    Button("Cancel", id="btn-cancel", variant="default"),
                    Button("Save", id="btn-save", variant="primary"),
                    id="button-row",
                ),
                id="settings-content",
            ),
            id="settings-container",
        )

    def _provider_row(self, label: str, key: str, enabled: bool) -> Horizontal:
        return Horizontal(
            Label(label, classes="setting-label"),
            Switch(value=enabled, id=f"{key}-enabled"),
            id=f"{key}-row",
        )

    def _selected_value(self, select_id: str) -> str:
        value = self.query_one(select_id, Select).value
        return value if isinstance(value, str) else ""

    @on(Button.Pressed, "#btn-save")
    def on_save_pressed(self) -> None:
        """Persist non-secret settings and reload configuration."""
        data_dir = self.query_one("#data-dir", Input).value.strip()
        if not data_dir:
            self.notify("Data directory cannot be empty", severity="error")
            return

        try:
            Path(data_dir).expanduser().mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.notify(f"Data directory is not writable: {exc}", severity="error")
            return

        updates: dict[str, object] = {
            "data_dir": data_dir,
            "mask_output": self.query_one("#mask-output", Switch).value,
            "confirm_external": self.query_one("#confirm-external", Switch).value,
            "log_level": self._selected_value("#log-level"),
            "theme": self._selected_value("#theme"),
            "hibp_enabled": self.query_one("#hibp-enabled", Switch).value,
            "breachdirectory_enabled": self.query_one(
                "#breachdirectory-enabled", Switch
            ).value,
            "emailrep_enabled": self.query_one("#emailrep-enabled", Switch).value,
            "github_enabled": self.query_one("#github-enabled", Switch).value,
            "brave_search_enabled": self.query_one(
                "#brave_search-enabled", Switch
            ).value,
            "virustotal_enabled": self.query_one("#virustotal-enabled", Switch).value,
            "dns_enabled": self.query_one("#dns-enabled", Switch).value,
        }

        try:
            path = save_general_settings(updates)
            reload_config()
        except (OSError, ValueError) as exc:
            self.notify(f"Could not save settings: {exc}", severity="error")
            return

        self.notify(f"Settings saved to {path}", severity="information")
        self.dismiss(True)

    @on(Button.Pressed, "#btn-cancel")
    def on_cancel_pressed(self) -> None:
        self.dismiss(False)

    def action_back(self) -> None:
        self.dismiss(False)

    def action_save(self) -> None:
        self.on_save_pressed()
