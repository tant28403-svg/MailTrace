"""Provider configuration screen for MailTrace TUI."""

from __future__ import annotations

from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Label, Static

from mailtrace.core.configuration import get_config, reload_config, save_general_settings


class ProviderConfigScreen(Screen[Any]):
    """Screen for enabling or disabling providers.

    Secrets are intentionally not editable here; they belong in environment
    variables or a local ``.env`` file.
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Back"),
        ("s", "save", "Save"),
    ]

    _PROVIDERS: ClassVar[list[tuple[str, str, str]]] = [
        ("hibp", "Have I Been Pwned", "Breach database"),
        ("breachdirectory", "BreachDirectory", "Breach intelligence via RapidAPI"),
        ("emailrep", "emailrep.io", "Email reputation (no key required)"),
        ("github", "GitHub", "Public repository metadata"),
        ("brave_search", "Brave Search", "Public web search"),
        ("virustotal", "VirusTotal", "Domain/URL reputation"),
        ("dns", "DNS", "Domain records (no key needed)"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.config = get_config()

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Static("Provider Configuration", id="screen-title"),
                Static(
                    "Enable or disable providers. API keys and tokens are read "
                    "from environment variables or .env and cannot be changed here.",
                    id="instruction",
                ),
                VerticalScroll(
                    *[
                        self._build_provider_section(key, name, description)
                        for key, name, description in self._PROVIDERS
                    ],
                    id="provider-list",
                ),
                Container(
                    Button("Cancel", id="btn-cancel", variant="default"),
                    Button("Save", id="btn-save", variant="primary"),
                    id="button-row",
                ),
                id="provider-content",
            ),
            id="provider-container",
        )

    def _build_provider_section(
        self, key: str, name: str, description: str
    ) -> Container:
        provider_config = getattr(self.config, key)
        api_key = getattr(provider_config, "api_key", None) or getattr(
            provider_config, "token", None
        )
        if key in {"dns", "emailrep"}:
            credential_status = "No API key required"
        else:
            credential_status = "Key configured" if api_key else "Key not configured"

        return Container(
            Static(name, classes="provider-name"),
            Static(description, classes="provider-desc"),
            Horizontal(
                Checkbox(
                    "Enabled",
                    value=provider_config.enabled,
                    id=f"{key}-enabled",
                ),
                Label(credential_status),
                id=f"{key}-row1",
            ),
            classes="provider-section",
            id=f"{key}-section",
        )

    @on(Button.Pressed, "#btn-save")
    def on_save_pressed(self) -> None:
        """Persist provider enable/disable switches."""
        updates = {
            f"{key}_enabled": self.query_one(f"#{key}-enabled", Checkbox).value
            for key, _, _ in self._PROVIDERS
        }
        try:
            path = save_general_settings(updates)
            reload_config()
        except (OSError, ValueError) as exc:
            self.notify(f"Could not save provider settings: {exc}", severity="error")
            return

        self.notify(f"Provider settings saved to {path}", severity="information")
        self.dismiss(True)

    @on(Button.Pressed, "#btn-cancel")
    def on_cancel_pressed(self) -> None:
        self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)

    def action_save(self) -> None:
        self.on_save_pressed()
