"""Setup-required screen shown when no provider API keys are configured."""

from __future__ import annotations

from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, Static

from mailtrace.core.configuration import (
    SETTINGS_ENV_FILE,
    get_config,
    iter_configured_keys,
)


class SetupRequiredScreen(Screen[Any]):
    """Explain the bring-your-own-keys requirement before a scan can start."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "back", "Back"),
        ("r", "recheck", "Recheck Keys"),
    ]

    def compose(self) -> ComposeResult:
        statuses = iter_configured_keys(get_config())
        lines = [
            "No API keys configured.",
            "",
            "MailTrace requires you to use your own provider keys. Scans are",
            "disabled until at least one key-requiring provider is configured,",
            "so a shared project can never spend someone else's quota.",
            "",
            "Provider status:",
        ]
        for status in statuses:
            if not status.requires_key:
                state = "ready (no key required)" if status.enabled else "disabled"
                lines.append(f"  {status.label}: {state}")
                continue
            if status.configured:
                state = "ready" if status.enabled else "key set (provider disabled)"
            elif status.source == "project .env (ignored)":
                state = "ignored project key - move it to your user config"
            else:
                state = "missing key"
            fingerprint = f" [{status.fingerprint}]" if status.fingerprint else ""
            lines.append(f"  {status.label}: {state}{fingerprint}")

        lines.extend(
            [
                "",
                f"Add your keys to: {SETTINGS_ENV_FILE}",
                "Or run: mailtrace config keys migrate",
                "",
                'See README "Bring your own API keys" for details.',
            ]
        )

        yield Container(
            Vertical(
                Static("Setup Required", id="screen-title"),
                Static("\n".join(lines), id="setup-details"),
                Container(
                    Button("Recheck Keys", id="btn-recheck", variant="primary"),
                    Button("Back", id="btn-back", variant="default"),
                    id="button-row",
                ),
                id="setup-content",
            ),
            id="setup-container",
        )

    @on(Button.Pressed, "#btn-recheck")
    def on_recheck_pressed(self) -> None:
        self.dismiss("retry")

    @on(Button.Pressed, "#btn-back")
    def on_back_pressed(self) -> None:
        self.dismiss(None)

    def action_back(self) -> None:
        self.dismiss(None)

    def action_recheck(self) -> None:
        self.dismiss("retry")
