"""Welcome screen for MailTrace TUI."""

from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, Markdown, Static

from mailtrace.tui.screens.help import HelpScreen


class WelcomeScreen(Screen[Any]):
    """Welcome/landing screen."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("n", "new", "New Investigation"),
        ("h", "history", "History"),
        ("s", "settings", "Settings"),
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Static(
                    r"""
███╗   ███╗ ██████╗ ██████╗ ███████╗███████╗███████╗
████╗ ████║██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
██╔████╔██║██║   ██║██████╔╝███████╗█████╗  ███████╗
██║╚██╔╝██║██║   ██║██╔══██╗╚════██║██╔══╝  ╚════██║
██║ ╚═╝ ██║╚██████╔╝██║  ██║███████║███████╗███████║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                    """,
                    id="logo",
                ),
                Static("Email Exposure Intelligence", id="tagline"),
                Markdown(
                    """
**MailTrace** investigates the digital footprint of an email address across:
- Known breach databases (HIBP)
- Public search indexes (Brave, GitHub)
- Domain intelligence (DNS, MX, SPF, DMARC)
                    """,
                    id="description",
                ),
                Container(
                    Button("🔍 New Investigation", id="btn-new", variant="primary"),
                    Button("📜 History", id="btn-history"),
                    Button("⚙️ Settings", id="btn-settings"),
                    Button("❓ Help", id="btn-help"),
                    id="button-row",
                ),
                id="welcome-content",
            ),
            id="welcome-container",
        )

    @on(Button.Pressed, "#btn-new")
    def on_new_pressed(self) -> None:
        self.dismiss("new")

    @on(Button.Pressed, "#btn-history")
    def on_history_pressed(self) -> None:
        self.dismiss("history")

    @on(Button.Pressed, "#btn-settings")
    def on_settings_pressed(self) -> None:
        self.dismiss("settings")

    @on(Button.Pressed, "#btn-help")
    def on_help_pressed(self) -> None:
        self.app.push_screen(HelpScreen())

    def action_new(self) -> None:
        self.dismiss("new")

    def action_history(self) -> None:
        self.dismiss("history")

    def action_settings(self) -> None:
        self.dismiss("settings")

    def action_quit(self) -> None:
        self.app.exit()
