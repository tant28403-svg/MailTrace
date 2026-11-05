"""Main Textual TUI application for MailTrace."""

from typing import Any, ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Container
from textual.widgets import Footer, Header

from mailtrace.core.configuration import (
    get_config,
    project_env_warning,
    reload_config,
)
from mailtrace.schemas.finding import Investigation, Profile
from mailtrace.tui.screens.auth_confirm import AuthConfirmScreen
from mailtrace.tui.screens.email_input import EmailInputScreen
from mailtrace.tui.screens.export import ExportScreen
from mailtrace.tui.screens.help import HelpScreen
from mailtrace.tui.screens.history import HistoryScreen
from mailtrace.tui.screens.live_progress import LiveProgressScreen
from mailtrace.tui.screens.profile_select import ProfileSelectScreen
from mailtrace.tui.screens.results import ResultsScreen
from mailtrace.tui.screens.settings import SettingsScreen
from mailtrace.tui.screens.setup_required import SetupRequiredScreen
from mailtrace.tui.screens.welcome import WelcomeScreen


class MailTraceApp(App[Any]):
    """Main MailTrace TUI application."""

    CSS_PATH = "css/app.tcss"
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "Quit", show=True),
        Binding("?", "help", "Help", show=True),
        Binding("ctrl+c", "cancel", "Cancel", show=False),
        Binding("f1", "help", "Help", show=False),
        Binding("f2", "new_investigation", "New", show=True),
        Binding("f3", "history", "History", show=True),
        Binding("f4", "settings", "Settings", show=True),
        Binding("f5", "export", "Export", show=True),
        Binding("escape", "back", "Back", show=True),
    ]

    TITLE = "MailTrace"
    SUB_TITLE = "Email Exposure Intelligence"

    def __init__(self) -> None:
        super().__init__()
        self.config = get_config()
        self.current_investigation: Investigation | None = None
        self.current_email: str | None = None
        self.current_profile: Profile = Profile.FULL

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Footer()
        yield Container(id="main-container")

    def on_mount(self) -> None:
        """Initialize the app and show the welcome screen."""
        warning = project_env_warning()
        if warning:
            self.notify(warning, severity="warning", timeout=12)
        self.push_screen(WelcomeScreen(), callback=self._on_welcome_done)

    def _open_new_investigation(self) -> None:
        """Open the email flow, or the setup screen when keys are missing."""
        if not self.config.require_keys_satisfied():
            self.push_screen(SetupRequiredScreen(), callback=self._on_setup_done)
            return
        self.push_screen(EmailInputScreen(), callback=self._on_email_entered)

    def _on_setup_done(self, result: str | None) -> None:
        self.config = reload_config()
        if result == "retry" and self.config.require_keys_satisfied():
            self.push_screen(EmailInputScreen(), callback=self._on_email_entered)
            return
        if result == "retry":
            self.notify(
                "No API keys detected yet. Add a key and try again.",
                severity="warning",
            )
        self.push_screen(WelcomeScreen(), callback=self._on_welcome_done)

    def _on_welcome_done(self, result: str | None) -> None:
        if result == "new":
            self._open_new_investigation()
        elif result == "history":
            self.push_screen(HistoryScreen(), callback=self._on_history_done)
        elif result == "settings":
            self.push_screen(SettingsScreen(), callback=self._on_settings_done)

    def _on_email_entered(self, email: str | None) -> None:
        if email:
            self.current_email = email
            self.push_screen(
                ProfileSelectScreen(default_profile=self.current_profile),
                callback=self._on_profile_selected,
            )

    def _on_profile_selected(self, profile: Profile | None) -> None:
        if profile:
            self.current_profile = profile
            enabled = self.config.get_enabled_providers()
            if enabled and self.config.general.confirm_external:
                self.push_screen(
                    AuthConfirmScreen(providers=enabled, email=self.current_email or ""),
                    callback=self._on_auth_confirmed,
                )
            else:
                self._start_investigation()

    def _on_auth_confirmed(self, confirmed: Any | None) -> None:
        if confirmed:
            self._start_investigation()
        else:
            self.notify(
                "Investigation cancelled - authorization not confirmed",
                severity="warning",
            )
            self._open_new_investigation()

    def _start_investigation(self) -> None:
        if not self.config.require_keys_satisfied():
            self.push_screen(SetupRequiredScreen(), callback=self._on_setup_done)
            return
        progress_screen = LiveProgressScreen(
            email=self.current_email or "", profile=self.current_profile
        )
        self.push_screen(
            progress_screen,
            callback=self._on_investigation_complete,
        )

    def _on_investigation_complete(self, investigation: Investigation | None) -> None:
        if investigation:
            self.current_investigation = investigation
            self.push_screen(
                ResultsScreen(investigation=investigation),
                callback=self._on_results_done,
            )
        else:
            self.notify("Investigation failed or cancelled", severity="error")
            self._open_new_investigation()

    def _on_results_done(self, action: str | None) -> None:
        if action == "new":
            self._open_new_investigation()
        elif action == "history":
            self.push_screen(HistoryScreen(), callback=self._on_history_done)

    def _on_history_done(self, investigation: Investigation | None) -> None:
        if investigation:
            self.current_investigation = investigation
            self.push_screen(
                ResultsScreen(investigation=investigation),
                callback=self._on_results_done,
            )
        else:
            self.push_screen(WelcomeScreen(), callback=self._on_welcome_done)

    def _on_settings_done(self, _: bool | None) -> None:
        self.config = reload_config()
        self.push_screen(WelcomeScreen(), callback=self._on_welcome_done)

    # Action handlers
    async def action_quit(self) -> None:
        self.exit()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_cancel(self) -> None:
        if len(self.screen_stack) > 1:
            self.pop_screen()
        else:
            self.notify("Nothing to cancel", severity="warning")

    def action_new_investigation(self) -> None:
        self._open_new_investigation()

    def action_history(self) -> None:
        self.push_screen(HistoryScreen(), callback=self._on_history_done)

    def action_settings(self) -> None:
        self.push_screen(SettingsScreen(), callback=self._on_settings_done)

    def action_export(self) -> None:
        if self.current_investigation:
            self.push_screen(ExportScreen(self.current_investigation))
        else:
            self.notify("No active investigation to export", severity="warning")

    async def action_back(self) -> None:
        if len(self.screen_stack) > 1:
            self.pop_screen()
