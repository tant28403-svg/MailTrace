"""Profile selection screen for MailTrace TUI."""

from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, RadioButton, RadioSet, Static

from mailtrace.schemas.finding import Profile


class ProfileSelectScreen(Screen[Any]):
    """Screen for selecting investigation profile."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Back"),
        ("enter", "submit", "Continue"),
    ]

    def __init__(self, default_profile: Profile = Profile.FULL):
        super().__init__()
        self.default_profile = default_profile

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Static("Select Investigation Profile", id="screen-title"),
                Static(
                    "Choose which checks to run. Each profile enables different providers.",
                    id="instruction",
                ),
                RadioSet(
                    RadioButton(
                        "🔴 Full — Breach + Public + Domain + Repository",
                        id="profile-full",
                        value=self.default_profile == Profile.FULL,
                    ),
                    RadioButton(
                        "🟠 Breach — Known breach databases only (HIBP)",
                        id="profile-breach",
                        value=self.default_profile == Profile.BREACH,
                    ),
                    RadioButton(
                        "🟡 Public — Public search indexes + GitHub",
                        id="profile-public",
                        value=self.default_profile == Profile.PUBLIC,
                    ),
                    RadioButton(
                        "🟢 Domain — DNS, MX, SPF, DMARC only",
                        id="profile-domain",
                        value=self.default_profile == Profile.DOMAIN,
                    ),
                    id="profile-radio",
                ),
                Static("", id="profile-description"),
                Container(
                    Button("Back", id="btn-back", variant="default"),
                    Button("Continue", id="btn-continue", variant="primary"),
                    id="button-row",
                ),
                id="profile-content",
            ),
            id="profile-container",
        )

    def on_mount(self) -> None:
        self._update_description()
        self.query_one("#profile-radio", RadioSet).focus()

    @on(RadioSet.Changed, "#profile-radio")
    def on_profile_changed(self, event: RadioSet.Changed) -> None:
        self._update_description()

    def _update_description(self) -> None:
        """Update profile description based on selection."""
        radio_set = self.query_one("#profile-radio", RadioSet)
        button = radio_set.pressed_button
        pressed_id = (button.id if button and button.id else "profile-full")
        descriptions = {
            "profile-full": "All enabled providers: breach databases, public search, GitHub, DNS and reputation",
            "profile-breach": "HIBP, BreachDirectory and emailrep.io. Requires configured keys where applicable.",
            "profile-public": "Brave Search, GitHub and emailrep.io public metadata. Requires API keys.",
            "profile-domain": "DNS resolution, MX records, SPF, DMARC and VirusTotal (if configured).",
        }
        self.query_one("#profile-description", Static).update(
            descriptions.get(pressed_id, "")
        )

    def _get_selected_profile(self) -> Profile:
        """Get selected profile from radio set."""
        radio_set = self.query_one("#profile-radio", RadioSet)
        button = radio_set.pressed_button
        pressed_id = (button.id if button and button.id else "profile-full")
        mapping = {
            "profile-full": Profile.FULL,
            "profile-breach": Profile.BREACH,
            "profile-public": Profile.PUBLIC,
            "profile-domain": Profile.DOMAIN,
        }
        return mapping.get(pressed_id, Profile.FULL)

    @on(Button.Pressed, "#btn-continue")
    def on_continue_pressed(self) -> None:
        self.dismiss(self._get_selected_profile())

    @on(Button.Pressed, "#btn-back")
    def on_back_pressed(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_submit(self) -> None:
        self.dismiss(self._get_selected_profile())
