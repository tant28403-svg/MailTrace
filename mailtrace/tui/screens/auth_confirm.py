"""Authorization confirmation screen for MailTrace TUI."""

from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Static


class AuthConfirmScreen(Screen[Any]):
    """Screen for confirming external API calls."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Cancel"),
        ("enter", "confirm", "Confirm"),
    ]

    def __init__(self, providers: list[str], email: str):
        super().__init__()
        self.providers = providers
        self.email = email

    def compose(self) -> ComposeResult:
        provider_names = {
            "hibp": "Have I Been Pwned (breach database)",
            "breachdirectory": "BreachDirectory (breach intelligence)",
            "emailrep": "emailrep.io (email reputation)",
            "github": "GitHub (public repository metadata)",
            "brave_search": "Brave Search (public web search)",
            "virustotal": "VirusTotal (domain/URL reputation)",
            "dns": "DNS (domain records - external resolvers)",
        }

        provider_list = "\n".join(
            f"  • {provider_names.get(p, p)}" for p in self.providers
        )

        yield Container(
            Vertical(
                Static("Authorization Required", id="screen-title"),
                Static(
                    f"The following external services will receive the email address:\n{provider_list}",
                    id="provider-list",
                ),
                Static(
                    f"Target: {self._mask_email(self.email)}",
                    id="target-display",
                ),
                Checkbox(
                    "I authorize MailTrace to send this email to the above providers",
                    id="auth-checkbox",
                ),
                Container(
                    Button("Cancel", id="btn-cancel", variant="default"),
                    Button("Authorize & Continue", id="btn-confirm", variant="primary"),
                    id="button-row",
                ),
                id="auth-content",
            ),
            id="auth-container",
        )

    def _mask_email(self, email: str) -> str:
        """Mask email for display."""
        try:
            local, domain = email.split("@", 1)
            if len(local) <= 2:
                masked_local = local[0] + "*" * (len(local) - 1)
            else:
                masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
            return f"{masked_local}@{domain}"
        except ValueError:
            return "***@***"

    @on(Button.Pressed, "#btn-confirm")
    def on_confirm_pressed(self) -> None:
        checkbox = self.query_one("#auth-checkbox", Checkbox)
        if checkbox.value:
            self.dismiss(True)
        else:
            self.notify("Please check the authorization box", severity="error")

    @on(Button.Pressed, "#btn-cancel")
    def on_cancel_pressed(self) -> None:
        self.dismiss(False)

    @on(Checkbox.Changed, "#auth-checkbox")
    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        self.query_one("#btn-confirm", Button).disabled = not event.value

    def action_cancel(self) -> None:
        self.dismiss(False)

    def action_confirm(self) -> None:
        checkbox = self.query_one("#auth-checkbox", Checkbox)
        if checkbox.value:
            self.dismiss(True)
