"""Email input screen for MailTrace TUI."""

import re
from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.validation import ValidationResult, Validator
from textual.widgets import Button, Input, Static


class EmailValidator(Validator):
    """Email address validator."""

    def validate(self, value: str) -> ValidationResult:
        if not value:
            return self.failure("Email address is required")
        # Basic email regex
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            return self.failure("Invalid email format")
        return self.success()


class EmailInputScreen(Screen[Any]):
    """Screen for entering target email address."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Cancel"),
        ("enter", "submit", "Submit"),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Static("New Investigation", id="screen-title"),
                Static("Enter the email address to investigate:", id="instruction"),
                Input(
                    placeholder="user@example.com",
                    id="email-input",
                    validators=[EmailValidator()],
                    validate_on=["submitted", "changed"],
                ),
                Static("", id="validation-message"),
                Container(
                    Button("Cancel", id="btn-cancel", variant="default"),
                    Button("Continue", id="btn-continue", variant="primary"),
                    id="button-row",
                ),
                id="email-content",
            ),
            id="email-container",
        )

    def on_mount(self) -> None:
        self.query_one("#email-input", Input).focus()

    @on(Input.Changed, "#email-input")
    def on_email_changed(self, event: Input.Changed) -> None:
        """Validate email on change."""
        input_widget = event.input
        validation = input_widget.validate(input_widget.value)
        msg_widget = self.query_one("#validation-message", Static)
        if validation is not None and validation.is_valid:
            msg_widget.update("")
            msg_widget.remove_class("error")
        else:
            descriptions = validation.failure_descriptions if validation else []
            msg_widget.update(descriptions[0] if descriptions else "Invalid")
            msg_widget.add_class("error")

    @on(Button.Pressed, "#btn-continue")
    def on_continue_pressed(self) -> None:
        email_input = self.query_one("#email-input", Input)
        validation = email_input.validate(email_input.value)
        if validation is not None and validation.is_valid:
            self.dismiss(email_input.value.strip().lower())
        else:
            self.notify("Please enter a valid email address", severity="error")

    @on(Button.Pressed, "#btn-cancel")
    def on_cancel_pressed(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted, "#email-input")
    def on_email_submitted(self, event: Input.Submitted) -> None:
        if event.validation_result is not None and event.validation_result.is_valid:
            self.dismiss(event.value.strip().lower())

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_submit(self) -> None:
        email_input = self.query_one("#email-input", Input)
        validation = email_input.validate(email_input.value)
        if validation is not None and validation.is_valid:
            self.dismiss(email_input.value.strip().lower())
