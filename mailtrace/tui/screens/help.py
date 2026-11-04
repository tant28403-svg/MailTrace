"""Help screen for MailTrace TUI."""

from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Markdown


class HelpScreen(Screen[Any]):
    """Help screen with keybindings."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape,q,?", "close", "Close", show=True)
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Markdown(
                """
# MailTrace Help

## Navigation
| Key | Action |
|-----|--------|
| `↑/↓` | Navigate lists/tables |
| `Enter` | Select/confirm |
| `Escape` | Go back/cancel |
| `Tab` | Next focusable |
| `Shift+Tab` | Previous focusable |

## Global Shortcuts
| Key | Action |
|-----|--------|
| `F1` / `?` | This help |
| `F2` | New investigation |
| `F3` | History |
| `F4` | Settings |
| `F5` | Export (when a case is loaded) |
| `Q` | Quit |
| `Ctrl+C` | Cancel/back |

## Results
| Key | Action |
|-----|--------|
| `E` | Export the current case |
| `H` | Return to history |
| `N` | Start a new investigation |

## History
| Key | Action |
|-----|--------|
| `Enter` | View the selected case |
| `C` | Compare two selected cases |
| `D` | Delete selected cases (requires a second press) |

## Profiles
- **Breach**: HIBP, BreachDirectory and emailrep.io
- **Public**: Brave Search, GitHub and emailrep.io
- **Domain**: DNS records and VirusTotal (when configured)
- **Full**: All enabled providers

## Privacy
- Email masked by default in output
- Explicit confirmation before external API calls
- Local SQLite storage only
- Credentials returned by breach providers are redacted
- No data leaves your machine except to configured providers
                """
            ),
            id="help-container",
        )

    @on(Markdown.LinkClicked)
    def on_link_clicked(self, event: Markdown.LinkClicked) -> None:
        """Open clicked links in the default browser."""
        self.app.open_url(str(event.href))

    def action_close(self) -> None:
        self.dismiss()
