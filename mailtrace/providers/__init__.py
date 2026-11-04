"""MailTrace providers package."""

from mailtrace.providers.base import BaseProvider, IntelligenceProvider
from mailtrace.providers.brave_search import BraveSearchProvider
from mailtrace.providers.breachdirectory import BreachDirectoryProvider
from mailtrace.providers.dns import DNSProvider
from mailtrace.providers.emailrep import EmailRepProvider
from mailtrace.providers.github import GitHubProvider
from mailtrace.providers.hibp import HIBPProvider
from mailtrace.providers.virustotal import VirusTotalProvider

__all__ = [
    "BaseProvider",
    "BraveSearchProvider",
    "BreachDirectoryProvider",
    "DNSProvider",
    "EmailRepProvider",
    "GitHubProvider",
    "HIBPProvider",
    "IntelligenceProvider",
    "VirusTotalProvider",
]

# Provider registry for easy access
PROVIDER_CLASSES: dict[str, type[BaseProvider]] = {
    "hibp": HIBPProvider,
    "breachdirectory": BreachDirectoryProvider,
    "emailrep": EmailRepProvider,
    "github": GitHubProvider,
    "brave_search": BraveSearchProvider,
    "virustotal": VirusTotalProvider,
    "dns": DNSProvider,
}


def get_provider_class(name: str) -> type[BaseProvider] | None:
    """Get provider class by name."""
    return PROVIDER_CLASSES.get(name)


def get_all_provider_names() -> list[str]:
    """Get all registered provider names."""
    return list(PROVIDER_CLASSES.keys())
