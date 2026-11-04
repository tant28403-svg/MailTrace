"""Configuration management for MailTrace."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

CONFIG_DIR = Path(os.getenv("MAILTRACE_CONFIG_DIR", "~/.config/mailtrace")).expanduser()
SETTINGS_ENV_FILE = CONFIG_DIR / ".env"
PROVIDERS_FILE = Path(
    os.getenv("MAILTRACE_CONFIG_FILE", str(CONFIG_DIR / "providers.toml"))
).expanduser()


class GeneralConfig(BaseSettings):
    """General application settings.

    Both ``MAILTRACE_DATA_DIR`` and the nested
    ``MAILTRACE_GENERAL_DATA_DIR`` spelling are accepted.  The latter is the
    form used in the example environment file and the project plan.
    """

    model_config = SettingsConfigDict(
        env_prefix="MAILTRACE_",
        env_file=(str(Path.cwd() / ".env"), str(SETTINGS_ENV_FILE)),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    data_dir: Path = Field(
        default_factory=lambda: Path.home() / ".local" / "share" / "mailtrace",
        validation_alias=AliasChoices(
            "MAILTRACE_GENERAL_DATA_DIR",
            "MAILTRACE_DATA_DIR",
            "data_dir",
        ),
    )
    mask_output: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "MAILTRACE_GENERAL_MASK_OUTPUT",
            "MAILTRACE_MASK_OUTPUT",
            "mask_output",
        ),
    )
    confirm_external: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "MAILTRACE_GENERAL_CONFIRM_EXTERNAL",
            "MAILTRACE_CONFIRM_EXTERNAL",
            "confirm_external",
        ),
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        validation_alias=AliasChoices(
            "MAILTRACE_GENERAL_LOG_LEVEL",
            "MAILTRACE_LOG_LEVEL",
            "log_level",
        ),
    )
    theme: Literal["dark", "light", "system"] = Field(
        default="dark",
        validation_alias=AliasChoices(
            "MAILTRACE_GENERAL_THEME",
            "MAILTRACE_THEME",
            "theme",
        ),
    )

    @field_validator("data_dir", mode="before")
    @classmethod
    def _expand_data_dir(cls, value: str | Path) -> Path:
        if isinstance(value, str):
            return Path(value).expanduser().resolve()
        if isinstance(value, Path):
            return value.expanduser().resolve()
        return value


def _flatten_provider_toml(data: dict[str, Any]) -> dict[str, Any]:
    """Convert the documented nested TOML layout into flat setting names."""
    flat: dict[str, Any] = {}
    providers = data.get("providers")
    if not isinstance(providers, dict):
        return flat

    for provider, values in providers.items():
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            if key == "enabled":
                flat[f"{provider}_enabled"] = value
            elif key == "api_key":
                flat[f"{provider}_api_key"] = value
            elif key == "token":
                flat[f"{provider}_token"] = value
            elif key == "base_url":
                flat[f"{provider}_base_url"] = value
            elif key == "timeout":
                flat[f"{provider}_timeout"] = value
            elif key == "rate_limit":
                flat[f"{provider}_rate_limit"] = value
            elif key == "rapidapi_host":
                flat[f"{provider}_rapidapi_host"] = value
            elif key == "resolvers":
                flat[f"{provider}_resolvers"] = value
    return flat


class MailTraceTomlSettingsSource(PydanticBaseSettingsSource):
    """Load provider settings from ``~/.config/mailtrace/providers.toml``."""

    def __init__(self, settings_cls: type[BaseSettings]) -> None:
        super().__init__(settings_cls)
        self._data: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any]:
        if self._data is not None:
            return self._data
        if not PROVIDERS_FILE.is_file():
            self._data = {}
            return self._data
        try:
            with PROVIDERS_FILE.open("rb") as handle:
                raw = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            self._data = {}
            return self._data
        self._data = _flatten_provider_toml(raw)
        return self._data

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        return self._load()


class Config(BaseSettings):
    """Main configuration container - flat structure with all provider settings."""

    model_config = SettingsConfigDict(
        env_prefix="MAILTRACE_",
        env_file=(str(Path.cwd() / ".env"), str(SETTINGS_ENV_FILE)),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # General settings
    general: GeneralConfig = Field(default_factory=GeneralConfig)

    # HIBP
    hibp_enabled: bool = True
    hibp_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("HIBP_API_KEY", "MAILTRACE_HIBP_API_KEY"),
    )
    hibp_base_url: str = "https://haveibeenpwned.com/api/v3"
    hibp_timeout: float = 30.0
    hibp_rate_limit: int = 60

    # GitHub
    github_enabled: bool = True
    github_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GITHUB_TOKEN", "MAILTRACE_GITHUB_TOKEN"),
    )
    github_base_url: str = "https://api.github.com"
    github_timeout: float = 30.0
    github_rate_limit: int = 60

    # Brave Search
    brave_search_enabled: bool = False
    brave_search_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("BRAVE_API_KEY", "MAILTRACE_BRAVE_API_KEY"),
    )
    brave_search_base_url: str = "https://api.search.brave.com/res/v1/web/search"
    brave_search_timeout: float = 30.0
    brave_search_rate_limit: int = 60

    # VirusTotal
    virustotal_enabled: bool = False
    virustotal_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("VIRUSTOTAL_API_KEY", "MAILTRACE_VIRUSTOTAL_API_KEY"),
    )
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    virustotal_timeout: float = 30.0
    virustotal_rate_limit: int = 60

    # DNS
    dns_enabled: bool = True
    dns_resolvers: list[str] = Field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    dns_timeout: float = 10.0
    dns_rate_limit: int = 60

    # BreachDirectory (RapidAPI)
    breachdirectory_enabled: bool = False
    breachdirectory_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "BREACHDIRECTORY_API_KEY",
            "MAILTRACE_BREACHDIRECTORY_API_KEY",
        ),
    )
    breachdirectory_base_url: str = "https://breachdirectory.p.rapidapi.com"
    breachdirectory_rapidapi_host: str = "breachdirectory.p.rapidapi.com"
    breachdirectory_timeout: float = 30.0
    breachdirectory_rate_limit: int = 60

    # emailrep.io
    emailrep_enabled: bool = True  # Enabled by default - no API key required
    emailrep_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("EMAILREP_API_KEY", "MAILTRACE_EMAILREP_API_KEY"),
    )
    emailrep_base_url: str = "https://emailrep.io"
    emailrep_timeout: float = 30.0
    emailrep_rate_limit: int = 100  # ~1000/day free tier

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Precedence: explicit arguments > process env > .env files >
        # providers.toml > secret files.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            MailTraceTomlSettingsSource(settings_cls),
            file_secret_settings,
        )

    def get_enabled_providers(self) -> list[str]:
        """Return list of enabled and configured provider names."""
        enabled: list[str] = []
        if self.hibp_enabled and self.hibp_api_key:
            enabled.append("hibp")
        if self.breachdirectory_enabled and self.breachdirectory_api_key:
            enabled.append("breachdirectory")
        if self.emailrep_enabled:
            enabled.append("emailrep")  # No API key required
        if self.github_enabled and self.github_token:
            enabled.append("github")
        if self.brave_search_enabled and self.brave_search_api_key:
            enabled.append("brave_search")
        if self.virustotal_enabled and self.virustotal_api_key:
            enabled.append("virustotal")
        if self.dns_enabled:
            enabled.append("dns")
        return enabled

    def configure_errors(self) -> dict[str, str]:
        """Return configuration errors for enabled providers without credentials."""
        errors: dict[str, str] = {}
        if self.hibp_enabled and not self.hibp_api_key:
            errors["hibp"] = "API key required (set HIBP_API_KEY)"
        if self.breachdirectory_enabled and not self.breachdirectory_api_key:
            errors["breachdirectory"] = "API key required (set BREACHDIRECTORY_API_KEY)"
        if self.github_enabled and not self.github_token:
            errors["github"] = "Token required (set GITHUB_TOKEN)"
        if self.brave_search_enabled and not self.brave_search_api_key:
            errors["brave_search"] = "API key required (set BRAVE_API_KEY)"
        if self.virustotal_enabled and not self.virustotal_api_key:
            errors["virustotal"] = "API key required (set VIRUSTOTAL_API_KEY)"
        return errors

    def validate_providers(self) -> dict[str, str]:
        """Backward-compatible alias for :meth:`configure_errors`."""
        return self.configure_errors()

    # Backward-compatible provider views used by the CLI and TUI.
    @property
    def hibp(self) -> HIBPConfig:
        return HIBPConfig(
            enabled=self.hibp_enabled,
            api_key=self.hibp_api_key,
            base_url=self.hibp_base_url,
            timeout=self.hibp_timeout,
            rate_limit=self.hibp_rate_limit,
        )

    @property
    def github(self) -> GitHubConfig:
        return GitHubConfig(
            enabled=self.github_enabled,
            token=self.github_token,
            base_url=self.github_base_url,
            timeout=self.github_timeout,
            rate_limit=self.github_rate_limit,
        )

    @property
    def brave_search(self) -> BraveSearchConfig:
        return BraveSearchConfig(
            enabled=self.brave_search_enabled,
            api_key=self.brave_search_api_key,
            base_url=self.brave_search_base_url,
            timeout=self.brave_search_timeout,
            rate_limit=self.brave_search_rate_limit,
        )

    @property
    def virustotal(self) -> VirusTotalConfig:
        return VirusTotalConfig(
            enabled=self.virustotal_enabled,
            api_key=self.virustotal_api_key,
            base_url=self.virustotal_base_url,
            timeout=self.virustotal_timeout,
            rate_limit=self.virustotal_rate_limit,
        )

    @property
    def dns(self) -> DNSConfig:
        return DNSConfig(
            enabled=self.dns_enabled,
            resolvers=self.dns_resolvers,
            timeout=self.dns_timeout,
            rate_limit=self.dns_rate_limit,
        )

    @property
    def breachdirectory(self) -> BreachDirectoryConfig:
        return BreachDirectoryConfig(
            enabled=self.breachdirectory_enabled,
            api_key=self.breachdirectory_api_key,
            base_url=self.breachdirectory_base_url,
            rapidapi_host=self.breachdirectory_rapidapi_host,
            timeout=self.breachdirectory_timeout,
            rate_limit=self.breachdirectory_rate_limit,
        )

    @property
    def emailrep(self) -> EmailRepConfig:
        return EmailRepConfig(
            enabled=self.emailrep_enabled,
            api_key=self.emailrep_api_key,
            base_url=self.emailrep_base_url,
            timeout=self.emailrep_timeout,
            rate_limit=self.emailrep_rate_limit,
        )


@dataclass(frozen=True)
class HIBPConfig:
    enabled: bool
    api_key: str | None
    base_url: str
    timeout: float
    rate_limit: int


@dataclass(frozen=True)
class GitHubConfig:
    enabled: bool
    token: str | None
    base_url: str
    timeout: float
    rate_limit: int


@dataclass(frozen=True)
class BraveSearchConfig:
    enabled: bool
    api_key: str | None
    base_url: str
    timeout: float
    rate_limit: int


@dataclass(frozen=True)
class VirusTotalConfig:
    enabled: bool
    api_key: str | None
    base_url: str
    timeout: float
    rate_limit: int


@dataclass(frozen=True)
class DNSConfig:
    enabled: bool
    resolvers: list[str]
    timeout: float
    rate_limit: int


@dataclass(frozen=True)
class BreachDirectoryConfig:
    enabled: bool
    api_key: str | None
    base_url: str
    rapidapi_host: str
    timeout: float
    rate_limit: int


@dataclass(frozen=True)
class EmailRepConfig:
    enabled: bool
    api_key: str | None
    base_url: str
    timeout: float
    rate_limit: int


# Global config instance
_config: Config | None = None


def get_config() -> Config:
    """Get global config instance (lazy load)."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def reload_config() -> Config:
    """Reload configuration from disk/env."""
    global _config
    _config = Config()
    return _config


def save_general_settings(updates: dict[str, Any]) -> Path:
    """Persist general settings to ``~/.config/mailtrace/.env``.

    Only non-secret general settings are written.  API keys must be supplied
    through the process environment or the project ``.env`` file.
    """
    key_map = {
        "data_dir": "MAILTRACE_GENERAL_DATA_DIR",
        "mask_output": "MAILTRACE_GENERAL_MASK_OUTPUT",
        "confirm_external": "MAILTRACE_GENERAL_CONFIRM_EXTERNAL",
        "log_level": "MAILTRACE_GENERAL_LOG_LEVEL",
        "theme": "MAILTRACE_GENERAL_THEME",
        "hibp_enabled": "MAILTRACE_HIBP_ENABLED",
        "breachdirectory_enabled": "MAILTRACE_BREACHDIRECTORY_ENABLED",
        "emailrep_enabled": "MAILTRACE_EMAILREP_ENABLED",
        "github_enabled": "MAILTRACE_GITHUB_ENABLED",
        "brave_search_enabled": "MAILTRACE_BRAVE_SEARCH_ENABLED",
        "virustotal_enabled": "MAILTRACE_VIRUSTOTAL_ENABLED",
        "dns_enabled": "MAILTRACE_DNS_ENABLED",
    }
    unknown = set(updates) - set(key_map)
    if unknown:
        raise ValueError(f"Unsupported settings: {', '.join(sorted(unknown))}")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    existing: dict[str, str] = {}
    if SETTINGS_ENV_FILE.is_file():
        for line in SETTINGS_ENV_FILE.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            existing[key.strip()] = value.strip()

    for key, value in updates.items():
        env_key = key_map[key]
        if isinstance(value, bool):
            value = "true" if value else "false"
        existing[env_key] = str(value)

    lines = [
        "# MailTrace settings written by the application.",
        "# Environment variables take precedence over values in this file.",
        "",
    ]
    lines.extend(f"{key}={value}" for key, value in sorted(existing.items()))
    SETTINGS_ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return SETTINGS_ENV_FILE
