"""Configuration management for MailTrace."""

from __future__ import annotations

import hashlib
import os
import shutil
import tomllib
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
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


@dataclass(frozen=True)
class ProviderKeySpec:
    """Metadata describing a provider credential."""

    provider: str
    label: str
    enabled_attr: str
    key_attr: str
    key_aliases: tuple[str, ...]
    toml_key: str | None = None
    requires_key: bool = True


#: Provider metadata used by the key gate, status output and migration helper.
#: Keeping this in one place prevents the CLI, TUI and orchestrator from
#: disagreeing about which providers require credentials.
PROVIDER_KEY_SPECS: tuple[ProviderKeySpec, ...] = (
    ProviderKeySpec(
        provider="hibp",
        label="HIBP",
        enabled_attr="hibp_enabled",
        key_attr="hibp_api_key",
        key_aliases=("HIBP_API_KEY", "MAILTRACE_HIBP_API_KEY"),
        toml_key="hibp_api_key",
    ),
    ProviderKeySpec(
        provider="breachdirectory",
        label="BreachDirectory",
        enabled_attr="breachdirectory_enabled",
        key_attr="breachdirectory_api_key",
        key_aliases=(
            "BREACHDIRECTORY_API_KEY",
            "MAILTRACE_BREACHDIRECTORY_API_KEY",
        ),
        toml_key="breachdirectory_api_key",
    ),
    ProviderKeySpec(
        provider="github",
        label="GitHub",
        enabled_attr="github_enabled",
        key_attr="github_token",
        key_aliases=("GITHUB_TOKEN", "MAILTRACE_GITHUB_TOKEN"),
        toml_key="github_token",
    ),
    ProviderKeySpec(
        provider="brave_search",
        label="Brave Search",
        enabled_attr="brave_search_enabled",
        key_attr="brave_search_api_key",
        key_aliases=("BRAVE_API_KEY", "MAILTRACE_BRAVE_API_KEY"),
        toml_key="brave_search_api_key",
    ),
    ProviderKeySpec(
        provider="virustotal",
        label="VirusTotal",
        enabled_attr="virustotal_enabled",
        key_attr="virustotal_api_key",
        key_aliases=("VIRUSTOTAL_API_KEY", "MAILTRACE_VIRUSTOTAL_API_KEY"),
        toml_key="virustotal_api_key",
    ),
    ProviderKeySpec(
        provider="emailrep",
        label="emailrep.io",
        enabled_attr="emailrep_enabled",
        key_attr="emailrep_api_key",
        key_aliases=("EMAILREP_API_KEY", "MAILTRACE_EMAILREP_API_KEY"),
        toml_key="emailrep_api_key",
        requires_key=False,
    ),
    ProviderKeySpec(
        provider="dns",
        label="DNS",
        enabled_attr="dns_enabled",
        key_attr="",
        key_aliases=(),
        requires_key=False,
    ),
)

PROJECT_ENV_OPT_IN = "MAILTRACE_USE_PROJECT_ENV"

SECRET_ENV_NAMES: frozenset[str] = frozenset(
    alias for spec in PROVIDER_KEY_SPECS for alias in spec.key_aliases
)

#: Recognised non-secret settings that ``config keys migrate --all`` may move.
RECOGNIZED_SETTING_NAMES: frozenset[str] = frozenset(
    {
        "MAILTRACE_GENERAL_DATA_DIR",
        "MAILTRACE_DATA_DIR",
        "MAILTRACE_GENERAL_MASK_OUTPUT",
        "MAILTRACE_MASK_OUTPUT",
        "MAILTRACE_GENERAL_CONFIRM_EXTERNAL",
        "MAILTRACE_CONFIRM_EXTERNAL",
        "MAILTRACE_GENERAL_LOG_LEVEL",
        "MAILTRACE_LOG_LEVEL",
        "MAILTRACE_GENERAL_THEME",
        "MAILTRACE_THEME",
        "MAILTRACE_GENERAL_REQUIRE_KEYS",
        "MAILTRACE_REQUIRE_KEYS",
        "MAILTRACE_HIBP_ENABLED",
        "HIBP_ENABLED",
        "MAILTRACE_BREACHDIRECTORY_ENABLED",
        "BREACHDIRECTORY_ENABLED",
        "MAILTRACE_EMAILREP_ENABLED",
        "EMAILREP_ENABLED",
        "MAILTRACE_GITHUB_ENABLED",
        "GITHUB_ENABLED",
        "MAILTRACE_BRAVE_SEARCH_ENABLED",
        "BRAVE_SEARCH_ENABLED",
        "MAILTRACE_VIRUSTOTAL_ENABLED",
        "VIRUSTOTAL_ENABLED",
        "MAILTRACE_DNS_ENABLED",
        "DNS_ENABLED",
    }
)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def use_project_env() -> bool:
    """Return whether the project-local ``.env`` is explicitly enabled."""
    return _env_flag(PROJECT_ENV_OPT_IN)


def project_env_path() -> Path:
    """Return the project-local ``.env`` path resolved at call time."""
    return Path.cwd() / ".env"


def _default_env_files() -> list[Path]:
    """Build the default dotenv source list.

    The per-user file is intentionally the only default source.  A project
    ``.env`` can be opted into for development, but it is loaded first so the
    per-user file always wins when both define the same key.
    """
    files: list[Path] = []
    if use_project_env():
        project_env = project_env_path()
        if project_env.is_file():
            files.append(project_env)
    if SETTINGS_ENV_FILE.is_file():
        files.append(SETTINGS_ENV_FILE)
    return files


class _MailTraceSettings(BaseSettings):
    """Settings base class that resolves dotenv files at construction time."""

    def __init__(self, **kwargs: Any) -> None:
        if "_env_file" not in kwargs:
            env_files = _default_env_files()
            kwargs["_env_file"] = env_files or None
        super().__init__(**kwargs)


class GeneralConfig(_MailTraceSettings):
    """General application settings.

    Both ``MAILTRACE_DATA_DIR`` and the nested
    ``MAILTRACE_GENERAL_DATA_DIR`` spelling are accepted.  The latter is the
    form used in the example environment file and the project plan.
    """

    model_config = SettingsConfigDict(
        env_prefix="MAILTRACE_",
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
    require_keys: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "MAILTRACE_GENERAL_REQUIRE_KEYS",
            "MAILTRACE_REQUIRE_KEYS",
            "require_keys",
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


class Config(_MailTraceSettings):
    """Main configuration container - flat structure with all provider settings."""

    model_config = SettingsConfigDict(
        env_prefix="MAILTRACE_",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # General settings
    general: GeneralConfig = Field(default_factory=GeneralConfig)

    # HIBP
    hibp_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("MAILTRACE_HIBP_ENABLED", "HIBP_ENABLED"),
    )
    hibp_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("HIBP_API_KEY", "MAILTRACE_HIBP_API_KEY"),
    )
    hibp_base_url: str = "https://haveibeenpwned.com/api/v3"
    hibp_timeout: float = 30.0
    hibp_rate_limit: int = 60

    # GitHub
    github_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("MAILTRACE_GITHUB_ENABLED", "GITHUB_ENABLED"),
    )
    github_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GITHUB_TOKEN", "MAILTRACE_GITHUB_TOKEN"),
    )
    github_base_url: str = "https://api.github.com"
    github_timeout: float = 30.0
    github_rate_limit: int = 60

    # Brave Search
    brave_search_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("MAILTRACE_BRAVE_SEARCH_ENABLED", "BRAVE_SEARCH_ENABLED"),
    )
    brave_search_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("BRAVE_API_KEY", "MAILTRACE_BRAVE_API_KEY"),
    )
    brave_search_base_url: str = "https://api.search.brave.com/res/v1/web/search"
    brave_search_timeout: float = 30.0
    brave_search_rate_limit: int = 60

    # VirusTotal
    virustotal_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("MAILTRACE_VIRUSTOTAL_ENABLED", "VIRUSTOTAL_ENABLED"),
    )
    virustotal_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("VIRUSTOTAL_API_KEY", "MAILTRACE_VIRUSTOTAL_API_KEY"),
    )
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    virustotal_timeout: float = 30.0
    virustotal_rate_limit: int = 60

    # DNS
    dns_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("MAILTRACE_DNS_ENABLED", "DNS_ENABLED"),
    )
    dns_resolvers: list[str] = Field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    dns_timeout: float = 10.0
    dns_rate_limit: int = 60

    # BreachDirectory (RapidAPI)
    breachdirectory_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "MAILTRACE_BREACHDIRECTORY_ENABLED", "BREACHDIRECTORY_ENABLED"
        ),
    )
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
    emailrep_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("MAILTRACE_EMAILREP_ENABLED", "EMAILREP_ENABLED"),
    )  # Enabled by default - no API key required
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

    def require_keys_satisfied(self) -> bool:
        """Return whether at least one enabled, key-requiring provider is usable.

        MailTrace is designed so a person who obtains the project cannot run
        investigations on someone else's provider credentials.  Scans are
        gated until the user configures their own key.  Setting
        ``MAILTRACE_GENERAL_REQUIRE_KEYS=false`` restores keyless DNS/emailrep
        runs for development or explicitly accepted use.
        """
        if not self.general.require_keys:
            return True
        return any(status.ready for status in iter_configured_keys(self) if status.requires_key)

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


@dataclass(frozen=True)
class ProviderKeyStatus:
    """Effective credential status for one provider."""

    provider: str
    label: str
    enabled: bool
    requires_key: bool
    configured: bool
    source: str
    fingerprint: str | None = None

    @property
    def ready(self) -> bool:
        """Return whether the provider can run with the current settings."""
        return self.enabled and (not self.requires_key or self.configured)


@dataclass
class KeyMigrationResult:
    """Outcome of moving project-local credentials to the per-user file.

    Only names and fingerprints are reported; credential values are never
    exposed by the migration API.
    """

    source: Path
    destination: Path
    backup: Path | None = None
    moved: list[str] = field(default_factory=list)
    destination_overrides: list[str] = field(default_factory=list)
    leftover: list[str] = field(default_factory=list)
    unrecognized: list[str] = field(default_factory=list)
    fingerprints: dict[str, str] = field(default_factory=dict)


def fingerprint_secret(value: str) -> str:
    """Return a short, stable fingerprint that does not reveal the secret."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def _read_env_file(path: Path) -> dict[str, str]:
    """Read simple ``KEY=VALUE`` pairs without ever logging their values."""
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def _read_toml_settings() -> dict[str, Any]:
    if not PROVIDERS_FILE.is_file():
        return {}
    try:
        with PROVIDERS_FILE.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return _flatten_provider_toml(raw)


def _detect_key_source(
    spec: ProviderKeySpec,
    process_env: dict[str, str],
    user_env: dict[str, str],
    project_env: dict[str, str],
    toml_settings: dict[str, Any],
) -> tuple[str, str | None]:
    """Find where a credential came from, following the load precedence."""
    for name in spec.key_aliases:
        value = process_env.get(name.upper(), "").strip()
        if value:
            return "process environment", value
    for name in spec.key_aliases:
        value = user_env.get(name, "").strip()
        if value:
            return "user .env", value
    for name in spec.key_aliases:
        value = project_env.get(name, "").strip()
        if value:
            if use_project_env():
                return "project .env", value
            return "project .env (ignored)", value
    if spec.toml_key:
        value = str(toml_settings.get(spec.toml_key) or "").strip()
        if value:
            return "providers.toml", value
    return "none", None


def iter_configured_keys(config: Config | None = None) -> list[ProviderKeyStatus]:
    """Return credential status for every known provider.

    Values are represented only by a short SHA-256 fingerprint.  If a project
    ``.env`` is ignored, its credential is still fingerprinted so the user can
    identify which key needs to be moved, but it is not marked configured.
    """
    settings = config or get_config()
    process_env = {name.upper(): value for name, value in os.environ.items()}
    user_env = _read_env_file(SETTINGS_ENV_FILE)
    project_env = _read_env_file(project_env_path())
    toml_settings = _read_toml_settings()

    statuses: list[ProviderKeyStatus] = []
    for spec in PROVIDER_KEY_SPECS:
        enabled = bool(getattr(settings, spec.enabled_attr))
        if not spec.requires_key:
            statuses.append(
                ProviderKeyStatus(
                    provider=spec.provider,
                    label=spec.label,
                    enabled=enabled,
                    requires_key=False,
                    configured=True,
                    source="not required",
                )
            )
            continue

        configured_value = getattr(settings, spec.key_attr, None)
        configured_value = (
            configured_value.strip() if isinstance(configured_value, str) else configured_value
        )
        source, source_value = _detect_key_source(
            spec, process_env, user_env, project_env, toml_settings
        )
        if configured_value and source == "none":
            source = "explicit"
            source_value = str(configured_value)
        fingerprint = (
            fingerprint_secret(str(source_value or configured_value))
            if (source_value or configured_value)
            else None
        )
        statuses.append(
            ProviderKeyStatus(
                provider=spec.provider,
                label=spec.label,
                enabled=enabled,
                requires_key=True,
                configured=bool(configured_value),
                source=source,
                fingerprint=fingerprint,
            )
        )
    return statuses


def find_project_env_secrets(project_dir: Path | None = None) -> dict[str, str]:
    """Return known credential names and fingerprints found in a project .env."""
    path = (project_dir or Path.cwd()) / ".env"
    values = _read_env_file(path)
    secrets: dict[str, str] = {}
    for name, value in values.items():
        if name.upper() in SECRET_ENV_NAMES and value.strip():
            secrets[name] = fingerprint_secret(value)
    return secrets


def project_env_warning() -> str | None:
    """Return a warning when an ignored project .env still contains keys."""
    if use_project_env():
        return None
    secrets = find_project_env_secrets()
    if not secrets:
        return None
    names = ", ".join(sorted(secrets))
    return (
        f"Keys found in ./.env are ignored ({names}). Move them to "
        f"{SETTINGS_ENV_FILE} - this project folder may be shared. "
        "Run `mailtrace config keys migrate`."
    )


def _restrict_permissions(path: Path) -> None:
    """Make a credential file private where the platform supports it."""
    with suppress(OSError):
        path.chmod(0o600)


def _merge_env_file(path: Path, updates: dict[str, str]) -> None:
    """Merge ``KEY=VALUE`` updates while preserving comments and other keys."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_lines = (
        path.read_text(encoding="utf-8-sig").splitlines() if path.is_file() else []
    )
    lines = list(existing_lines)
    if not lines:
        lines = [
            "# MailTrace settings. Keep this file private.",
            "# Environment variables take precedence over values in this file.",
            "",
        ]

    seen: set[str] = set()
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, _ = stripped.partition("=")
        key = key.strip()
        if key in updates:
            lines[index] = f"{key}={updates[key]}"
            seen.add(key)

    for key, value in updates.items():
        if key not in seen:
            lines.append(f"{key}={value}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _restrict_permissions(path)


def migrate_project_keys(
    project_dir: Path | None = None,
    *,
    include_all: bool = False,
) -> KeyMigrationResult:
    """Move project-local credentials into the per-user env file.

    A timestamped backup of the destination file is written next to it (not in
    the project folder) so the migration never re-introduces secrets into a
    directory that may be shared or committed.  Existing destination values win
    over project values; the project line is still removed.
    """
    source = (project_dir or Path.cwd()) / ".env"
    destination = SETTINGS_ENV_FILE
    result = KeyMigrationResult(source=source, destination=destination)
    if not source.is_file():
        raise FileNotFoundError(f"No project .env found at {source}")

    destination_values = _read_env_file(destination)
    destination_upper = {key.upper(): value for key, value in destination_values.items()}

    updates: dict[str, str] = {}
    remaining_lines: list[str] = []
    for raw in source.read_text(encoding="utf-8-sig").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            remaining_lines.append(raw)
            continue
        candidate = stripped[7:].lstrip() if stripped.startswith("export ") else stripped
        key, separator, value = candidate.partition("=")
        name = key.strip()
        if not separator or not name:
            remaining_lines.append(raw)
            continue
        upper = name.upper()
        recognized = upper in SECRET_ENV_NAMES or (
            include_all and upper in RECOGNIZED_SETTING_NAMES
        )
        if not recognized:
            if value.strip():
                if upper in RECOGNIZED_SETTING_NAMES:
                    result.leftover.append(name)
                else:
                    result.unrecognized.append(name)
            remaining_lines.append(raw)
            continue
        if not value.strip():
            remaining_lines.append(raw)
            continue

        if destination_upper.get(upper):
            result.destination_overrides.append(name)
        else:
            updates[name] = value.strip()
            destination_upper[upper] = value.strip()
            result.moved.append(name)
            if upper in SECRET_ENV_NAMES:
                result.fingerprints[name] = fingerprint_secret(value.strip())

    if not result.moved and not result.destination_overrides:
        return result

    if destination.is_file():
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = destination.parent / f".env.backup-{timestamp}"
        suffix = 1
        while backup.exists():
            backup = destination.parent / f".env.backup-{timestamp}-{suffix}"
            suffix += 1
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(destination, backup)
        _restrict_permissions(backup)
        result.backup = backup
    if updates:
        _merge_env_file(destination, updates)

    if any(line.strip() and not line.strip().startswith("#") for line in remaining_lines):
        source.write_text("\n".join(remaining_lines) + "\n", encoding="utf-8")
    else:
        source.write_text(
            "# API keys were moved to the per-user MailTrace configuration.\n"
            "# This file no longer contains credentials and can be deleted.\n",
            encoding="utf-8",
        )
    return result


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

    Only non-secret settings are written.  Credentials belong in the same
    per-user file (or the process environment) and are never added here by this
    function.  Existing keys and comments are preserved.
    """
    key_map = {
        "data_dir": "MAILTRACE_GENERAL_DATA_DIR",
        "mask_output": "MAILTRACE_GENERAL_MASK_OUTPUT",
        "confirm_external": "MAILTRACE_GENERAL_CONFIRM_EXTERNAL",
        "log_level": "MAILTRACE_GENERAL_LOG_LEVEL",
        "theme": "MAILTRACE_GENERAL_THEME",
        "require_keys": "MAILTRACE_GENERAL_REQUIRE_KEYS",
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

    rendered: dict[str, str] = {}
    for key, value in updates.items():
        if isinstance(value, bool):
            rendered[key_map[key]] = "true" if value else "false"
        else:
            rendered[key_map[key]] = str(value)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _merge_env_file(SETTINGS_ENV_FILE, rendered)
    return SETTINGS_ENV_FILE
