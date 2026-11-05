"""Tests for MailTrace configuration."""

from pathlib import Path

import pytest

from mailtrace.core import configuration
from mailtrace.core.configuration import (
    Config,
    GeneralConfig,
    find_project_env_secrets,
    fingerprint_secret,
    iter_configured_keys,
    save_general_settings,
)

KEY_ENV_NAMES = (
    "HIBP_API_KEY",
    "MAILTRACE_HIBP_API_KEY",
    "BREACHDIRECTORY_API_KEY",
    "MAILTRACE_BREACHDIRECTORY_API_KEY",
    "EMAILREP_API_KEY",
    "MAILTRACE_EMAILREP_API_KEY",
    "GITHUB_TOKEN",
    "MAILTRACE_GITHUB_TOKEN",
    "BRAVE_API_KEY",
    "MAILTRACE_BRAVE_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "MAILTRACE_VIRUSTOTAL_API_KEY",
    "MAILTRACE_USE_PROJECT_ENV",
)


def _clear_key_env(monkeypatch) -> None:
    for name in KEY_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def _isolate_config_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", tmp_path / "user" / ".env")
    monkeypatch.setattr(configuration, "PROVIDERS_FILE", tmp_path / "providers.toml")


class TestConfig:
    """Tests for configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        # Create config without loading .env by using explicit values
        config = Config(
            _env_file=None,
            hibp_enabled=True,
            github_enabled=True,
            brave_search_enabled=False,
            virustotal_enabled=False,
            dns_enabled=True,
            hibp_api_key=None,
            github_token=None,
            brave_search_api_key=None,
            virustotal_api_key=None,
        )
        assert config.general.mask_output is True
        assert config.general.confirm_external is True
        assert config.general.log_level == "INFO"
        assert config.general.theme == "dark"
        assert isinstance(config.general.data_dir, Path)

    def test_provider_configs(self):
        """Test provider configurations exist."""
        config = Config(
            _env_file=None,
            hibp_enabled=True,
            github_enabled=True,
            brave_search_enabled=False,
            virustotal_enabled=False,
            dns_enabled=True,
        )
        assert config.hibp.enabled is True
        assert config.github.enabled is True
        assert config.brave_search.enabled is False
        assert config.virustotal.enabled is False
        assert config.dns.enabled is True

    def test_get_enabled_providers_empty(self):
        """Test get_enabled_providers with no API keys."""
        config = Config(
            _env_file=None,
            hibp_enabled=True,
            github_enabled=True,
            brave_search_enabled=False,
            virustotal_enabled=False,
            dns_enabled=True,
            hibp_api_key=None,
            github_token=None,
            brave_search_api_key=None,
            virustotal_api_key=None,
        )
        # All providers need API keys except DNS
        enabled = config.get_enabled_providers()
        assert "dns" in enabled
        # Others should not be enabled without keys
        assert "hibp" not in enabled
        assert "github" not in enabled

    def test_validate_providers(self):
        """Test provider validation."""
        config = Config(
            _env_file=None,
            hibp_enabled=True,
            github_enabled=True,
            brave_search_enabled=False,
            virustotal_enabled=False,
            dns_enabled=True,
            hibp_api_key=None,
            github_token=None,
            brave_search_api_key=None,
            virustotal_api_key=None,
        )
        errors = config.validate_providers()
        # Should have errors for enabled providers without keys
        assert "hibp" in errors
        assert "github" in errors
        # brave_search and virustotal are disabled by default
        assert "brave_search" not in errors
        assert "virustotal" not in errors
        # DNS should not have errors
        assert "dns" not in errors


class TestGeneralConfig:
    """Tests for GeneralConfig."""

    def test_data_dir_expansion(self):
        """Test data directory path expansion."""
        config = GeneralConfig(data_dir="~/test_mailtrace")
        # The validator should expand ~ to home directory
        assert str(config.data_dir).startswith(str(Path.home()))
        assert "~" not in str(config.data_dir)


class TestConfigSources:
    """Tests for environment and TOML based configuration."""

    def test_general_env_alias(self, monkeypatch, tmp_path):
        """The nested MAILTRACE_GENERAL_* spelling is honored."""
        monkeypatch.setenv("MAILTRACE_GENERAL_DATA_DIR", str(tmp_path))
        config = Config(_env_file=None)
        assert config.general.data_dir == tmp_path

    def test_legacy_data_dir_alias(self, monkeypatch, tmp_path):
        """The legacy MAILTRACE_DATA_DIR spelling keeps working."""
        monkeypatch.delenv("MAILTRACE_GENERAL_DATA_DIR", raising=False)
        monkeypatch.setenv("MAILTRACE_DATA_DIR", str(tmp_path))
        config = Config(_env_file=None)
        assert config.general.data_dir == tmp_path

    def test_boolean_env_alias(self, monkeypatch):
        """Booleans are parsed for the documented general env vars."""
        monkeypatch.setenv("MAILTRACE_GENERAL_MASK_OUTPUT", "false")
        config = Config(_env_file=None)
        assert config.general.mask_output is False

    def test_unprefixed_provider_toggle_in_env_file(self, monkeypatch, tmp_path):
        """BREACHDIRECTORY_ENABLED in .env enables the provider."""
        monkeypatch.delenv("BREACHDIRECTORY_ENABLED", raising=False)
        monkeypatch.delenv("MAILTRACE_BREACHDIRECTORY_ENABLED", raising=False)
        env_file = tmp_path / ".env"
        env_file.write_text(
            "BREACHDIRECTORY_ENABLED=true\nBREACHDIRECTORY_API_KEY=test-key\n",
            encoding="utf-8",
        )

        config = Config(_env_file=env_file)
        assert config.breachdirectory_enabled is True
        assert "breachdirectory" in config.get_enabled_providers()

    def test_prefixed_provider_toggle_from_environment(self, monkeypatch):
        """The MAILTRACE_ prefix is the canonical spelling for toggles."""
        monkeypatch.delenv("BREACHDIRECTORY_ENABLED", raising=False)
        monkeypatch.setenv("MAILTRACE_BREACHDIRECTORY_ENABLED", "true")
        config = Config(_env_file=None)
        assert config.breachdirectory_enabled is True

    def test_provider_toml_loading(self, monkeypatch, tmp_path):
        """Provider settings can be loaded from the documented TOML layout."""
        providers_file = tmp_path / "providers.toml"
        providers_file.write_text(
            '[providers.github]\nenabled = true\ntoken = "ghp_test"\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(configuration, "PROVIDERS_FILE", providers_file)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("MAILTRACE_GITHUB_TOKEN", raising=False)

        config = Config(_env_file=None)
        assert config.github_enabled is True
        assert config.github_token == "ghp_test"
        assert config.github.enabled is True

    def test_save_general_settings(self, monkeypatch, tmp_path):
        """Non-secret settings are persisted and reloadable."""
        env_file = tmp_path / ".env"
        monkeypatch.setattr(configuration, "CONFIG_DIR", tmp_path)
        monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", env_file)

        path = save_general_settings({"mask_output": False, "theme": "light"})
        assert path == env_file
        content = env_file.read_text(encoding="utf-8")
        assert "MAILTRACE_GENERAL_MASK_OUTPUT=false" in content
        assert "MAILTRACE_GENERAL_THEME=light" in content

    def test_save_general_settings_preserves_existing_keys(self, monkeypatch, tmp_path):
        """Writing non-secret settings must not destroy credentials."""
        env_file = tmp_path / ".env"
        monkeypatch.setattr(configuration, "CONFIG_DIR", tmp_path)
        monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", env_file)
        env_file.write_text("# private\nHIBP_API_KEY=existing-key\n", encoding="utf-8")

        save_general_settings({"theme": "light", "require_keys": True})

        content = env_file.read_text(encoding="utf-8")
        assert "HIBP_API_KEY=existing-key" in content
        assert "# private" in content
        assert "MAILTRACE_GENERAL_THEME=light" in content
        assert "MAILTRACE_GENERAL_REQUIRE_KEYS=true" in content

    def test_save_general_settings_rejects_unknown(self, monkeypatch, tmp_path):
        """Unknown keys are rejected rather than silently written."""
        monkeypatch.setattr(configuration, "CONFIG_DIR", tmp_path)
        monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", tmp_path / ".env")

        with pytest.raises(ValueError, match="Unsupported settings"):
            save_general_settings({"unknown_setting": True})

    def test_project_env_is_ignored_by_default(self, monkeypatch, tmp_path):
        """A project-local .env cannot supply credentials by default."""
        _clear_key_env(monkeypatch)
        _isolate_config_files(monkeypatch, tmp_path)
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("BREACHDIRECTORY_API_KEY=project-secret\n", encoding="utf-8")

        config = Config()
        assert config.breachdirectory_api_key is None

        secrets = find_project_env_secrets()
        assert secrets == {"BREACHDIRECTORY_API_KEY": fingerprint_secret("project-secret")}
        assert "project-secret" not in str(secrets)

        status = {item.provider: item for item in iter_configured_keys(config)}["breachdirectory"]
        assert status.configured is False
        assert status.source == "project .env (ignored)"
        assert status.fingerprint == fingerprint_secret("project-secret")

    def test_project_env_opt_in(self, monkeypatch, tmp_path):
        """MAILTRACE_USE_PROJECT_ENV=1 restores the project .env for development."""
        _clear_key_env(monkeypatch)
        _isolate_config_files(monkeypatch, tmp_path)
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("BREACHDIRECTORY_API_KEY=project-secret\n", encoding="utf-8")
        monkeypatch.setenv("MAILTRACE_USE_PROJECT_ENV", "1")

        config = Config()
        assert config.breachdirectory_api_key == "project-secret"
        status = {item.provider: item for item in iter_configured_keys(config)}["breachdirectory"]
        assert status.configured is True
        assert status.source == "project .env"

    def test_user_env_wins_over_project_env(self, monkeypatch, tmp_path):
        """When opted in, the per-user file always overrides the project file."""
        _clear_key_env(monkeypatch)
        _isolate_config_files(monkeypatch, tmp_path)
        project = tmp_path / "project"
        project.mkdir()
        (project / ".env").write_text("BREACHDIRECTORY_API_KEY=project-secret\n", encoding="utf-8")
        user_env = tmp_path / "user" / ".env"
        user_env.parent.mkdir()
        user_env.write_text("BREACHDIRECTORY_API_KEY=user-secret\n", encoding="utf-8")
        monkeypatch.chdir(project)
        monkeypatch.setenv("MAILTRACE_USE_PROJECT_ENV", "1")

        config = Config()
        assert config.breachdirectory_api_key == "user-secret"

    def test_require_keys_default_and_override(self, monkeypatch):
        """The no-key gate defaults on and can be disabled explicitly."""
        monkeypatch.delenv("MAILTRACE_GENERAL_REQUIRE_KEYS", raising=False)
        monkeypatch.delenv("MAILTRACE_REQUIRE_KEYS", raising=False)
        assert Config(_env_file=None).general.require_keys is True

        monkeypatch.setenv("MAILTRACE_GENERAL_REQUIRE_KEYS", "false")
        assert Config(_env_file=None).general.require_keys is False

    def test_require_keys_satisfied(self, monkeypatch, tmp_path):
        """At least one enabled provider with its own key unlocks scans."""
        _clear_key_env(monkeypatch)
        _isolate_config_files(monkeypatch, tmp_path)

        without_key = Config(
            _env_file=None,
            hibp_enabled=True,
            hibp_api_key=None,
            github_enabled=False,
            brave_search_enabled=False,
            virustotal_enabled=False,
            breachdirectory_enabled=False,
        )
        assert without_key.require_keys_satisfied() is False

        with_key = Config(
            _env_file=None,
            hibp_enabled=True,
            hibp_api_key="dummy-key",
            github_enabled=False,
            brave_search_enabled=False,
            virustotal_enabled=False,
            breachdirectory_enabled=False,
        )
        assert with_key.require_keys_satisfied() is True

    def test_secret_detection_finds_only_known_keys(self, tmp_path):
        """Warnings must never enumerate arbitrary project-side values."""
        (tmp_path / ".env").write_text(
            "HIBP_API_KEY=known-secret\nUNRELATED_SETTING=not-a-credential\nGITHUB_TOKEN=\n",
            encoding="utf-8",
        )

        secrets = find_project_env_secrets(tmp_path)
        assert secrets == {"HIBP_API_KEY": fingerprint_secret("known-secret")}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
