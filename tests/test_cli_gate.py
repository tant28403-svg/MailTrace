"""Tests for the no-api-keys gate and key management CLI."""

from datetime import UTC, datetime

from typer.testing import CliRunner

from mailtrace import cli as cli_module
from mailtrace.__main__ import app
from mailtrace.core import configuration
from mailtrace.core.configuration import Config, fingerprint_secret
from mailtrace.schemas.finding import (
    Investigation,
    InvestigationStatus,
    Profile,
)

runner = CliRunner()


def _config(**overrides) -> Config:
    values = {
        "_env_file": None,
        "hibp_enabled": True,
        "hibp_api_key": None,
        "breachdirectory_enabled": False,
        "github_enabled": False,
        "brave_search_enabled": False,
        "virustotal_enabled": False,
    }
    values.update(overrides)
    return Config(**values)


def _investigation() -> Investigation:
    return Investigation(
        target_hash="a" * 64,
        target_masked="v*****@example.com",
        target_email="victim@example.com",
        profile=Profile.FULL,
        status=InvestigationStatus.COMPLETE,
        authorization_confirmed=True,
        completed_at=datetime.now(UTC),
    )


def test_scan_is_blocked_without_keys(monkeypatch, tmp_path):
    config = _config()
    monkeypatch.setattr(cli_module, "get_config", lambda: config)
    monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", tmp_path / "config" / ".env")

    result = runner.invoke(app, ["scan", "victim@example.com", "--no-confirm"])

    assert result.exit_code == 2
    assert "No API keys configured" in result.output
    assert "config keys status" in result.output
    assert "victim@example.com" not in result.output


def test_scan_proceeds_with_a_user_key(monkeypatch, tmp_path):
    config = _config(hibp_api_key="dummy-user-key")
    monkeypatch.setattr(cli_module, "get_config", lambda: config)
    monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", tmp_path / "config" / ".env")

    async def fake_run(email, profile, authorization_confirmed):
        assert email == "victim@example.com"
        assert authorization_confirmed is True
        return _investigation()

    monkeypatch.setattr(cli_module, "run_investigation_async", fake_run)

    result = runner.invoke(app, ["scan", "victim@example.com", "--no-confirm"])

    assert result.exit_code == 0
    assert "MailTrace Investigation Report" in result.output


def test_keys_status_never_prints_values(monkeypatch, tmp_path):
    secret = "my-super-secret-api-key"
    config = _config(hibp_api_key=secret)
    monkeypatch.setattr(cli_module, "get_config", lambda: config)
    monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", tmp_path / "config" / ".env")
    monkeypatch.setattr(configuration, "PROVIDERS_FILE", tmp_path / "providers.toml")
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    monkeypatch.delenv("MAILTRACE_HIBP_API_KEY", raising=False)

    result = runner.invoke(app, ["config", "keys", "status"])

    assert result.exit_code == 0
    assert fingerprint_secret(secret) in result.output
    assert secret not in result.output


def test_keys_migrate_cli(monkeypatch, tmp_path):
    destination = tmp_path / "config" / ".env"
    monkeypatch.setattr(configuration, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", destination)
    project = tmp_path / "project"
    project.mkdir()
    secret = "migrate-me-secret"
    (project / ".env").write_text(f"HIBP_API_KEY={secret}\n", encoding="utf-8")

    result = runner.invoke(app, ["config", "keys", "migrate", "--project-dir", str(project)])

    assert result.exit_code == 0
    assert secret not in result.output
    assert fingerprint_secret(secret) in result.output
    assert secret not in (project / ".env").read_text(encoding="utf-8")
    assert secret in destination.read_text(encoding="utf-8")
