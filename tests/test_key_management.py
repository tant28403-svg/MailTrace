"""Tests for credential status and project-to-user key migration."""

from mailtrace.core import configuration
from mailtrace.core.configuration import (
    Config,
    find_project_env_secrets,
    fingerprint_secret,
    iter_configured_keys,
    migrate_project_keys,
)

SECRET = "super-secret-value-123"


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(configuration, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", tmp_path / "config" / ".env")
    monkeypatch.setattr(configuration, "PROVIDERS_FILE", tmp_path / "providers.toml")
    for name in (
        "HIBP_API_KEY",
        "MAILTRACE_HIBP_API_KEY",
        "GITHUB_TOKEN",
        "MAILTRACE_GITHUB_TOKEN",
        "MAILTRACE_USE_PROJECT_ENV",
    ):
        monkeypatch.delenv(name, raising=False)


def test_fingerprint_is_stable_and_hides_value():
    first = fingerprint_secret(SECRET)
    second = fingerprint_secret(SECRET)

    assert first == second
    assert len(first) == 10
    assert SECRET not in first
    assert first != fingerprint_secret("different-secret")


def test_status_reports_process_environment(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("HIBP_API_KEY", SECRET)

    status = {item.provider: item for item in iter_configured_keys(Config(_env_file=None))}["hibp"]

    assert status.configured is True
    assert status.source == "process environment"
    assert status.fingerprint == fingerprint_secret(SECRET)
    assert SECRET not in repr(status)


def test_status_reports_user_env(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    user_env = tmp_path / "config" / ".env"
    user_env.parent.mkdir()
    user_env.write_text(f"HIBP_API_KEY={SECRET}\n", encoding="utf-8")

    status = {item.provider: item for item in iter_configured_keys(Config())}["hibp"]

    assert status.configured is True
    assert status.source == "user .env"
    assert status.fingerprint == fingerprint_secret(SECRET)


def test_migrate_moves_credentials_and_keeps_other_settings(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    source = project / ".env"
    source.write_text(
        "# project settings\n"
        f"HIBP_API_KEY={SECRET}\n"
        "BREACHDIRECTORY_ENABLED=true\n"
        "CUSTOM_SETTING=keep-me\n",
        encoding="utf-8",
    )

    result = migrate_project_keys(project)

    destination = tmp_path / "config" / ".env"
    assert result.moved == ["HIBP_API_KEY"]
    assert result.fingerprints["HIBP_API_KEY"] == fingerprint_secret(SECRET)
    assert SECRET not in repr(result)
    assert destination.read_text(encoding="utf-8").count(SECRET) == 1
    remaining = source.read_text(encoding="utf-8")
    assert SECRET not in remaining
    assert "BREACHDIRECTORY_ENABLED=true" in remaining
    assert "CUSTOM_SETTING=keep-me" in remaining
    assert result.unrecognized == ["CUSTOM_SETTING"]
    assert result.leftover == ["BREACHDIRECTORY_ENABLED"]
    assert not list(project.glob(".env.backup-*"))

    # Running again is a no-op for credentials.
    second = migrate_project_keys(project)
    assert second.moved == []
    assert second.destination_overrides == []


def test_migrate_prefers_existing_user_value_and_creates_backup(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    destination = tmp_path / "config" / ".env"
    destination.parent.mkdir()
    destination.write_text("HIBP_API_KEY=existing-user-key\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    source = project / ".env"
    source.write_text(f"HIBP_API_KEY={SECRET}\n", encoding="utf-8")

    result = migrate_project_keys(project)

    assert result.destination_overrides == ["HIBP_API_KEY"]
    assert destination.read_text(encoding="utf-8").count("existing-user-key") == 1
    assert SECRET not in destination.read_text(encoding="utf-8")
    assert SECRET not in source.read_text(encoding="utf-8")
    assert result.backup is not None
    assert result.backup.parent == destination.parent
    assert "existing-user-key" in result.backup.read_text(encoding="utf-8")


def test_migrate_all_moves_recognized_settings(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    source = project / ".env"
    source.write_text(
        "BREACHDIRECTORY_ENABLED=true\nMAILTRACE_GENERAL_THEME=light\nUNKNOWN=leave-me\n",
        encoding="utf-8",
    )

    result = migrate_project_keys(project, include_all=True)

    destination = tmp_path / "config" / ".env"
    content = destination.read_text(encoding="utf-8")
    assert "BREACHDIRECTORY_ENABLED=true" in content
    assert "MAILTRACE_GENERAL_THEME=light" in content
    assert "UNKNOWN=leave-me" not in content
    assert result.moved == [
        "BREACHDIRECTORY_ENABLED",
        "MAILTRACE_GENERAL_THEME",
    ]
    assert result.unrecognized == ["UNKNOWN"]
    assert result.leftover == []


def test_bom_prefixed_project_env_is_detected_and_migrated(monkeypatch, tmp_path):
    """Windows editors may save .env with a UTF-8 BOM; keys must still be found."""
    _isolate(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    source = project / ".env"
    source.write_text(f"HIBP_API_KEY={SECRET}\n", encoding="utf-8-sig")

    assert find_project_env_secrets(project) == {
        "HIBP_API_KEY": fingerprint_secret(SECRET)
    }

    result = migrate_project_keys(project)

    assert result.moved == ["HIBP_API_KEY"]
    assert result.fingerprints["HIBP_API_KEY"] == fingerprint_secret(SECRET)
    assert SECRET in (tmp_path / "config" / ".env").read_text(encoding="utf-8")
    assert SECRET not in source.read_text(encoding="utf-8-sig")
