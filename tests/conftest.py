"""Shared pytest configuration.

Tests must never read the developer's real ``~/.config/mailtrace/.env`` or
process-level MailTrace variables.  Without this isolation a customized local
configuration could make default-value assertions fail, and a real key could
silently satisfy the scan gate.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from mailtrace.core import configuration


@pytest.fixture(autouse=True)
def isolate_mailtrace_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[None]:
    """Point configuration at an empty per-test directory and clear env vars."""
    config_dir = tmp_path_factory.mktemp("mailtrace-config")
    monkeypatch.setattr(configuration, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(configuration, "SETTINGS_ENV_FILE", config_dir / ".env")
    monkeypatch.setattr(configuration, "PROVIDERS_FILE", config_dir / "providers.toml")
    monkeypatch.setattr(configuration, "_config", None)

    blocked = configuration.SECRET_ENV_NAMES | configuration.RECOGNIZED_SETTING_NAMES
    for name in list(os.environ):
        upper = name.upper()
        if upper in blocked or upper.startswith("MAILTRACE_"):
            monkeypatch.delenv(name, raising=False)

    yield
