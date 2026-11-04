"""Tests for BreachDirectory credential redaction."""

import json
from uuid import uuid4

from mailtrace.providers.breachdirectory import BreachDirectoryProvider
from mailtrace.schemas.finding import ProviderRun, Severity

PLAINTEXT_PASSWORD = "hunter2"
SHA1_HASH = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"


def _run() -> ProviderRun:
    return ProviderRun(investigation_id=uuid4(), provider="breachdirectory")


async def test_credentials_are_redacted():
    """Plaintext passwords and hashes never reach findings or evidence."""
    provider = BreachDirectoryProvider({})
    breach = {
        "sources": ["Example Breach"],
        "password": PLAINTEXT_PASSWORD,
        "sha1": SHA1_HASH,
        "email": "victim@example.com",
    }

    finding = await provider._process_breach("victim@example.com", breach, _run())

    assert finding is not None
    serialized = json.dumps(finding.raw_data, default=str)
    assert PLAINTEXT_PASSWORD not in serialized
    assert SHA1_HASH not in serialized

    assert finding.raw_data["credential_exposed"] is True
    assert finding.raw_data["password_exposed"] is True
    assert finding.raw_data["password_hash_exposed"] is True
    assert finding.raw_data["hash_type"] == "sha1"
    assert finding.severity == Severity.HIGH
    assert "redacted" in finding.evidence[0].notes
    assert PLAINTEXT_PASSWORD not in finding.evidence[0].notes
    assert SHA1_HASH not in finding.evidence[0].notes


async def test_account_only_breach_has_medium_severity():
    """A record without credential material is not overstated."""
    provider = BreachDirectoryProvider({})
    breach = {"sources": ["Example Breach"], "email": "victim@example.com"}

    finding = await provider._process_breach("victim@example.com", breach, _run())

    assert finding is not None
    assert finding.raw_data["credential_exposed"] is False
    assert finding.severity == Severity.MEDIUM
