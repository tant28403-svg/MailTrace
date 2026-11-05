"""Tests for orchestrator processing, persistence and status derivation."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from mailtrace.core import orchestrator as orchestrator_module
from mailtrace.core.configuration import Config, GeneralConfig
from mailtrace.core.orchestrator import Orchestrator
from mailtrace.providers.base import BaseProvider
from mailtrace.schemas.finding import (
    Confidence,
    CorrelationType,
    EvidenceRecord,
    EvidenceType,
    Finding,
    FindingType,
    Investigation,
    InvestigationStatus,
    Profile,
    ProviderRun,
    ProviderStatus,
    Severity,
    VerificationStatus,
)
from mailtrace.storage import close_database, get_database_manager, init_database
from mailtrace.storage.models import SnapshotModel
from mailtrace.storage.repositories import (
    EvidenceRepository,
    FindingRepository,
    ProviderRunRepository,
)


class FakeDNSProvider(BaseProvider):
    """Provider that returns duplicate findings with distinct evidence."""

    name = "dns"
    display_name = "Fake DNS"
    requires_auth = False

    def _get_default_headers(self) -> dict[str, str]:
        return {}

    def _get_base_url(self) -> str:
        return ""

    async def health_check(self) -> dict[str, object]:
        return {"healthy": True, "message": "ok", "details": {}}

    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        findings = []
        for index in (1, 2):
            finding = self._create_finding(
                investigation_id=run.investigation_id,
                finding_type=FindingType.DOMAIN_INTELLIGENCE,
                title="MX records for example.com",
                service_name="DNS",
                domain="example.com",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.VERIFIED,
                verification_status=VerificationStatus.VERIFIED,
                raw_data={"record_type": "MX"},
            )
            finding.add_evidence(
                EvidenceRecord(
                    id=uuid4(),
                    provider=self.name,
                    source_reference=f"MX:example.com:{index}",
                    evidence_type=EvidenceType.DNS_RECORD,
                    verification_status=VerificationStatus.VERIFIED,
                    collected_at=datetime.now(UTC),
                    evidence_hash=f"hash-{index}",
                )
            )
            findings.append(finding)
        return findings


def _test_config(tmp_path) -> Config:
    return Config(
        general=GeneralConfig(data_dir=tmp_path, require_keys=False),
        _env_file=None,
        hibp_api_key=None,
        breachdirectory_api_key=None,
        github_token=None,
        brave_search_api_key=None,
        virustotal_api_key=None,
    )


def _orchestrator(tmp_path, monkeypatch) -> Orchestrator:
    config = _test_config(tmp_path)
    monkeypatch.setattr(orchestrator_module, "get_config", lambda: config)
    return Orchestrator()


def _finding(
    investigation: Investigation,
    *,
    finding_type: FindingType = FindingType.BREACH_EXPOSURE,
    service_name: str = "Example",
    title: str = "Example finding",
    raw_data: dict | None = None,
    confidence: Confidence = Confidence.VERIFIED,
) -> Finding:
    return Finding(
        id=uuid4(),
        investigation_id=investigation.id,
        finding_type=finding_type,
        title=title,
        service_name=service_name,
        domain="example.com",
        severity=Severity.HIGH,
        confidence=confidence,
        verification_status=VerificationStatus.VERIFIED,
        raw_data=raw_data or {"breach_name": "Example"},
    )


def test_process_findings_deduplicates_and_merges_evidence(tmp_path, monkeypatch):
    """Repeated provider results become one finding with all evidence."""
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    investigation = Investigation(
        target_hash="a" * 64,
        target_masked="v*****@example.com",
        profile=Profile.FULL,
    )
    first = _finding(investigation)
    second = _finding(investigation)
    for finding, reference in ((first, "breach-a"), (second, "breach-b")):
        finding.add_evidence(
            EvidenceRecord(
                id=uuid4(),
                provider="hibp",
                source_reference=reference,
                evidence_type=EvidenceType.BREACH_RECORD,
                verification_status=VerificationStatus.VERIFIED,
                collected_at=datetime.now(UTC),
            )
        )

    investigation.findings = [first, second]
    orchestrator._process_findings(investigation)

    assert len(investigation.findings) == 1
    assert len(investigation.findings[0].evidence) == 2


def test_process_findings_correlates_shared_services(tmp_path, monkeypatch):
    """Findings from the same service are correlated."""
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    investigation = Investigation(
        target_hash="b" * 64,
        target_masked="v*****@example.com",
        profile=Profile.FULL,
    )
    breach = _finding(investigation, service_name="HIBP")
    exposure = _finding(
        investigation,
        finding_type=FindingType.PUBLIC_EXPOSURE,
        service_name="HIBP",
        raw_data={"url": "https://example.com/post"},
    )
    investigation.findings = [breach, exposure]

    orchestrator._process_findings(investigation)

    assert len(investigation.correlations) == 1
    assert investigation.correlations[0].correlation_type == CorrelationType.SAME_SERVICE


def test_determine_status():
    """Investigation status reflects provider outcomes."""
    completed = ProviderRun(
        investigation_id=uuid4(),
        provider="dns",
        status=ProviderStatus.COMPLETED_WITH_FINDINGS,
    )
    empty = ProviderRun(
        investigation_id=uuid4(),
        provider="emailrep",
        status=ProviderStatus.COMPLETED_NO_MATCHES,
    )
    failed = ProviderRun(
        investigation_id=uuid4(),
        provider="hibp",
        status=ProviderStatus.FAILED,
    )

    assert Orchestrator._determine_status([completed, empty]) == InvestigationStatus.COMPLETE
    assert Orchestrator._determine_status([completed, failed]) == InvestigationStatus.PARTIAL
    assert Orchestrator._determine_status([failed]) == InvestigationStatus.FAILED
    assert Orchestrator._determine_status([]) == InvestigationStatus.FAILED


async def test_orchestrator_rejects_keyless_runs(tmp_path, monkeypatch):
    """Direct Python callers cannot bypass the bring-your-own-key gate."""
    config = _test_config(tmp_path)
    config.general.require_keys = True
    monkeypatch.setattr(orchestrator_module, "get_config", lambda: config)
    orchestrator = Orchestrator()

    with pytest.raises(RuntimeError, match="No API keys configured"):
        await orchestrator.run_investigation(
            "victim@example.com",
            profile=Profile.DOMAIN,
            authorization_confirmed=True,
        )


async def test_investigation_persistence_uses_processed_findings(tmp_path, monkeypatch):
    """Persisted findings reflect deduplication and carry their evidence."""
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    await init_database(data_dir=tmp_path)
    orchestrator._db_manager = get_database_manager()
    orchestrator._providers = {"dns": FakeDNSProvider()}

    try:
        investigation = await orchestrator.run_investigation(
            "victim@example.com",
            profile=Profile.DOMAIN,
            authorization_confirmed=True,
        )

        assert investigation.status == InvestigationStatus.COMPLETE
        assert len(investigation.findings) == 1

        async with get_database_manager().session() as session:
            runs = await ProviderRunRepository(session).list_by_investigation(investigation.id)
            findings = await FindingRepository(session).list_by_investigation(investigation.id)
            assert len(runs) == 1
            assert runs[0].status == ProviderStatus.COMPLETED_WITH_FINDINGS
            assert len(findings) == 1

            evidence = await EvidenceRepository(session).get_by_finding(findings[0].id)
            assert len(evidence) == 2

            snapshot_count = await session.execute(
                select(func.count())
                .select_from(SnapshotModel)
                .where(SnapshotModel.investigation_id == investigation.id)
            )
            assert snapshot_count.scalar_one() == 1
    finally:
        await close_database()
