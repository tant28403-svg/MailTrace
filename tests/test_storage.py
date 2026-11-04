"""Tests for database bootstrap and repositories."""

from uuid import uuid4

from sqlalchemy import text

from mailtrace.schemas.finding import (
    Confidence,
    EvidenceType,
    FindingType,
    Investigation,
    InvestigationStatus,
    Profile,
    ProviderStatus,
    Severity,
    VerificationStatus,
)
from mailtrace.storage.database import DatabaseManager
from mailtrace.storage.models import (
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ProviderRunModel,
)
from mailtrace.storage.repositories import InvestigationRepository

EXPECTED_TABLES = {
    "audit_events",
    "breach_records",
    "correlations",
    "evidence",
    "findings",
    "investigations",
    "provider_runs",
    "snapshots",
}


async def test_initialize_creates_all_tables(tmp_path):
    """A fresh database is bootstrapped without a separate migration step."""
    manager = DatabaseManager(data_dir=tmp_path)
    await manager.initialize()
    try:
        async with manager.session() as session:
            result = await session.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'table'")
            )
            tables = {row[0] for row in result}
    finally:
        await manager.close()

    assert tables >= EXPECTED_TABLES


async def test_initialize_is_idempotent(tmp_path):
    """Calling initialize twice keeps the existing schema and data."""
    manager = DatabaseManager(data_dir=tmp_path)
    await manager.initialize()
    try:
        await manager.initialize()
        async with manager.session() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM investigations"))
            assert result.scalar_one() == 0
    finally:
        await manager.close()


async def test_repository_round_trip(tmp_path):
    """Investigations, provider runs, findings and evidence survive a round trip."""
    manager = DatabaseManager(data_dir=tmp_path)
    await manager.initialize()
    investigation_id = uuid4()
    try:
        async with manager.session() as session:
            session.add(
                InvestigationModel(
                    id=investigation_id,
                    target_hash="a" * 64,
                    target_masked="v*****@example.com",
                    profile=Profile.FULL,
                    status=InvestigationStatus.COMPLETE,
                    authorization_confirmed=True,
                )
            )
            session.add(
                ProviderRunModel(
                    id=uuid4(),
                    investigation_id=investigation_id,
                    provider="dns",
                    status=ProviderStatus.COMPLETED_WITH_FINDINGS,
                    result_count=1,
                )
            )
            finding_id = uuid4()
            session.add(
                FindingModel(
                    id=finding_id,
                    investigation_id=investigation_id,
                    finding_type=FindingType.DOMAIN_INTELLIGENCE,
                    title="MX records",
                    service_name="DNS",
                    domain="example.com",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.VERIFIED,
                    verification_status=VerificationStatus.VERIFIED,
                )
            )
            session.add(
                EvidenceModel(
                    id=uuid4(),
                    finding_id=finding_id,
                    provider="dns",
                    source_reference="MX:example.com",
                    evidence_type=EvidenceType.DNS_RECORD,
                    verification_status=VerificationStatus.VERIFIED,
                )
            )

        async with manager.session() as session:
            schema = await InvestigationRepository(session).get_schema(investigation_id)

        assert schema is not None
        assert isinstance(schema, Investigation)
        assert schema.target_masked == "v*****@example.com"
        assert len(schema.provider_runs) == 1
        assert len(schema.findings) == 1
        assert len(schema.findings[0].evidence) == 1
        assert schema.findings[0].evidence[0].source_reference == "MX:example.com"
    finally:
        await manager.close()
