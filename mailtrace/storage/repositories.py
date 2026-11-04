"""Repository classes for data access."""

from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from mailtrace.schemas.finding import (
    Confidence,
    Investigation,
    InvestigationStatus,
    ProviderStatus,
    VerificationStatus,
)
from mailtrace.storage.mappers import investigation_model_to_schema
from mailtrace.storage.models import (
    AuditEventModel,
    CorrelationModel,
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ProviderRunModel,
    SnapshotModel,
)


class InvestigationRepository:
    """Repository for investigation operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, investigation: InvestigationModel) -> InvestigationModel:
        """Create a new investigation."""
        self.session.add(investigation)
        await self.session.flush()
        return investigation

    async def get(self, investigation_id: UUID) -> InvestigationModel | None:
        """Get investigation by ID."""
        result = await self.session.execute(
            select(InvestigationModel).where(InvestigationModel.id == investigation_id)
        )
        return result.scalar_one_or_none()

    async def get_with_relations(self, investigation_id: UUID) -> InvestigationModel | None:
        """Get investigation with all relations loaded."""
        from sqlalchemy.orm import selectinload

        result = await self.session.execute(
            select(InvestigationModel)
            .options(
                selectinload(InvestigationModel.provider_runs),
                selectinload(InvestigationModel.findings).selectinload(FindingModel.evidence),
                selectinload(InvestigationModel.findings).selectinload(FindingModel.breach_record),
                selectinload(InvestigationModel.correlations),
            )
            .where(InvestigationModel.id == investigation_id)
        )
        return result.scalar_one_or_none()

    async def get_schema(self, investigation_id: UUID) -> Investigation | None:
        """Get an investigation as a Pydantic schema with relations loaded."""
        model = await self.get_with_relations(investigation_id)
        if model is None:
            return None
        return investigation_model_to_schema(model)

    async def list(
        self, limit: int = 20, offset: int = 0, target_hash: str | None = None
    ) -> Sequence[InvestigationModel]:
        """List investigations."""
        from sqlalchemy.orm import selectinload

        query = (
            select(InvestigationModel)
            .options(selectinload(InvestigationModel.provider_runs))
            .order_by(desc(InvestigationModel.created_at))
        )
        if target_hash:
            query = query.where(InvestigationModel.target_hash == target_hash)
        query = query.limit(limit).offset(offset)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def count(self, target_hash: str | None = None) -> int:
        """Count investigations."""
        query = select(func.count(InvestigationModel.id))
        if target_hash:
            query = query.where(InvestigationModel.target_hash == target_hash)
        result = await self.session.execute(query)
        return result.scalar_one()

    async def update_status(
        self,
        investigation_id: UUID,
        status: InvestigationStatus,
        completed_at: datetime | None = None,
    ) -> None:
        """Update investigation status."""
        investigation = await self.get(investigation_id)
        if investigation:
            investigation.status = status
            if completed_at:
                investigation.completed_at = completed_at
            await self.session.flush()

    async def add_tags(self, investigation_id: UUID, tags: Sequence[str]) -> None:
        """Add tags to investigation."""
        investigation = await self.get(investigation_id)
        if investigation:
            existing = set(investigation.tags or [])
            existing.update(tags)
            investigation.tags = list(existing)
            await self.session.flush()

    async def delete(self, investigation_id: UUID) -> bool:
        """Delete investigation and all related data."""
        investigation = await self.get(investigation_id)
        if investigation:
            await self.session.delete(investigation)
            await self.session.flush()
            return True
        return False


class ProviderRunRepository:
    """Repository for provider run operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, provider_run: ProviderRunModel) -> ProviderRunModel:
        """Create a new provider run."""
        self.session.add(provider_run)
        await self.session.flush()
        return provider_run

    async def get(self, run_id: UUID) -> ProviderRunModel | None:
        """Get provider run by ID."""
        result = await self.session.execute(
            select(ProviderRunModel).where(ProviderRunModel.id == run_id)
        )
        return result.scalar_one_or_none()

    async def get_by_investigation_and_provider(
        self, investigation_id: UUID, provider: str
    ) -> ProviderRunModel | None:
        """Get provider run for investigation and provider."""
        result = await self.session.execute(
            select(ProviderRunModel).where(
                ProviderRunModel.investigation_id == investigation_id,
                ProviderRunModel.provider == provider,
            )
        )
        return result.scalar_one_or_none()

    async def list_by_investigation(self, investigation_id: UUID) -> Sequence[ProviderRunModel]:
        """List all provider runs for an investigation."""
        result = await self.session.execute(
            select(ProviderRunModel)
            .where(ProviderRunModel.investigation_id == investigation_id)
            .order_by(ProviderRunModel.started_at)
        )
        return result.scalars().all()

    async def update_status(
        self,
        run_id: UUID,
        status: ProviderStatus,
        finished_at: datetime | None = None,
        result_count: int = 0,
        error_code: str | None = None,
        error_message: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        """Update provider run status."""
        run = await self.get(run_id)
        if run:
            run.status = status
            if finished_at:
                run.finished_at = finished_at
            run.result_count = result_count
            if error_code:
                run.error_code = error_code
            if error_message:
                run.error_message = error_message
            if duration_ms is not None:
                run.duration_ms = duration_ms
            await self.session.flush()


class FindingRepository:
    """Repository for finding operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, finding: FindingModel) -> FindingModel:
        """Create a new finding."""
        self.session.add(finding)
        await self.session.flush()
        return finding

    async def bulk_create(self, findings: list[FindingModel]) -> list[FindingModel]:
        """Create multiple findings."""
        self.session.add_all(findings)
        await self.session.flush()
        return findings

    async def get(self, finding_id: UUID) -> FindingModel | None:
        """Get finding by ID."""
        result = await self.session.execute(
            select(FindingModel).where(FindingModel.id == finding_id)
        )
        return result.scalar_one_or_none()

    async def get_with_evidence(self, finding_id: UUID) -> FindingModel | None:
        """Get finding with evidence loaded."""
        from sqlalchemy.orm import selectinload

        result = await self.session.execute(
            select(FindingModel)
            .options(
                selectinload(FindingModel.evidence),
                selectinload(FindingModel.breach_record),
            )
            .where(FindingModel.id == finding_id)
        )
        return result.scalar_one_or_none()

    async def list_by_investigation(
        self,
        investigation_id: UUID,
        finding_type: str | None = None,
        severity: str | None = None,
    ) -> Sequence[FindingModel]:
        """List findings for an investigation."""
        query = select(FindingModel).where(FindingModel.investigation_id == investigation_id)
        if finding_type:
            query = query.where(FindingModel.finding_type == finding_type)
        if severity:
            query = query.where(FindingModel.severity == severity)
        query = query.order_by(FindingModel.collected_at.desc())
        result = await self.session.execute(query)
        return result.scalars().all()

    async def count_by_investigation(self, investigation_id: UUID) -> int:
        """Count findings for an investigation."""
        result = await self.session.execute(
            select(func.count(FindingModel.id)).where(
                FindingModel.investigation_id == investigation_id
            )
        )
        return result.scalar_one()

    async def get_by_source_reference(
        self, investigation_id: UUID, provider: str, source_reference: str
    ) -> FindingModel | None:
        """Find finding by provider and source reference."""
        from sqlalchemy.orm import joinedload

        result = await self.session.execute(
            select(FindingModel)
            .options(joinedload(FindingModel.evidence))
            .where(
                FindingModel.investigation_id == investigation_id,
                FindingModel.evidence.any(
                    (EvidenceModel.provider == provider)
                    & (EvidenceModel.source_reference == source_reference)
                ),
            )
        )
        return result.scalar_one_or_none()

    async def update_verification(
        self,
        finding_id: UUID,
        verification_status: VerificationStatus,
        confidence: Confidence | None = None,
    ) -> None:
        """Update finding verification status."""
        finding = await self.get(finding_id)
        if finding:
            finding.verification_status = verification_status
            if confidence:
                finding.confidence = confidence
            await self.session.flush()


class EvidenceRepository:
    """Repository for evidence operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, evidence: EvidenceModel) -> EvidenceModel:
        """Create new evidence."""
        self.session.add(evidence)
        await self.session.flush()
        return evidence

    async def bulk_create(self, evidence_list: list[EvidenceModel]) -> list[EvidenceModel]:
        """Create multiple evidence records."""
        self.session.add_all(evidence_list)
        await self.session.flush()
        return evidence_list

    async def get_by_finding(self, finding_id: UUID) -> Sequence[EvidenceModel]:
        """Get all evidence for a finding."""
        result = await self.session.execute(
            select(EvidenceModel)
            .where(EvidenceModel.finding_id == finding_id)
            .order_by(EvidenceModel.collected_at)
        )
        return result.scalars().all()

    async def update_verification(
        self,
        evidence_id: UUID,
        verification_status: VerificationStatus,
        verified_at: datetime | None = None,
        evidence_hash: str | None = None,
    ) -> None:
        """Update evidence verification status."""
        result = await self.session.execute(
            select(EvidenceModel).where(EvidenceModel.id == evidence_id)
        )
        evidence = result.scalar_one_or_none()
        if evidence:
            evidence.verification_status = verification_status
            if verified_at:
                evidence.verified_at = verified_at
            if evidence_hash:
                evidence.evidence_hash = evidence_hash
            await self.session.flush()


class CorrelationRepository:
    """Repository for correlation operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, correlation: CorrelationModel) -> CorrelationModel:
        """Create a new correlation."""
        self.session.add(correlation)
        await self.session.flush()
        return correlation

    async def bulk_create(
        self, correlations: list[CorrelationModel]
    ) -> list[CorrelationModel]:
        """Create multiple correlations."""
        self.session.add_all(correlations)
        await self.session.flush()
        return correlations

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> Sequence[CorrelationModel]:
        """List correlations for an investigation."""
        result = await self.session.execute(
            select(CorrelationModel).where(
                CorrelationModel.investigation_id == investigation_id
            )
        )
        return result.scalars().all()


class SnapshotRepository:
    """Repository for snapshot operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, snapshot: SnapshotModel) -> SnapshotModel:
        """Create a new snapshot."""
        self.session.add(snapshot)
        await self.session.flush()
        return snapshot

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> Sequence[SnapshotModel]:
        """List snapshots for an investigation."""
        result = await self.session.execute(
            select(SnapshotModel)
            .where(SnapshotModel.investigation_id == investigation_id)
            .order_by(SnapshotModel.snapshot_date.desc())
        )
        return result.scalars().all()

    async def get_latest(self, investigation_id: UUID) -> SnapshotModel | None:
        """Get latest snapshot for an investigation."""
        result = await self.session.execute(
            select(SnapshotModel)
            .where(SnapshotModel.investigation_id == investigation_id)
            .order_by(SnapshotModel.snapshot_date.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


class AuditRepository:
    """Repository for audit event operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event: AuditEventModel) -> AuditEventModel:
        """Create an audit event."""
        self.session.add(event)
        await self.session.flush()
        return event

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> Sequence[AuditEventModel]:
        """List audit events for an investigation."""
        result = await self.session.execute(
            select(AuditEventModel)
            .where(AuditEventModel.investigation_id == investigation_id)
            .order_by(AuditEventModel.created_at.desc())
        )
        return result.scalars().all()
