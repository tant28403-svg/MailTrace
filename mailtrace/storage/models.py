"""Database models and setup for MailTrace."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from mailtrace.schemas.finding import (
    Confidence,
    CorrelationType,
    EvidenceType,
    FindingType,
    InvestigationStatus,
    Profile,
    ProviderStatus,
    Severity,
    VerificationStatus,
    utc_now,
)


class Base(DeclarativeBase):
    """Base class for all models."""



class InvestigationModel(Base):
    """Investigation case model."""

    __tablename__ = "investigations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_masked: Mapped[str] = mapped_column(String(255), nullable=False)
    profile: Mapped[Profile] = mapped_column(Enum(Profile), nullable=False)
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus), default=InvestigationStatus.PENDING, nullable=False
    )
    authorization_confirmed: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tags: Mapped[list[str]] = mapped_column(SQLiteJSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    provider_runs: Mapped[list["ProviderRunModel"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    findings: Mapped[list["FindingModel"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    snapshots: Mapped[list["SnapshotModel"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list["AuditEventModel"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    correlations: Mapped[list["CorrelationModel"]] = relationship(
        back_populates="investigation"
    )

    __table_args__ = (
        Index("ix_investigations_created_at", "created_at"),
    )


class ProviderRunModel(Base):
    """Provider run status model."""

    __tablename__ = "provider_runs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[ProviderStatus] = mapped_column(
        Enum(ProviderStatus), default=ProviderStatus.PENDING, nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Relationship
    investigation: Mapped["InvestigationModel"] = relationship(back_populates="provider_runs")

    __table_args__ = (
        Index("ix_provider_runs_investigation_provider", "investigation_id", "provider"),
        UniqueConstraint("investigation_id", "provider", name="uq_investigation_provider"),
    )


class FindingModel(Base):
    """Finding model."""

    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_type: Mapped[FindingType] = mapped_column(Enum(FindingType), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity), default=Severity.INFORMATIONAL, nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        Enum(Confidence), default=Confidence.UNVERIFIED, nullable=False
    )
    verification_status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus), default=VerificationStatus.PENDING, nullable=False
    )
    first_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    raw_data: Mapped[dict[str, Any]] = mapped_column(SQLiteJSON, default=dict)

    # Relationships
    investigation: Mapped["InvestigationModel"] = relationship(back_populates="findings")
    evidence: Mapped[list["EvidenceModel"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    breach_record: Mapped["BreachRecordModel | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
    correlations_a: Mapped[list["CorrelationModel"]] = relationship(
        foreign_keys="CorrelationModel.finding_a_id",
        back_populates="finding_a",
        cascade="all, delete-orphan",
    )
    correlations_b: Mapped[list["CorrelationModel"]] = relationship(
        foreign_keys="CorrelationModel.finding_b_id",
        back_populates="finding_b",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_findings_investigation_type", "investigation_id", "finding_type"),
        Index("ix_findings_severity", "severity"),
    )


class EvidenceModel(Base):
    """Evidence model."""

    __tablename__ = "evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence_type: Mapped[EvidenceType] = mapped_column(Enum(EvidenceType), nullable=False)
    evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus), default=VerificationStatus.PENDING, nullable=False
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationship
    finding: Mapped["FindingModel"] = relationship(back_populates="evidence")

    __table_args__ = (
        Index("ix_evidence_finding", "finding_id"),
        Index("ix_evidence_provider", "provider"),
    )


class BreachRecordModel(Base):
    """Breach-specific details model."""

    __tablename__ = "breach_records"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    breach_name: Mapped[str] = mapped_column(String(255), nullable=False)
    breach_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    breach_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    discovery_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    data_classes: Mapped[list[str]] = mapped_column(SQLiteJSON, default=list)
    provider_status: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Relationship
    finding: Mapped["FindingModel"] = relationship(back_populates="breach_record")


class CorrelationModel(Base):
    """Correlation between findings model."""

    __tablename__ = "correlations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_a_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    finding_b_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    correlation_type: Mapped[CorrelationType] = mapped_column(Enum(CorrelationType), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    # Relationships
    investigation: Mapped["InvestigationModel"] = relationship(back_populates="correlations")
    finding_a: Mapped["FindingModel"] = relationship(
        foreign_keys=[finding_a_id], back_populates="correlations_a"
    )
    finding_b: Mapped["FindingModel"] = relationship(
        foreign_keys=[finding_b_id], back_populates="correlations_b"
    )

    __table_args__ = (
        Index("ix_correlations_investigation", "investigation_id"),
        Index("ix_correlations_findings", "finding_a_id", "finding_b_id"),
        UniqueConstraint("finding_a_id", "finding_b_id", "correlation_type", name="uq_correlation"),
    )


class SnapshotModel(Base):
    """Historical snapshot model."""

    __tablename__ = "snapshots"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    snapshot_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    findings_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_ids: Mapped[list[str]] = mapped_column(SQLiteJSON, default=list)

    # Relationship
    investigation: Mapped["InvestigationModel"] = relationship(back_populates="snapshots")

    __table_args__ = (
        Index("ix_snapshots_investigation_date", "investigation_id", "snapshot_date"),
    )


class AuditEventModel(Base):
    """Audit event model."""

    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(SQLiteJSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    # Relationship
    investigation: Mapped["InvestigationModel"] = relationship(back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_events_investigation", "investigation_id"),
        Index("ix_audit_events_type", "event_type"),
    )
