"""Pydantic schemas for MailTrace data models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, HttpUrl


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(StrEnum):
    """Finding confidence levels."""

    VERIFIED = "verified"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class VerificationStatus(StrEnum):
    """Evidence verification status."""

    VERIFIED = "verified"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    PENDING = "pending"


class ProviderStatus(StrEnum):
    """Provider run status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED_WITH_FINDINGS = "completed_with_findings"
    COMPLETED_NO_MATCHES = "completed_no_matches"
    UNAUTHORIZED = "unauthorized"
    RATE_LIMITED = "rate_limited"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    CONFIGURATION_ERROR = "configuration_error"
    PARTIAL = "partial"
    FAILED = "failed"


class InvestigationStatus(StrEnum):
    """Overall investigation status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Profile(StrEnum):
    """Investigation profiles."""

    BREACH = "breach"
    PUBLIC = "public"
    DOMAIN = "domain"
    FULL = "full"


class EvidenceType(StrEnum):
    """Types of evidence."""

    BREACH_RECORD = "breach_record"
    SEARCH_RESULT = "search_result"
    REPOSITORY_METADATA = "repository_metadata"
    DNS_RECORD = "dns_record"
    PAGE_CONTENT = "page_content"
    API_RESPONSE = "api_response"


class FindingType(StrEnum):
    """Types of findings."""

    BREACH_EXPOSURE = "breach_exposure"
    PUBLIC_EXPOSURE = "public_exposure"
    REPOSITORY_EXPOSURE = "repository_exposure"
    DOMAIN_INTELLIGENCE = "domain_intelligence"
    METADATA_EXPOSURE = "metadata_exposure"


class CorrelationType(StrEnum):
    """Correlation relationship types."""

    SAME_SERVICE = "same_service"
    SAME_DOMAIN = "same_domain"
    SAME_PUBLIC_PAGE = "same_public_page"
    SAME_PROVIDER_RECORD = "same_provider_record"
    POSSIBLE_RELATED = "possible_related_observation"


class EvidenceRecord(BaseModel):
    """Normalized evidence record."""

    id: UUID = Field(default_factory=uuid4)
    finding_id: UUID | None = None
    provider: str
    source_url: HttpUrl | None = None
    source_reference: str | None = None
    evidence_type: EvidenceType
    verification_status: VerificationStatus = VerificationStatus.PENDING
    collected_at: datetime = Field(default_factory=utc_now)
    verified_at: datetime | None = None
    evidence_hash: str | None = None
    notes: str | None = None


class Finding(BaseModel):
    """Normalized finding from any provider."""

    id: UUID = Field(default_factory=uuid4)
    investigation_id: UUID
    finding_type: FindingType
    title: str
    service_name: str | None = None
    domain: str | None = None
    severity: Severity = Severity.INFORMATIONAL
    confidence: Confidence = Confidence.UNVERIFIED
    verification_status: VerificationStatus = VerificationStatus.PENDING
    first_observed_at: datetime | None = None
    collected_at: datetime = Field(default_factory=utc_now)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict, exclude=True)

    def add_evidence(self, evidence: EvidenceRecord) -> None:
        """Add evidence to finding."""
        self.evidence.append(evidence)


class ProviderRun(BaseModel):
    """Status and results of a single provider run."""

    id: UUID = Field(default_factory=uuid4)
    investigation_id: UUID
    provider: str
    status: ProviderStatus = ProviderStatus.PENDING
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    result_count: int = 0
    error_code: str | None = None
    error_message: str | None = None
    duration_ms: int | None = None


class Correlation(BaseModel):
    """Correlation between findings."""

    id: UUID = Field(default_factory=uuid4)
    investigation_id: UUID
    finding_a_id: UUID
    finding_b_id: UUID
    correlation_type: CorrelationType
    confidence: Confidence
    notes: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class Investigation(BaseModel):
    """Full investigation case."""

    id: UUID = Field(default_factory=uuid4)
    target_hash: str  # HMAC of email
    target_masked: str  # Display-safe masked email
    # Kept in memory only for immediate ``--show-target`` output. It is
    # deliberately excluded from serialization and never persisted.
    target_email: str | None = Field(default=None, exclude=True)
    profile: Profile
    status: InvestigationStatus = InvestigationStatus.PENDING
    authorization_confirmed: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    provider_runs: list[ProviderRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None


class InvestigationSummary(BaseModel):
    """Lightweight investigation summary for listings."""

    id: UUID
    target_masked: str
    profile: Profile
    status: InvestigationStatus
    created_at: datetime
    completed_at: datetime | None
    finding_count: int
    provider_count: int


class Snapshot(BaseModel):
    """Historical snapshot for comparison."""

    id: UUID = Field(default_factory=uuid4)
    investigation_id: UUID
    snapshot_date: datetime = Field(default_factory=utc_now)
    findings_hash: str  # Hash of finding IDs for change detection
    finding_ids: list[UUID] = Field(default_factory=list)


class AuditEvent(BaseModel):
    """Local audit trail event."""

    id: UUID = Field(default_factory=uuid4)
    investigation_id: UUID
    event_type: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ExportFormat(StrEnum):
    """Report export formats."""

    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    TERMINAL = "terminal"


class ReportOptions(BaseModel):
    """Options for report generation."""

    format: ExportFormat = ExportFormat.TERMINAL
    output_path: str | None = None
    include_evidence: bool = True
    include_raw: bool = False
    mask_target: bool = True
    template: str | None = None
