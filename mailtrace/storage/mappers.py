"""Conversions between SQLAlchemy models and Pydantic schemas."""

from __future__ import annotations

from pydantic import HttpUrl

from mailtrace.schemas.finding import (
    Correlation,
    EvidenceRecord,
    Finding,
    Investigation,
    ProviderRun,
)
from mailtrace.storage.models import (
    CorrelationModel,
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ProviderRunModel,
)


def _source_url(value: str | None) -> HttpUrl | None:
    """Only pass values that look like HTTP(S) URLs to Pydantic."""
    if value and value.startswith(("http://", "https://")):
        return HttpUrl(value)
    return None


def evidence_model_to_schema(model: EvidenceModel) -> EvidenceRecord:
    """Convert an evidence row to its schema representation."""
    return EvidenceRecord(
        id=model.id,
        finding_id=model.finding_id,
        provider=model.provider,
        source_url=_source_url(model.source_url),
        source_reference=model.source_reference,
        evidence_type=model.evidence_type,
        verification_status=model.verification_status,
        collected_at=model.collected_at,
        verified_at=model.verified_at,
        evidence_hash=model.evidence_hash,
        notes=model.notes,
    )


def finding_model_to_schema(model: FindingModel) -> Finding:
    """Convert a finding row (with evidence loaded) to its schema representation."""
    return Finding(
        id=model.id,
        investigation_id=model.investigation_id,
        finding_type=model.finding_type,
        title=model.title,
        service_name=model.service_name,
        domain=model.domain,
        severity=model.severity,
        confidence=model.confidence,
        verification_status=model.verification_status,
        first_observed_at=model.first_observed_at,
        collected_at=model.collected_at,
        evidence=[evidence_model_to_schema(item) for item in model.evidence],
        raw_data=model.raw_data or {},
    )


def provider_run_model_to_schema(model: ProviderRunModel) -> ProviderRun:
    """Convert a provider run row to its schema representation."""
    return ProviderRun(
        id=model.id,
        investigation_id=model.investigation_id,
        provider=model.provider,
        status=model.status,
        started_at=model.started_at,
        finished_at=model.finished_at,
        result_count=model.result_count,
        error_code=model.error_code,
        error_message=model.error_message,
        duration_ms=model.duration_ms,
    )


def correlation_model_to_schema(model: CorrelationModel) -> Correlation:
    """Convert a correlation row to its schema representation."""
    return Correlation(
        id=model.id,
        investigation_id=model.investigation_id,
        finding_a_id=model.finding_a_id,
        finding_b_id=model.finding_b_id,
        correlation_type=model.correlation_type,
        confidence=model.confidence,
        notes=model.notes,
        created_at=model.created_at,
    )


def investigation_model_to_schema(model: InvestigationModel) -> Investigation:
    """Convert a fully loaded investigation row to the domain schema."""
    return Investigation(
        id=model.id,
        target_hash=model.target_hash,
        target_masked=model.target_masked,
        profile=model.profile,
        status=model.status,
        authorization_confirmed=model.authorization_confirmed,
        created_at=model.created_at,
        completed_at=model.completed_at,
        tags=list(model.tags or []),
        notes=model.notes,
        provider_runs=[provider_run_model_to_schema(run) for run in model.provider_runs],
        findings=[finding_model_to_schema(finding) for finding in model.findings],
        correlations=[
            correlation_model_to_schema(correlation)
            for correlation in getattr(model, "correlations", [])
        ],
    )


__all__ = [
    "correlation_model_to_schema",
    "evidence_model_to_schema",
    "finding_model_to_schema",
    "investigation_model_to_schema",
    "provider_run_model_to_schema",
]
