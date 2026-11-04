"""Tests for report generation and target masking."""

import json
from datetime import UTC, datetime
from uuid import uuid4

from mailtrace.reporting import ReportGenerator
from mailtrace.schemas.finding import (
    Confidence,
    EvidenceRecord,
    EvidenceType,
    ExportFormat,
    Finding,
    FindingType,
    Investigation,
    InvestigationStatus,
    Profile,
    ReportOptions,
    Severity,
    VerificationStatus,
)

RAW_EMAIL = "victim@example.com"
MASKED_EMAIL = "v*****@example.com"


def _build_investigation() -> Investigation:
    investigation = Investigation(
        target_hash="a" * 64,
        target_masked=MASKED_EMAIL,
        target_email=RAW_EMAIL,
        profile=Profile.FULL,
        status=InvestigationStatus.COMPLETE,
        authorization_confirmed=True,
        completed_at=datetime.now(UTC),
    )
    finding = Finding(
        id=uuid4(),
        investigation_id=investigation.id,
        finding_type=FindingType.BREACH_EXPOSURE,
        title="Email found in Example breach",
        service_name="Example",
        domain="example.com",
        severity=Severity.HIGH,
        confidence=Confidence.VERIFIED,
        verification_status=VerificationStatus.VERIFIED,
        raw_data={"breach_name": "Example"},
    )
    finding.add_evidence(
        EvidenceRecord(
            id=uuid4(),
            provider="hibp",
            source_reference="Example",
            evidence_type=EvidenceType.BREACH_RECORD,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
        )
    )
    investigation.findings.append(finding)
    return investigation


def _options(**overrides) -> ReportOptions:
    values = {
        "format": ExportFormat.JSON,
        "mask_target": True,
    }
    values.update(overrides)
    return ReportOptions(**values)


def test_json_report_masks_target_by_default():
    report = ReportGenerator(_build_investigation()).generate(_options())
    data = json.loads(report)

    assert data["investigation"]["target"] == MASKED_EMAIL
    assert RAW_EMAIL not in report


def test_json_report_can_show_target_when_requested():
    report = ReportGenerator(_build_investigation()).generate(
        _options(mask_target=False)
    )
    data = json.loads(report)

    assert data["investigation"]["target"] == RAW_EMAIL


def test_json_report_evidence_toggle():
    investigation = _build_investigation()

    with_evidence = json.loads(
        ReportGenerator(investigation).generate(_options(include_evidence=True))
    )
    without_evidence = json.loads(
        ReportGenerator(investigation).generate(_options(include_evidence=False))
    )

    assert "evidence" in with_evidence["findings"][0]
    assert "evidence" not in without_evidence["findings"][0]


def test_csv_report_includes_target_column():
    investigation = _build_investigation()
    report = ReportGenerator(investigation).generate(
        _options(format=ExportFormat.CSV)
    )

    header = report.splitlines()[0]
    assert header.startswith("Target,")
    assert MASKED_EMAIL in report


def test_terminal_report_does_not_duplicate_content():
    report = ReportGenerator(_build_investigation()).generate(
        _options(format=ExportFormat.TERMINAL)
    )

    assert report.count("MailTrace Investigation Report") == 1
    assert "Email found in Example breach" in report
