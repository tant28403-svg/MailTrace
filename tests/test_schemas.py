"""Tests for MailTrace schemas."""

from uuid import uuid4

import pytest

from mailtrace.schemas.finding import (
    Confidence,
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


class TestFinding:
    """Tests for Finding model."""

    def test_create_finding(self):
        """Test creating a finding."""
        finding = Finding(
            investigation_id=uuid4(),
            finding_type=FindingType.BREACH_EXPOSURE,
            title="Test breach",
            service_name="Test Service",
            domain="example.com",
            severity=Severity.HIGH,
            confidence=Confidence.VERIFIED,
        )
        assert finding.finding_type == FindingType.BREACH_EXPOSURE
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.VERIFIED

    def test_finding_with_evidence(self):
        """Test finding with evidence."""
        finding = Finding(
            investigation_id=uuid4(),
            finding_type=FindingType.PUBLIC_EXPOSURE,
            title="Public exposure",
        )
        evidence = EvidenceRecord(
            provider="hibp",
            source_reference="breach-123",
            evidence_type=EvidenceType.BREACH_RECORD,
            verification_status=VerificationStatus.VERIFIED,
        )
        finding.add_evidence(evidence)
        assert len(finding.evidence) == 1
        assert finding.evidence[0].provider == "hibp"


class TestInvestigation:
    """Tests for Investigation model."""

    def test_create_investigation(self):
        """Test creating an investigation."""
        inv = Investigation(
            target_hash="abc123",
            target_masked="u***@example.com",
            profile=Profile.FULL,
            status=InvestigationStatus.PENDING,
        )
        assert inv.profile == Profile.FULL
        assert inv.status == InvestigationStatus.PENDING
        assert inv.target_masked == "u***@example.com"

    def test_investigation_with_findings(self):
        """Test investigation with findings."""
        inv = Investigation(
            target_hash="abc123",
            target_masked="u***@example.com",
            profile=Profile.FULL,
        )
        finding = Finding(
            investigation_id=inv.id,
            finding_type=FindingType.BREACH_EXPOSURE,
            title="Test breach",
        )
        inv.findings.append(finding)
        assert len(inv.findings) == 1


class TestProviderRun:
    """Tests for ProviderRun model."""

    def test_provider_run(self):
        """Test provider run status."""
        run = ProviderRun(
            investigation_id=uuid4(),
            provider="hibp",
            status=ProviderStatus.PENDING,
        )
        assert run.provider == "hibp"
        assert run.status == ProviderStatus.PENDING


class TestEnums:
    """Tests for enum values."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFORMATIONAL.value == "informational"

    def test_confidence_values(self):
        """Test confidence enum values."""
        assert Confidence.VERIFIED.value == "verified"
        assert Confidence.HIGH.value == "high"
        assert Confidence.MEDIUM.value == "medium"
        assert Confidence.LOW.value == "low"
        assert Confidence.UNVERIFIED.value == "unverified"

    def test_profile_values(self):
        """Test profile enum values."""
        assert Profile.BREACH.value == "breach"
        assert Profile.PUBLIC.value == "public"
        assert Profile.DOMAIN.value == "domain"
        assert Profile.FULL.value == "full"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
