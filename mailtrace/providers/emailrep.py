"""emailrep.io provider for email reputation and breach intelligence."""

import contextlib
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import uuid4

from mailtrace.providers.base import BaseProvider
from mailtrace.schemas.finding import (
    Confidence,
    EvidenceRecord,
    EvidenceType,
    Finding,
    FindingType,
    ProviderRun,
    ProviderStatus,
    Severity,
    VerificationStatus,
)


class EmailRepProvider(BaseProvider):
    """emailrep.io email reputation and breach intelligence provider."""

    name = "emailrep"
    display_name = "emailrep.io"
    requires_auth = False  # No API key required for basic usage
    supported_profiles: ClassVar[list[str]] = ["breach", "full"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.base_url = str(self.config.get("base_url", "https://emailrep.io"))
        self.api_key = self.config.get("api_key")  # Optional: for higher rate limits

    def _get_default_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "MailTrace/0.1.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Key"] = self.api_key
        return headers

    def _get_base_url(self) -> str:
        return self.base_url

    async def health_check(self) -> dict[str, Any]:
        """Check emailrep.io API availability."""
        try:
            response = await self._make_request("GET", "/test@example.com")
            if response.status_code == 200:
                return {"healthy": True, "message": "emailrep.io API accessible", "details": {}}
            if response.status_code == 429:
                return {"healthy": False, "message": "Rate limited", "details": {"status_code": 429}}
            return {"healthy": False, "message": f"Unexpected status: {response.status_code}", "details": {}}
        except Exception as e:
            return {"healthy": False, "message": f"Health check failed: {e}", "details": {}}

    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        """Check email reputation and breach data via emailrep.io."""
        findings: list[Finding] = []

        try:
            response = await self._make_request("GET", f"/{email}")

            if response.status_code == 404:
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
                return findings

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                self._update_run_status(run, ProviderStatus.RATE_LIMITED, "rate_limited", f"Retry after {retry_after}s")
                raise Exception(f"Rate limited, retry after {retry_after}s")

            response.raise_for_status()
            data = response.json()

            findings = self._process_emailrep_data(email, data, run)

            if findings:
                self._update_run_status(run, ProviderStatus.COMPLETED_WITH_FINDINGS, result_count=len(findings))
            else:
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)

        except Exception as e:
            if "Rate limited" in str(e):
                raise
            self._update_run_status(run, ProviderStatus.FAILED, "error", str(e))
            raise

        return findings

    def _process_emailrep_data(
        self, email: str, data: dict[str, Any], run: ProviderRun
    ) -> list[Finding]:
        """Process emailrep.io response into findings."""
        findings = []

        # Check for breach data
        breach_details = data.get("details", {}).get("breach_details", [])
        if breach_details:
            for breach in breach_details:
                finding = self._create_breach_finding(email, breach, run)
                if finding:
                    findings.append(finding)

        # Create reputation finding if suspicious
        suspicious = data.get("suspicious", False)
        malicious_activity = data.get("details", {}).get("malicious_activity", False)
        credentials_leaked = data.get("details", {}).get("credentials_leaked", False)
        data_breach = data.get("details", {}).get("data_breach", False)

        if suspicious or malicious_activity or credentials_leaked or data_breach:
            finding = self._create_reputation_finding(email, data, run)
            if finding:
                findings.append(finding)

        return findings

    def _create_breach_finding(
        self, email: str, breach: dict[str, Any], run: ProviderRun
    ) -> Finding | None:
        """Create a finding from breach details."""
        breach_name = breach.get("name", "Unknown Breach")
        breach_date_str = breach.get("date", "")
        sources = breach.get("sources", [])
        description = breach.get("description", "")
        compromised_data = breach.get("compromised_data", [])

        breach_date = None
        if breach_date_str:
            with contextlib.suppress(ValueError):
                breach_date = datetime.fromisoformat(breach_date_str.replace("Z", "+00:00"))

        severity = self._assess_severity(compromised_data)

        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.BREACH_EXPOSURE,
            title=f"Email found in {breach_name} breach (via emailrep.io)",
            service_name=breach_name,
            domain=email.split("@")[1] if "@" in email else "",
            severity=severity,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.VERIFIED,
            first_observed_at=breach_date,
            raw_data={
                "breach_name": breach_name,
                "breach_date": breach_date_str,
                "sources": sources,
                "description": description,
                "compromised_data": compromised_data,
            },
        )

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_reference=breach_name,
            evidence_type=EvidenceType.BREACH_RECORD,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(str(breach)),
            notes=f"Breach via emailrep.io: {breach_name} - {len(compromised_data)} data types",
        )
        finding.add_evidence(evidence)

        return finding

    def _create_reputation_finding(
        self, email: str, data: dict[str, Any], run: ProviderRun
    ) -> Finding | None:
        """Create a reputation/suspicious activity finding."""
        details = data.get("details", {})
        reputation = data.get("reputation", "neutral")
        suspicious = data.get("suspicious", False)

        # Determine severity based on indicators
        severity = Severity.INFORMATIONAL
        if data.get("details", {}).get("malicious_activity") or data.get("details", {}).get("credentials_leaked"):
            severity = Severity.HIGH
        elif data.get("details", {}).get("data_breach") or suspicious:
            severity = Severity.MEDIUM

        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.BREACH_EXPOSURE,
            title="Suspicious email reputation detected (via emailrep.io)",
            service_name="emailrep.io",
            domain=email.split("@")[1] if "@" in email else "",
            severity=severity,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.PARTIAL,
            raw_data={
                "reputation": reputation,
                "suspicious": suspicious,
                "malicious_activity": details.get("malicious_activity", False),
                "credentials_leaked": details.get("credentials_leaked", False),
                "data_breach": details.get("data_breach", False),
                "spam": details.get("spam", False),
                "disposable": details.get("disposable", False),
                "free_provider": details.get("free_provider", False),
                "domain_age_days": details.get("domain_age_days", 0),
                "profiles": details.get("profiles", []),
            },
        )

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_reference=f"reputation:{self._mask_email(email)}",
            evidence_type=EvidenceType.BREACH_RECORD,
            verification_status=VerificationStatus.PARTIAL,
            collected_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(str(data)),
            notes=f"Reputation: {reputation}, Suspicious: {suspicious}",
        )
        finding.add_evidence(evidence)

        return finding

    def _assess_severity(self, compromised_data: list[str]) -> Severity:
        """Assess severity based on compromised data types."""
        high_sensitivity = {
            "passwords", "password hashes", "salted passwords", "unsalted passwords",
            "credit cards", "financial data", "bank account numbers",
            "social security numbers", "passport numbers", "driver's license",
            "national id", "medical records", "health data",
            "authentication tokens", "api keys", "private keys",
            "credentials", "credential", "login", "access token",
        }

        medium_sensitivity = {
            "email addresses", "phone numbers", "physical addresses",
            "names", "dates of birth", "genders", "ip addresses",
            "user agents", "browser info", "employment history", "education",
            "emails", "email", "address", "name", "dob",
        }

        data_lower = {dc.lower() for dc in compromised_data}

        if data_lower & high_sensitivity:
            return Severity.CRITICAL

        if data_lower & medium_sensitivity:
            return Severity.MEDIUM

        return Severity.LOW
