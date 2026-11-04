"""Have I Been Pwned provider adapter."""

import contextlib
import json
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import uuid4

from mailtrace.providers.base import (
    BaseProvider,
    ProviderRateLimitedError,
    ProviderUnauthorizedError,
)
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


class HIBPProvider(BaseProvider):
    """Have I Been Pwned breach intelligence provider."""

    name = "hibp"
    display_name = "Have I Been Pwned"
    requires_auth = True
    supported_profiles: ClassVar[list[str]] = ["breach", "full"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.api_key = self.config.get("api_key") or self.config.get("HIBP_API_KEY")
        self.base_url = str(
            self.config.get("base_url", "https://haveibeenpwned.com/api/v3")
        )
        self.user_agent = str(self.config.get("user_agent", "MailTrace/0.1.0"))

    def _get_default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "hibp-api-key": self.api_key or "",
            "Accept": "application/json",
        }

    def _get_base_url(self) -> str:
        return self.base_url

    async def health_check(self) -> dict[str, Any]:
        """Check HIBP API availability."""
        try:
            response = await self._make_request("GET", "/breaches", params={"truncateResponse": "true"})
            if response.status_code == 200:
                return {"healthy": True, "message": "HIBP API accessible", "details": {}}
            if response.status_code == 401:
                return {"healthy": False, "message": "Invalid API key", "details": {"status_code": 401}}
            if response.status_code == 429:
                return {"healthy": False, "message": "Rate limited", "details": {"status_code": 429}}
            return {"healthy": False, "message": f"Unexpected status: {response.status_code}", "details": {}}
        except Exception as e:
            return {"healthy": False, "message": f"Health check failed: {e}", "details": {}}

    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        """Check email against HIBP breach database."""
        findings: list[Finding] = []

        try:
            # Get breaches for this email
            response = await self._make_request(
                "GET",
                f"/breachedaccount/{email}",
                params={"truncateResponse": "false", "includeUnverified": "true"},
            )

            if response.status_code == 404:
                # No breaches found
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
                return findings

            if response.status_code == 401:
                self._update_run_status(run, ProviderStatus.UNAUTHORIZED, "unauthorized", "Invalid API key")
                raise ProviderUnauthorizedError("Invalid HIBP API key")

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                self._update_run_status(run, ProviderStatus.RATE_LIMITED, "rate_limited", f"Retry after {retry_after}s")
                raise ProviderRateLimitedError(f"Rate limited, retry after {retry_after}s")

            response.raise_for_status()
            breaches = response.json()

            if not breaches:
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
                return findings

            # Process each breach
            for breach in breaches:
                finding = await self._process_breach(email, breach, run)
                if finding:
                    findings.append(finding)

            self._update_run_status(run, ProviderStatus.COMPLETED_WITH_FINDINGS, result_count=len(findings))

        except ProviderUnauthorizedError:
            raise
        except ProviderRateLimitedError:
            raise
        except Exception as e:
            self._update_run_status(run, ProviderStatus.FAILED, "error", str(e))
            raise

        return findings

    async def _process_breach(
        self, email: str, breach_data: dict[str, Any], run: ProviderRun
    ) -> Finding | None:
        """Process a single breach record into a finding."""
        breach_name = breach_data.get("Name", "Unknown Breach")
        breach_domain = breach_data.get("Domain", "")
        breach_date_str = breach_data.get("BreachDate", "")
        added_date_str = breach_data.get("AddedDate", "")
        data_classes = breach_data.get("DataClasses", [])
        is_verified = breach_data.get("IsVerified", False)
        is_retired = breach_data.get("IsRetired", False)
        is_spam_list = breach_data.get("IsSpamList", False)
        description = breach_data.get("Description", "")

        # Parse dates
        breach_date = None
        if breach_date_str:
            with contextlib.suppress(ValueError):
                breach_date = datetime.fromisoformat(breach_date_str.replace("Z", "+00:00"))

        # Determine severity based on data classes
        severity = self._assess_severity(data_classes)

        # Create finding
        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.BREACH_EXPOSURE,
            title=f"Email found in {breach_name} breach",
            service_name=breach_name,
            domain=breach_domain,
            severity=severity,
            confidence=Confidence.VERIFIED if is_verified else Confidence.HIGH,
            verification_status=VerificationStatus.VERIFIED if is_verified else VerificationStatus.PARTIAL,
            first_observed_at=breach_date,
            raw_data={
                "breach_name": breach_name,
                "domain": breach_domain,
                "breach_date": breach_date_str,
                "added_date": added_date_str,
                "data_classes": data_classes,
                "is_verified": is_verified,
                "is_retired": is_retired,
                "is_spam_list": is_spam_list,
                "description": description,
            },
        )

        # Create evidence record
        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_reference=breach_name,
            evidence_type=EvidenceType.BREACH_RECORD,
            verification_status=VerificationStatus.VERIFIED if is_verified else VerificationStatus.PARTIAL,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC) if is_verified else None,
            evidence_hash=self._create_evidence_hash(json.dumps(breach_data, sort_keys=True)),
            notes=f"Breach: {breach_name} ({breach_domain}) - {len(data_classes)} data classes",
        )
        finding.add_evidence(evidence)

        return finding

    def _assess_severity(self, data_classes: list[str]) -> Severity:
        """Assess severity based on exposed data classes."""
        # High sensitivity data classes
        high_sensitivity = {
            "passwords",
            "password hashes",
            "salted passwords",
            "unsalted passwords",
            "credit cards",
            "financial data",
            "bank account numbers",
            "social security numbers",
            "passport numbers",
            "driver's license",
            "national id",
            "medical records",
            "health data",
            "authentication tokens",
            "api keys",
            "private keys",
        }

        # Medium sensitivity
        medium_sensitivity = {
            "email addresses",
            "phone numbers",
            "physical addresses",
            "names",
            "dates of birth",
            "genders",
            "ip addresses",
            "user agents",
            "browser info",
            "employment history",
            "education",
        }

        data_classes_lower = {dc.lower() for dc in data_classes}

        # Check for high sensitivity
        if data_classes_lower & high_sensitivity:
            return Severity.CRITICAL

        # Check for medium sensitivity
        if data_classes_lower & medium_sensitivity:
            return Severity.HIGH

        # Default to medium
        return Severity.MEDIUM
