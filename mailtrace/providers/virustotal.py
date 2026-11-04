"""VirusTotal provider adapter for domain/URL reputation."""

from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import uuid4

from pydantic import HttpUrl

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


class VirusTotalProvider(BaseProvider):
    """VirusTotal domain and URL reputation provider."""

    name = "virustotal"
    display_name = "VirusTotal"
    requires_auth = True
    supported_profiles: ClassVar[list[str]] = ["domain", "full"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.api_key = self.config.get("api_key") or self.config.get("VIRUSTOTAL_API_KEY")
        self.base_url = str(
            self.config.get("base_url", "https://www.virustotal.com/api/v3")
        )
        self.user_agent = str(self.config.get("user_agent", "MailTrace/0.1.0"))

    def _get_default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "x-apikey": self.api_key or "",
        }

    def _get_base_url(self) -> str:
        return self.base_url

    async def health_check(self) -> dict[str, Any]:
        """Check VirusTotal API availability."""
        try:
            response = await self._make_request("GET", "/users/me")
            if response.status_code == 200:
                return {"healthy": True, "message": "VirusTotal API accessible", "details": {}}
            if response.status_code == 401:
                return {"healthy": False, "message": "Invalid API key", "details": {"status_code": 401}}
            if response.status_code == 429:
                return {"healthy": False, "message": "Rate limited", "details": {"status_code": 429}}
            return {"healthy": False, "message": f"Unexpected status: {response.status_code}", "details": {}}
        except Exception as e:
            return {"healthy": False, "message": f"Health check failed: {e}", "details": {}}

    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        """Check domain reputation for email domain."""
        findings: list[Finding] = []

        # Extract domain from email
        domain = self._extract_domain(email)
        if not domain:
            self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
            return findings

        try:
            # Get domain report
            response = await self._make_request("GET", f"/domains/{domain}")

            if response.status_code == 401:
                self._update_run_status(run, ProviderStatus.UNAUTHORIZED, "unauthorized", "Invalid API key")
                raise ProviderUnauthorizedError("Invalid VirusTotal API key")

            if response.status_code == 404:
                # Domain not in VT database
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
                return findings

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                self._update_run_status(run, ProviderStatus.RATE_LIMITED, "rate_limited", f"Retry after {retry_after}s")
                raise ProviderRateLimitedError(f"Rate limited, retry after {retry_after}s")

            response.raise_for_status()
            data = response.json()

            finding = await self._process_domain_report(domain, data, run)
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

    async def _process_domain_report(
        self, domain: str, data: dict[str, Any], run: ProviderRun
    ) -> Finding | None:
        """Process VirusTotal domain report into a finding."""
        domain_data = data.get("data", {})
        attributes = domain_data.get("attributes", {})

        # Extract reputation data
        reputation = attributes.get("reputation", 0)
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        categories = attributes.get("categories", [])
        registrar = attributes.get("registrar", "")
        creation_date = attributes.get("creation_date", 0)
        last_update = attributes.get("last_update_date", 0)

        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        harmless_count = last_analysis_stats.get("harmless", 0)
        undetected_count = last_analysis_stats.get("undetected", 0)

        total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

        # Determine severity based on malicious detections
        if malicious_count > 5:
            severity = Severity.HIGH
        elif malicious_count > 0 or suspicious_count > 3:
            severity = Severity.MEDIUM
        else:
            severity = Severity.INFORMATIONAL

        # Confidence based on number of engines
        if total_engines > 50:
            confidence = Confidence.HIGH
        elif total_engines > 10:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.DOMAIN_INTELLIGENCE,
            title=f"VirusTotal domain reputation: {domain}",
            service_name="VirusTotal",
            domain=domain,
            severity=severity,
            confidence=confidence,
            verification_status=VerificationStatus.VERIFIED,
            raw_data={
                "domain": domain,
                "reputation": reputation,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "harmless_count": harmless_count,
                "undetected_count": undetected_count,
                "total_engines": total_engines,
                "categories": categories,
                "registrar": registrar,
                "creation_date": creation_date,
                "last_update": last_update,
            },
        )

        # Create evidence
        vt_url = f"https://www.virustotal.com/gui/domain/{domain}"
        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_url=HttpUrl(vt_url),
            source_reference=f"domain:{domain}",
            evidence_type=EvidenceType.API_RESPONSE,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(f"vt_domain_{domain}"),
            notes=f"VT reputation: {reputation}, {malicious_count}/{total_engines} malicious",
        )
        finding.add_evidence(evidence)

        return finding

    def _extract_domain(self, email: str) -> str | None:
        """Extract domain from email."""
        try:
            return email.split("@", 1)[1].lower()
        except (ValueError, IndexError):
            return None
