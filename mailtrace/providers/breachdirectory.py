"""BreachDirectory provider via RapidAPI."""

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


class BreachDirectoryProvider(BaseProvider):
    """BreachDirectory breach intelligence provider via RapidAPI."""

    name = "breachdirectory"
    display_name = "BreachDirectory"
    requires_auth = True
    supported_profiles: ClassVar[list[str]] = ["breach", "full"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.api_key = self.config.get("api_key") or self.config.get("BREACHDIRECTORY_API_KEY")
        self.base_url = str(
            self.config.get("base_url", "https://breachdirectory.p.rapidapi.com")
        )
        self.rapidapi_host = str(
            self.config.get("rapidapi_host", "breachdirectory.p.rapidapi.com")
        )

    def _get_default_headers(self) -> dict[str, str]:
        return {
            "X-RapidAPI-Key": self.api_key or "",
            "X-RapidAPI-Host": self.rapidapi_host,
        }

    def _get_base_url(self) -> str:
        return self.base_url

    async def health_check(self) -> dict[str, Any]:
        """Check BreachDirectory API availability."""
        try:
            response = await self._make_request("GET", "/", params={"term": "test@example.com", "func": "auto"})
            # 200 = OK, 422 = missing params (valid endpoint), 401/403 = auth issues
            if response.status_code in (200, 422):
                return {"healthy": True, "message": "BreachDirectory API accessible", "details": {"status_code": response.status_code}}
            if response.status_code == 401:
                return {"healthy": False, "message": "Invalid API key", "details": {"status_code": 401}}
            if response.status_code == 403:
                return {"healthy": False, "message": "Invalid RapidAPI subscription", "details": {"status_code": 403}}
            if response.status_code == 429:
                return {"healthy": False, "message": "Rate limited", "details": {"status_code": 429}}
            return {"healthy": False, "message": f"Unexpected status: {response.status_code}", "details": {}}
        except Exception as e:
            return {"healthy": False, "message": f"Health check failed: {e}", "details": {}}

    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        """Check email against BreachDirectory."""
        findings: list[Finding] = []

        try:
            response = await self._make_request("GET", "/", params={"term": email, "func": "auto"})

            if response.status_code == 404:
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
                return findings

            if response.status_code == 401:
                self._update_run_status(
                    run, ProviderStatus.UNAUTHORIZED, "unauthorized", "Invalid API key"
                )
                raise ProviderUnauthorizedError("Invalid BreachDirectory API key")

            if response.status_code == 403:
                self._update_run_status(
                    run,
                    ProviderStatus.UNAUTHORIZED,
                    "forbidden",
                    "Invalid RapidAPI subscription",
                )
                raise ProviderUnauthorizedError("Invalid RapidAPI subscription")

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                self._update_run_status(
                    run,
                    ProviderStatus.RATE_LIMITED,
                    "rate_limited",
                    f"Retry after {retry_after}s",
                )
                raise ProviderRateLimitedError(f"Rate limited, retry after {retry_after}s")

            response.raise_for_status()
            data = response.json()

            # New API format: {"success": true, "found": 752, "result": [...]}
            if not data or not data.get("success") or not data.get("result"):
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
                return findings

            for breach in data.get("result", []):
                finding = await self._process_breach(email, breach, run)
                if finding:
                    findings.append(finding)

            self._update_run_status(run, ProviderStatus.COMPLETED_WITH_FINDINGS, result_count=len(findings))

        except (ProviderUnauthorizedError, ProviderRateLimitedError):
            raise
        except Exception as e:
            self._update_run_status(run, ProviderStatus.FAILED, "error", str(e))
            raise

        return findings

    async def _process_breach(
        self, email: str, breach_data: dict[str, Any], run: ProviderRun
    ) -> Finding | None:
        """Process a single breach record into a finding.

        BreachDirectory can return plaintext passwords and password hashes.
        MailTrace deliberately stores only presence/type metadata: credentials
        must never be written to the local case database or reports.
        """
        raw_source = breach_data.get("sources") or breach_data.get("source")
        if isinstance(raw_source, list):
            source = ", ".join(str(item) for item in raw_source) or "Unknown Breach"
        else:
            source = str(raw_source or "Unknown Breach")

        password_exposed = bool(breach_data.get("password"))
        sha1_exposed = bool(breach_data.get("sha1"))
        hash_exposed = bool(breach_data.get("hash"))
        hash_password = bool(breach_data.get("hash_password", False))
        credential_exposed = password_exposed or sha1_exposed or hash_exposed

        if sha1_exposed:
            hash_type = "sha1"
        elif hash_exposed:
            hash_type = "unknown"
        else:
            hash_type = None

        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.BREACH_EXPOSURE,
            title=f"Email found in {source} breach",
            service_name=source,
            domain=email.split("@")[1] if "@" in email else "",
            severity=Severity.HIGH if credential_exposed else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.VERIFIED,
            raw_data={
                "breach_name": source,
                "source": source,
                "credential_exposed": credential_exposed,
                "password_exposed": password_exposed,
                "password_hash_exposed": sha1_exposed or hash_exposed,
                "hash_type": hash_type,
                "hash_password": hash_password,
            },
        )

        if credential_exposed:
            notes = f"Breach: {source} - credential material exposed (redacted)"
        else:
            notes = f"Breach: {source} - account record exposed"

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_reference=source,
            evidence_type=EvidenceType.BREACH_RECORD,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(str(breach_data)),
            notes=notes,
        )
        finding.add_evidence(evidence)

        return finding
