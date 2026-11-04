"""Brave Search provider adapter for public web search."""

from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import urlparse
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


class BraveSearchProvider(BaseProvider):
    """Brave Search API provider for public web search."""

    name = "brave_search"
    display_name = "Brave Search"
    requires_auth = True
    supported_profiles: ClassVar[list[str]] = ["public", "full"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.api_key = self.config.get("api_key") or self.config.get("BRAVE_API_KEY")
        self.base_url = str(
            self.config.get("base_url", "https://api.search.brave.com/res/v1/web/search")
        )
        self.user_agent = str(self.config.get("user_agent", "MailTrace/0.1.0"))

    def _get_default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": self.api_key or "",
        }

    def _get_base_url(self) -> str:
        return self.base_url

    async def health_check(self) -> dict[str, Any]:
        """Check Brave Search API availability."""
        try:
            # Simple test query
            response = await self._make_request("GET", "", params={"q": "test", "count": 1})
            if response.status_code == 200:
                return {"healthy": True, "message": "Brave Search API accessible", "details": {}}
            if response.status_code == 401:
                return {"healthy": False, "message": "Invalid API key", "details": {"status_code": 401}}
            if response.status_code == 429:
                return {"healthy": False, "message": "Rate limited", "details": {"status_code": 429}}
            return {"healthy": False, "message": f"Unexpected status: {response.status_code}", "details": {}}
        except Exception as e:
            return {"healthy": False, "message": f"Health check failed: {e}", "details": {}}

    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        """Search for email on the public web."""
        findings: list[Finding] = []

        try:
            # Search for email address
            query = f'"{email}"'
            response = await self._make_request(
                "GET",
                "",
                params={
                    "q": query,
                    "count": 20,
                    "search_lang": "en",
                    "safesearch": "moderate",
                },
            )

            if response.status_code == 401:
                self._update_run_status(run, ProviderStatus.UNAUTHORIZED, "unauthorized", "Invalid API key")
                raise ProviderUnauthorizedError("Invalid Brave Search API key")

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                self._update_run_status(run, ProviderStatus.RATE_LIMITED, "rate_limited", f"Retry after {retry_after}s")
                raise ProviderRateLimitedError(f"Rate limited, retry after {retry_after}s")

            if response.status_code == 422:
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
                return findings

            response.raise_for_status()
            data = response.json()

            web_results = data.get("web", {}).get("results", [])

            if not web_results:
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
                return findings

            # Process each result
            for result in web_results[:15]:
                finding = await self._process_result(email, result, run)
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

    async def _process_result(
        self, email: str, result: dict[str, Any], run: ProviderRun
    ) -> Finding | None:
        """Process a search result into a finding."""
        url = result.get("url", "")
        title = result.get("title", "")
        description = result.get("description", "")
        page_age = result.get("page_age", "")
        language = result.get("language", "")
        is_source_local = result.get("is_source_local", False)
        is_source_news = result.get("is_source_news", False)

        # Extract domain from URL
        domain = self._extract_domain(url)

        # Determine if this looks like a real exposure vs just a search hit
        # Check if email appears in title or description
        email_lower = email.lower()
        email_in_title = email_lower in title.lower()
        email_in_desc = email_lower in description.lower()

        if not email_in_title and not email_in_desc:
            # Email not visibly in snippet - lower confidence
            confidence = Confidence.LOW
            verification = VerificationStatus.PENDING
        else:
            confidence = Confidence.MEDIUM
            verification = VerificationStatus.PARTIAL

        # Assess severity based on context
        severity = self._assess_severity(title, description, domain)

        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.PUBLIC_EXPOSURE,
            title=f"Public web reference: {title[:100]}",
            service_name=domain or "Unknown",
            domain=domain,
            severity=severity,
            confidence=confidence,
            verification_status=verification,
            raw_data={
                "url": url,
                "title": title,
                "description": description,
                "page_age": page_age,
                "language": language,
                "is_source_local": is_source_local,
                "is_source_news": is_source_news,
                "email_in_title": email_in_title,
                "email_in_description": email_in_desc,
            },
        )

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_url=HttpUrl(url) if str(url).startswith(("http://", "https://")) else None,
            source_reference=str(url),
            evidence_type=EvidenceType.SEARCH_RESULT,
            verification_status=verification,
            collected_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(url),
            notes=f"Search result: {title[:100]}",
        )
        finding.add_evidence(evidence)

        return finding

    def _extract_domain(self, url: str) -> str | None:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except ValueError:
            return None

    def _assess_severity(self, title: str, description: str, domain: str | None) -> Severity:
        """Assess severity based on content and domain."""
        content = (title + " " + description).lower()

        # High severity indicators
        high_indicators = [
            "password", "credential", "login", "account", "ssn", "social security",
            "credit card", "bank", "financial", "medical", "health", "passport",
            "driver license", "identity", "personal", "private", "confidential",
            "leak", "breach", "dump", "paste", "dump", "exposed", "compromised",
        ]

        # Medium severity indicators
        medium_indicators = [
            "profile", "contact", "email", "phone", "address", "name",
            "linkedin", "facebook", "twitter", "github", "resume", "cv",
            "directory", "listing", "public", "register", "signup",
        ]

        for indicator in high_indicators:
            if indicator in content:
                return Severity.HIGH

        for indicator in medium_indicators:
            if indicator in content:
                return Severity.MEDIUM

        # Check domain reputation
        if domain:
            # Known paste/bin sites
            if any(site in domain for site in ["pastebin", "pastie", "hastebin", "ghostbin", "justpaste"]):
                return Severity.HIGH
            # Social/professional sites
            if any(site in domain for site in ["linkedin", "facebook", "twitter", "instagram", "github", "gitlab"]):
                return Severity.MEDIUM

        return Severity.LOW
