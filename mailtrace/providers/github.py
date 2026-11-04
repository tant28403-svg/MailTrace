"""GitHub provider adapter for public repository metadata."""

import contextlib
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


class GitHubProvider(BaseProvider):
    """GitHub public repository and commit metadata provider."""

    name = "github"
    display_name = "GitHub"
    requires_auth = True
    supported_profiles: ClassVar[list[str]] = ["public", "full"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.token = self.config.get("token") or self.config.get("GITHUB_TOKEN")
        self.base_url = str(self.config.get("base_url", "https://api.github.com"))
        self.user_agent = str(self.config.get("user_agent", "MailTrace/0.1.0"))

    def _get_default_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get_base_url(self) -> str:
        return self.base_url

    async def health_check(self) -> dict[str, Any]:
        """Check GitHub API availability."""
        try:
            response = await self._make_request("GET", "/rate_limit")
            if response.status_code == 200:
                data = response.json()
                remaining = data.get("resources", {}).get("search", {}).get("remaining", 0)
                return {
                    "healthy": True,
                    "message": f"GitHub API accessible, {remaining} search requests remaining",
                    "details": {"rate_limit_remaining": remaining},
                }
            if response.status_code == 401:
                return {"healthy": False, "message": "Invalid token", "details": {"status_code": 401}}
            return {"healthy": False, "message": f"Unexpected status: {response.status_code}", "details": {}}
        except Exception as e:
            return {"healthy": False, "message": f"Health check failed: {e}", "details": {}}

    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        """Search GitHub for an email in public commits and code."""
        findings: list[Finding] = []

        try:
            # Commit search supports author-email and committer-email
            # qualifiers separately, so run both and merge by commit SHA.
            commits: list[dict[str, Any]] = []
            seen_shas: set[str] = set()
            for qualifier in ("author-email", "committer-email"):
                for item in await self._search_commits(email, qualifier, run):
                    sha = str(item.get("sha", ""))
                    if sha and sha in seen_shas:
                        continue
                    if sha:
                        seen_shas.add(sha)
                    commits.append(item)

            for item in commits[:20]:
                finding = await self._process_commit(email, item, run)
                if finding:
                    findings.append(finding)

            # Code search is best-effort: a failure here must not discard
            # commit findings that were already collected.
            await self._search_code(email, run, findings)

            run.result_count = len(findings)
            if findings:
                self._update_run_status(
                    run, ProviderStatus.COMPLETED_WITH_FINDINGS,
                    result_count=len(findings),
                )
            else:
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)

        except ProviderUnauthorizedError:
            raise
        except ProviderRateLimitedError:
            raise
        except Exception as e:
            self._update_run_status(run, ProviderStatus.FAILED, "error", str(e))
            raise

        return findings

    async def _search_commits(
        self, email: str, qualifier: str, run: ProviderRun
    ) -> list[dict[str, Any]]:
        """Run one commit search and return raw items."""
        response = await self._make_request(
            "GET",
            "/search/commits",
            params={
                "q": f'{qualifier}:"{email}"',
                "per_page": 30,
                "sort": "committer-date",
                "order": "desc",
            },
        )

        if response.status_code == 401:
            self._update_run_status(
                run, ProviderStatus.UNAUTHORIZED, "unauthorized", "Invalid token"
            )
            raise ProviderUnauthorizedError("Invalid GitHub token")

        if response.status_code in (403, 429):
            retry_after = response.headers.get("Retry-After", "60")
            self._update_run_status(
                run,
                ProviderStatus.RATE_LIMITED,
                "rate_limited",
                f"Retry after {retry_after}s",
            )
            raise ProviderRateLimitedError(f"Rate limited, retry after {retry_after}s")

        if response.status_code == 422:
            return []

        response.raise_for_status()
        data = response.json()
        items = data.get("items", [])
        return items if isinstance(items, list) else []

    async def _search_code(
        self, email: str, run: ProviderRun, findings: list[Finding]
    ) -> None:
        """Search for an email in code (best-effort, additional search)."""
        try:
            response = await self._make_request(
                "GET",
                "/search/code",
                params={"q": f'"{email}"', "per_page": 10},
            )

            if response.status_code in (401, 403, 429, 422):
                return

            response.raise_for_status()
            data = response.json()

            for item in data.get("items", [])[:5]:
                finding = await self._process_code_result(email, item, run)
                if finding:
                    findings.append(finding)

        except Exception:
            return

    async def _process_commit(
        self, email: str, commit_data: dict[str, Any], run: ProviderRun
    ) -> Finding | None:
        """Process a commit search result into a finding."""
        commit = commit_data.get("commit", {})
        author = commit.get("author", {})
        committer = commit.get("committer", {})
        repository = commit_data.get("repository", {})
        html_url = commit_data.get("html_url", "")

        # Check if email matches author or committer
        author_email = author.get("email", "").lower()
        committer_email = committer.get("email", "").lower()
        target_email = email.lower()

        if author_email != target_email and committer_email != target_email:
            return None

        repo_name = repository.get("full_name", "")
        repo_url = repository.get("html_url", "")
        commit_message = commit.get("message", "")
        commit_date_str = author.get("date") or committer.get("date")
        commit_sha = commit_data.get("sha", "")

        # Parse date
        commit_date = None
        if commit_date_str:
            with contextlib.suppress(ValueError):
                commit_date = datetime.fromisoformat(commit_date_str.replace("Z", "+00:00"))

        # Create finding
        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.REPOSITORY_EXPOSURE,
            title=f"Email in GitHub commit: {repo_name}",
            service_name="GitHub",
            domain=repo_name.split("/")[0] if "/" in repo_name else repo_name,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.VERIFIED,
            first_observed_at=commit_date,
            raw_data={
                "repository": repo_name,
                "repository_url": repo_url,
                "commit_sha": commit_sha,
                "commit_url": html_url,
                "commit_message": commit_message[:200] if commit_message else "",
                "author_name": author.get("name", ""),
                "committer_name": committer.get("name", ""),
                "commit_date": commit_date_str,
            },
        )

        # Create evidence
        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_url=HttpUrl(html_url)
            if str(html_url).startswith(("http://", "https://"))
            else None,
            source_reference=commit_sha,
            evidence_type=EvidenceType.REPOSITORY_METADATA,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(commit_sha),
            notes=f"Commit in {repo_name}: {commit_message[:100]}...",
        )
        finding.add_evidence(evidence)

        return finding

    async def _process_code_result(
        self, email: str, item: dict[str, Any], run: ProviderRun
    ) -> Finding | None:
        """Process a code search result into a finding."""
        repository = item.get("repository", {})
        repo_name = repository.get("full_name", "")
        repo_url = repository.get("html_url", "")
        html_url = item.get("html_url", "")
        path = item.get("path", "")
        sha = item.get("sha", "")

        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.REPOSITORY_EXPOSURE,
            title=f"Email in GitHub code: {repo_name}/{path}",
            service_name="GitHub",
            domain=repo_name.split("/")[0] if "/" in repo_name else repo_name,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.PARTIAL,
            raw_data={
                "repository": repo_name,
                "repository_url": repo_url,
                "file_path": path,
                "file_url": html_url,
                "blob_sha": sha,
            },
        )

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_url=HttpUrl(html_url)
            if str(html_url).startswith(("http://", "https://"))
            else None,
            source_reference=f"{repo_name}/{path}",
            evidence_type=EvidenceType.REPOSITORY_METADATA,
            verification_status=VerificationStatus.PARTIAL,
            collected_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(sha),
            notes=f"Code file in {repo_name}: {path}",
        )
        finding.add_evidence(evidence)

        return finding
