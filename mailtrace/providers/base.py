"""Provider base classes for MailTrace."""

import asyncio
import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import UUID, uuid4

import httpx

from mailtrace.schemas.finding import (
    Finding,
    FindingType,
    ProviderRun,
    ProviderStatus,
)


class IntelligenceProvider(ABC):
    """Abstract base class for intelligence providers."""

    name: str
    display_name: str
    requires_auth: bool = True
    supported_profiles: ClassVar[list[str]] = []

    def __init__(self, config: dict[str, Any] | None = None):
        self.config: dict[str, Any] = config or {}
        self._client: httpx.AsyncClient | None = None

    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """Check provider availability and configuration."""
        raise NotImplementedError

    @abstractmethod
    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        """Check an email address and return normalized findings."""
        raise NotImplementedError

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize provider (create HTTP clients, etc.)."""

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup provider resources."""


class BaseProvider(IntelligenceProvider, ABC):
    """Base class for all provider adapters with common HTTP functionality."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.config = config or {}
        self._client: httpx.AsyncClient | None = None
        self._rate_limit_semaphore: asyncio.Semaphore | None = None

    async def initialize(self) -> None:
        """Initialize HTTP client and rate limiting."""
        timeout = httpx.Timeout(
            connect=10.0,
            read=self.config.get("timeout", 30.0),
            write=10.0,
            pool=5.0,
        )

        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            headers=self._get_default_headers(),
        )

        # Rate limiting
        rate_limit = self.config.get("rate_limit", 60)
        self._rate_limit_semaphore = asyncio.Semaphore(rate_limit)

    async def cleanup(self) -> None:
        """Cleanup HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @abstractmethod
    def _get_default_headers(self) -> dict[str, str]:
        """Get default headers for requests."""

    @abstractmethod
    def _get_base_url(self) -> str:
        """Get base URL for API."""

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Make HTTP request with rate limiting and error handling."""
        if not self._client:
            await self.initialize()

        if not self._rate_limit_semaphore or not self._client:
            raise RuntimeError("HTTP client or rate limit semaphore not initialized")

        client = self._client
        semaphore = self._rate_limit_semaphore

        async with semaphore:
            url = f"{self._get_base_url()}{endpoint}"
            request_headers = self._get_default_headers()
            if headers:
                request_headers.update(headers)

            try:
                response = await client.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    headers=request_headers,
                )
                return response
            except httpx.TimeoutException as exc:
                raise ProviderTimeoutError(f"{self.name} request timed out") from exc
            except httpx.ConnectError as exc:
                raise ProviderUnavailableError(f"{self.name} connection failed") from exc
            except httpx.HTTPStatusError as exc:
                raise ProviderError(
                    f"{self.name} HTTP error: {exc.response.status_code}"
                ) from exc

    def _create_evidence_hash(self, content: str) -> str:
        """Create SHA256 hash of evidence content."""
        return hashlib.sha256(content.encode()).hexdigest()

    @staticmethod
    def _mask_email(email: str) -> str:
        """Mask an email address for output and storage references."""
        try:
            local, domain = email.split("@", 1)
        except ValueError:
            return "***@***"
        if len(local) <= 2:
            masked_local = local[:1] + "*" * max(len(local) - 1, 0)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"

    def _update_run_status(
        self,
        run: ProviderRun,
        status: ProviderStatus,
        error_code: str | None = None,
        error_message: str | None = None,
        result_count: int | None = None,
    ) -> None:
        """Update provider run status."""
        run.status = status
        run.finished_at = datetime.now(UTC)
        if error_code:
            run.error_code = error_code
        if error_message:
            run.error_message = error_message
        if result_count is not None:
            run.result_count = result_count
        if run.started_at:
            # Ensure both datetimes are timezone-aware
            started = run.started_at
            finished = run.finished_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            if finished.tzinfo is None:
                finished = finished.replace(tzinfo=UTC)
            run.duration_ms = int((finished - started).total_seconds() * 1000)

    def _create_finding(
        self,
        investigation_id: str | UUID,
        finding_type: FindingType,
        title: str,
        **kwargs: Any,
    ) -> Finding:
        """Helper to create a finding with common fields."""
        if isinstance(investigation_id, str):
            investigation_id = UUID(investigation_id)

        return Finding(
            id=uuid4(),
            investigation_id=investigation_id,
            finding_type=finding_type,
            title=title,
            **kwargs,
        )


# Custom exceptions
class ProviderError(Exception):
    """Base provider error."""


class ProviderTimeoutError(ProviderError):
    """Provider request timeout."""


class ProviderUnavailableError(ProviderError):
    """Provider unavailable."""


class ProviderUnauthorizedError(ProviderError):
    """Provider authentication failed."""


class ProviderRateLimitedError(ProviderError):
    """Provider rate limited."""
