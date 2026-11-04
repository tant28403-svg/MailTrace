"""Investigation orchestrator for MailTrace."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from mailtrace.core.configuration import get_config
from mailtrace.modules.email_validator import get_email_validator
from mailtrace.providers import BaseProvider, get_provider_class
from mailtrace.schemas.finding import (
    Confidence,
    Correlation,
    CorrelationType,
    EvidenceRecord,
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
from mailtrace.storage import (
    AuditRepository,
    CorrelationRepository,
    DatabaseManager,
    EvidenceRepository,
    FindingRepository,
    InvestigationRepository,
    ProviderRunRepository,
    SnapshotRepository,
    close_database,
    init_database,
)
from mailtrace.storage.models import (
    AuditEventModel,
    CorrelationModel,
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ProviderRunModel,
    SnapshotModel,
)

SUCCESSFUL_PROVIDER_STATUSES = frozenset(
    {
        ProviderStatus.COMPLETED_WITH_FINDINGS,
        ProviderStatus.COMPLETED_NO_MATCHES,
    }
)

# Statuses a provider may set before raising (e.g. rate limit); they should be
# preserved instead of being overwritten with FAILED by the orchestrator.
_TERMINAL_PROVIDER_STATUSES = frozenset(
    {
        *SUCCESSFUL_PROVIDER_STATUSES,
        ProviderStatus.UNAUTHORIZED,
        ProviderStatus.RATE_LIMITED,
        ProviderStatus.UNAVAILABLE,
        ProviderStatus.TIMEOUT,
        ProviderStatus.CONFIGURATION_ERROR,
        ProviderStatus.UNSUPPORTED,
        ProviderStatus.PARTIAL,
    }
)

_PROFILE_PROVIDERS: dict[Profile, list[str]] = {
    Profile.BREACH: ["hibp", "breachdirectory", "emailrep"],
    Profile.PUBLIC: ["brave_search", "github", "emailrep"],
    Profile.DOMAIN: ["dns", "virustotal"],
    Profile.FULL: [
        "hibp",
        "breachdirectory",
        "emailrep",
        "brave_search",
        "github",
        "virustotal",
        "dns",
    ],
}


class Orchestrator:
    """Main investigation orchestrator."""

    def __init__(self) -> None:
        self.config = get_config()
        self.email_validator = get_email_validator()
        self._providers: dict[str, BaseProvider] = {}
        self._db_manager: DatabaseManager | None = None
        self._hmac_key = self._get_or_create_hmac_key()

    def _get_or_create_hmac_key(self) -> bytes:
        """Get or create the HMAC key used for email hashing."""
        data_dir = self.config.general.data_dir
        key_file = data_dir / ".hmac_key"

        if key_file.exists():
            return key_file.read_bytes()

        key = secrets.token_bytes(32)
        data_dir.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(key)
        with contextlib.suppress(OSError):
            # chmod is best-effort on Windows and some filesystems.
            key_file.chmod(0o600)
        return key

    def _hash_email(self, email: str) -> str:
        """Create an HMAC hash of an email for storage."""
        return hmac.new(self._hmac_key, email.lower().encode(), hashlib.sha256).hexdigest()

    def _mask_email(self, email: str) -> str:
        """Mask an email for display."""
        return self.email_validator.mask_email(email)

    async def initialize(self) -> None:
        """Initialize database and providers."""
        self._db_manager = await init_database(data_dir=self.config.general.data_dir)

        provider_configs: dict[str, dict[str, Any]] = {
            "hibp": {
                "api_key": self.config.hibp.api_key,
                "base_url": self.config.hibp.base_url,
                "timeout": self.config.hibp.timeout,
                "rate_limit": self.config.hibp.rate_limit,
            },
            "breachdirectory": {
                "api_key": self.config.breachdirectory.api_key,
                "base_url": self.config.breachdirectory.base_url,
                "rapidapi_host": self.config.breachdirectory.rapidapi_host,
                "timeout": self.config.breachdirectory.timeout,
                "rate_limit": self.config.breachdirectory.rate_limit,
            },
            "emailrep": {
                "api_key": self.config.emailrep.api_key,
                "base_url": self.config.emailrep.base_url,
                "timeout": self.config.emailrep.timeout,
                "rate_limit": self.config.emailrep.rate_limit,
            },
            "github": {
                "token": self.config.github.token,
                "base_url": self.config.github.base_url,
                "timeout": self.config.github.timeout,
                "rate_limit": self.config.github.rate_limit,
            },
            "brave_search": {
                "api_key": self.config.brave_search.api_key,
                "base_url": self.config.brave_search.base_url,
                "timeout": self.config.brave_search.timeout,
                "rate_limit": self.config.brave_search.rate_limit,
            },
            "virustotal": {
                "api_key": self.config.virustotal.api_key,
                "base_url": self.config.virustotal.base_url,
                "timeout": self.config.virustotal.timeout,
                "rate_limit": self.config.virustotal.rate_limit,
            },
            "dns": {
                "resolvers": self.config.dns.resolvers,
                "timeout": self.config.dns.timeout,
                "rate_limit": self.config.dns.rate_limit,
            },
        }

        enabled = self.config.get_enabled_providers()
        for provider_name in enabled:
            if provider_name in self._providers:
                continue
            provider_class = get_provider_class(provider_name)
            if provider_class is None:
                continue
            provider_config = {
                key: value
                for key, value in provider_configs.get(provider_name, {}).items()
                if value is not None
            }
            provider = provider_class(provider_config)
            await provider.initialize()
            self._providers[provider_name] = provider

    @property
    def _database(self) -> DatabaseManager:
        """Return the initialized database manager."""
        if self._db_manager is None:
            raise RuntimeError("Orchestrator has not been initialized")
        return self._db_manager

    async def cleanup(self) -> None:
        """Clean up providers and database connections."""
        for provider in self._providers.values():
            await provider.cleanup()
        self._providers.clear()
        await close_database()

    def _get_providers_for_profile(self, profile: Profile) -> list[str]:
        """Get the provider names relevant to a profile."""
        return list(_PROFILE_PROVIDERS.get(profile, []))

    # ------------------------------------------------------------------
    # Model conversion
    # ------------------------------------------------------------------

    def _pydantic_to_sqlalchemy_investigation(
        self, investigation: Investigation
    ) -> InvestigationModel:
        return InvestigationModel(
            id=investigation.id,
            target_hash=investigation.target_hash,
            target_masked=investigation.target_masked,
            profile=investigation.profile,
            status=investigation.status,
            authorization_confirmed=investigation.authorization_confirmed,
            created_at=investigation.created_at,
            completed_at=investigation.completed_at,
            tags=investigation.tags,
            notes=investigation.notes,
        )

    def _pydantic_to_sqlalchemy_provider_run(self, run: ProviderRun) -> ProviderRunModel:
        return ProviderRunModel(
            id=run.id,
            investigation_id=run.investigation_id,
            provider=run.provider,
            status=run.status,
            started_at=run.started_at,
            finished_at=run.finished_at,
            result_count=run.result_count,
            error_code=run.error_code,
            error_message=run.error_message,
            duration_ms=run.duration_ms,
        )

    def _pydantic_to_sqlalchemy_finding(self, finding: Finding) -> FindingModel:
        return FindingModel(
            id=finding.id,
            investigation_id=finding.investigation_id,
            finding_type=finding.finding_type,
            title=finding.title,
            service_name=finding.service_name,
            domain=finding.domain,
            severity=finding.severity,
            confidence=finding.confidence,
            verification_status=finding.verification_status,
            first_observed_at=finding.first_observed_at,
            collected_at=finding.collected_at,
            raw_data=finding.raw_data,
        )

    def _pydantic_to_sqlalchemy_evidence(self, evidence: EvidenceRecord) -> EvidenceModel:
        return EvidenceModel(
            id=evidence.id,
            finding_id=evidence.finding_id,
            provider=evidence.provider,
            source_url=str(evidence.source_url) if evidence.source_url else None,
            source_reference=evidence.source_reference,
            evidence_type=evidence.evidence_type,
            evidence_hash=evidence.evidence_hash,
            verification_status=evidence.verification_status,
            collected_at=evidence.collected_at,
            verified_at=evidence.verified_at,
            notes=evidence.notes,
        )

    def _pydantic_to_sqlalchemy_correlation(
        self, correlation: Correlation
    ) -> CorrelationModel:
        return CorrelationModel(
            id=correlation.id,
            investigation_id=correlation.investigation_id,
            finding_a_id=correlation.finding_a_id,
            finding_b_id=correlation.finding_b_id,
            correlation_type=correlation.correlation_type,
            confidence=correlation.confidence,
            notes=correlation.notes,
            created_at=correlation.created_at,
        )

    # ------------------------------------------------------------------
    # Investigation lifecycle
    # ------------------------------------------------------------------

    async def run_investigation(
        self,
        email: str,
        profile: Profile = Profile.FULL,
        authorization_confirmed: bool = False,
        on_investigation_created: Callable[[Investigation], None] | None = None,
    ) -> Investigation:
        """Run a full investigation."""
        validation = self.email_validator.validate(email)
        if not validation.valid:
            raise ValueError(f"Invalid email: {validation.error}")

        normalized_email = validation.normalized
        if normalized_email is None:
            raise ValueError("Email validation did not return a normalized address")
        email_hash = self._hash_email(normalized_email)
        masked_email = self._mask_email(normalized_email)

        profile_providers = self._get_providers_for_profile(profile)
        enabled_providers = [name for name in profile_providers if name in self._providers]

        if not enabled_providers:
            raise ValueError(
                f"No providers configured for the {profile.value} profile. "
                "Set the required API keys or enable the DNS provider."
            )

        if self.config.general.confirm_external and not authorization_confirmed:
            raise ValueError("External API authorization required")

        investigation = Investigation(
            id=uuid4(),
            target_hash=email_hash,
            target_masked=masked_email,
            target_email=normalized_email,
            profile=profile,
            status=InvestigationStatus.RUNNING,
            authorization_confirmed=authorization_confirmed,
        )

        async with self._database.session() as session:
            inv_repo = InvestigationRepository(session)
            run_repo = ProviderRunRepository(session)

            await inv_repo.create(self._pydantic_to_sqlalchemy_investigation(investigation))

            provider_runs: dict[str, ProviderRun] = {}
            for provider_name in enabled_providers:
                run = ProviderRun(
                    investigation_id=investigation.id,
                    provider=provider_name,
                    status=ProviderStatus.PENDING,
                )
                await run_repo.create(self._pydantic_to_sqlalchemy_provider_run(run))
                provider_runs[provider_name] = run
                investigation.provider_runs.append(run)

        if on_investigation_created is not None:
            on_investigation_created(investigation)

        await self._run_providers(normalized_email, investigation, provider_runs)

        # Deduplicate, correlate and reassess *before* persisting findings so
        # the database reflects the final normalized result set.
        self._process_findings(investigation)
        await self._persist_results(investigation)
        await self._create_snapshot(investigation)

        investigation.status = self._determine_status(investigation.provider_runs)
        investigation.completed_at = datetime.now(UTC)

        async with self._database.session() as session:
            inv_repo = InvestigationRepository(session)
            await inv_repo.update_status(
                investigation.id, investigation.status, investigation.completed_at
            )

        await self._audit_event(
            investigation.id,
            "investigation_complete",
            {
                "profile": profile.value,
                "status": investigation.status.value,
                "finding_count": len(investigation.findings),
                "provider_count": len(investigation.provider_runs),
            },
        )

        return investigation

    async def _run_providers(
        self,
        email: str,
        investigation: Investigation,
        provider_runs: dict[str, ProviderRun],
    ) -> None:
        """Run all relevant providers concurrently."""

        async def run_provider(
            provider_name: str, provider: BaseProvider, run: ProviderRun
        ) -> None:
            try:
                async with self._database.session() as session:
                    run_repo = ProviderRunRepository(session)
                    await run_repo.update_status(run.id, ProviderStatus.RUNNING)

                findings = await provider.check_email(email, run)

                if run.status in (ProviderStatus.PENDING, ProviderStatus.RUNNING):
                    run.status = (
                        ProviderStatus.COMPLETED_WITH_FINDINGS
                        if findings
                        else ProviderStatus.COMPLETED_NO_MATCHES
                    )
                run.result_count = len(findings)
                if run.finished_at is None:
                    run.finished_at = datetime.now(UTC)
                investigation.findings.extend(findings)

                async with self._database.session() as session:
                    run_repo = ProviderRunRepository(session)
                    await run_repo.update_status(
                        run.id,
                        run.status,
                        run.finished_at,
                        run.result_count,
                        run.error_code,
                        run.error_message,
                        run.duration_ms,
                    )

            except Exception as exc:
                if run.status in _TERMINAL_PROVIDER_STATUSES:
                    status = run.status
                    error_code = run.error_code
                    error_message = run.error_message
                    result_count = run.result_count
                    duration_ms = run.duration_ms
                else:
                    status = ProviderStatus.FAILED
                    error_code = "exception"
                    error_message = str(exc)
                    result_count = 0
                    duration_ms = None

                run.status = status
                run.finished_at = run.finished_at or datetime.now(UTC)
                run.error_code = error_code
                run.error_message = error_message
                run.result_count = result_count
                if run.duration_ms is None:
                    run.duration_ms = duration_ms

                async with self._database.session() as session:
                    run_repo = ProviderRunRepository(session)
                    await run_repo.update_status(
                        run.id,
                        status,
                        run.finished_at,
                        result_count,
                        error_code,
                        error_message,
                        run.duration_ms,
                    )

        tasks = [
            run_provider(name, provider, provider_runs[name])
            for name, provider in self._providers.items()
            if name in provider_runs
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _determine_status(runs: list[ProviderRun]) -> InvestigationStatus:
        """Derive the investigation status from provider outcomes."""
        if not runs:
            return InvestigationStatus.FAILED
        successful = sum(run.status in SUCCESSFUL_PROVIDER_STATUSES for run in runs)
        if successful == len(runs):
            return InvestigationStatus.COMPLETE
        if successful:
            return InvestigationStatus.PARTIAL
        return InvestigationStatus.FAILED

    async def _persist_results(self, investigation: Investigation) -> None:
        """Persist final findings, evidence and correlations."""
        async with self._database.session() as session:
            finding_repo = FindingRepository(session)
            evidence_repo = EvidenceRepository(session)
            correlation_repo = CorrelationRepository(session)

            for finding in investigation.findings:
                await finding_repo.create(self._pydantic_to_sqlalchemy_finding(finding))
                for evidence in finding.evidence:
                    evidence.finding_id = finding.id
                    await evidence_repo.create(
                        self._pydantic_to_sqlalchemy_evidence(evidence)
                    )

            for correlation in investigation.correlations:
                await correlation_repo.create(
                    self._pydantic_to_sqlalchemy_correlation(correlation)
                )

    def _process_findings(self, investigation: Investigation) -> None:
        """Deduplicate, correlate, and reassess findings in memory."""
        if not investigation.findings:
            return
        self._deduplicate_findings(investigation)
        self._correlate_findings(investigation)
        self._reassess_findings(investigation)

    @staticmethod
    def _finding_key(finding: Finding) -> str:
        """Build a conservative deduplication key for a finding."""
        key_parts = [
            finding.finding_type.value,
            finding.service_name or "",
            finding.domain or "",
        ]

        if finding.finding_type == FindingType.BREACH_EXPOSURE:
            key_parts.append(str(finding.raw_data.get("breach_name", "")))
        elif finding.finding_type == FindingType.REPOSITORY_EXPOSURE:
            key_parts.append(str(finding.raw_data.get("repository", "")))
            key_parts.append(
                str(
                    finding.raw_data.get("commit_sha")
                    or finding.raw_data.get("file_path")
                    or ""
                )
            )
        elif finding.finding_type == FindingType.PUBLIC_EXPOSURE:
            key_parts.append(str(finding.raw_data.get("url", "")))
        elif finding.finding_type == FindingType.DOMAIN_INTELLIGENCE:
            key_parts.append(str(finding.raw_data.get("record_type", "")))

        return "|".join(key_parts)

    def _deduplicate_findings(self, investigation: Investigation) -> None:
        """Merge duplicate findings while preserving all unique evidence."""
        deduplicated: dict[str, Finding] = {}

        for finding in investigation.findings:
            key = self._finding_key(finding)
            existing = deduplicated.get(key)
            if existing is None:
                deduplicated[key] = finding
                continue

            seen_evidence = {
                (item.provider, item.source_reference, item.evidence_hash)
                for item in existing.evidence
            }
            for evidence in finding.evidence:
                signature = (
                    evidence.provider,
                    evidence.source_reference,
                    evidence.evidence_hash,
                )
                if signature not in seen_evidence:
                    existing.add_evidence(evidence)
                    seen_evidence.add(signature)

        investigation.findings = list(deduplicated.values())

    def _correlate_findings(self, investigation: Investigation) -> None:
        """Correlate findings across providers and types."""
        findings = investigation.findings
        correlations: list[Correlation] = []

        for index, finding_a in enumerate(findings):
            for finding_b in findings[index + 1 :]:
                correlation = self._check_correlation(finding_a, finding_b)
                if correlation:
                    correlation.investigation_id = investigation.id
                    correlations.append(correlation)

        investigation.correlations = correlations

    def _check_correlation(
        self, finding_a: Finding, finding_b: Finding
    ) -> Correlation | None:
        """Check whether two findings are correlated."""
        if (
            finding_a.service_name
            and finding_b.service_name
            and finding_a.service_name.lower() == finding_b.service_name.lower()
        ):
            return Correlation(
                investigation_id=UUID(int=0),
                finding_a_id=finding_a.id,
                finding_b_id=finding_b.id,
                correlation_type=CorrelationType.SAME_SERVICE,
                confidence=Confidence.HIGH,
                notes=f"Both findings from {finding_a.service_name}",
            )

        if (
            finding_a.domain
            and finding_b.domain
            and finding_a.domain.lower() == finding_b.domain.lower()
        ):
            return Correlation(
                investigation_id=UUID(int=0),
                finding_a_id=finding_a.id,
                finding_b_id=finding_b.id,
                correlation_type=CorrelationType.SAME_DOMAIN,
                confidence=Confidence.MEDIUM,
                notes=f"Both findings from domain {finding_a.domain}",
            )

        if (
            finding_a.finding_type == FindingType.BREACH_EXPOSURE
            and finding_b.finding_type == FindingType.BREACH_EXPOSURE
        ):
            breach_a = str(finding_a.raw_data.get("breach_name", ""))
            breach_b = str(finding_b.raw_data.get("breach_name", ""))
            if breach_a and breach_a == breach_b:
                return Correlation(
                    investigation_id=UUID(int=0),
                    finding_a_id=finding_a.id,
                    finding_b_id=finding_b.id,
                    correlation_type=CorrelationType.SAME_PROVIDER_RECORD,
                    confidence=Confidence.VERIFIED,
                    notes=f"Same breach record: {breach_a}",
                )

        return None

    def _reassess_findings(self, investigation: Investigation) -> None:
        """Reassess severity and confidence based on evidence and correlations."""
        for finding in investigation.findings:
            verified_evidence = [
                evidence
                for evidence in finding.evidence
                if evidence.verification_status == VerificationStatus.VERIFIED
            ]
            if verified_evidence and finding.confidence in (
                Confidence.LOW,
                Confidence.UNVERIFIED,
            ):
                finding.confidence = Confidence.MEDIUM
            elif finding.verification_status == VerificationStatus.VERIFIED:
                finding.confidence = Confidence.VERIFIED

            correlated_high = any(
                correlation.confidence in (Confidence.HIGH, Confidence.VERIFIED)
                and correlation.correlation_type
                in (
                    CorrelationType.SAME_SERVICE,
                    CorrelationType.SAME_PROVIDER_RECORD,
                )
                for correlation in investigation.correlations
                if finding.id
                in (correlation.finding_a_id, correlation.finding_b_id)
            )
            if correlated_high and finding.severity == Severity.INFORMATIONAL:
                finding.severity = Severity.LOW

    async def _create_snapshot(self, investigation: Investigation) -> None:
        """Create a historical snapshot for the investigation."""
        finding_ids = [str(finding.id) for finding in investigation.findings]
        findings_hash = self._hash_finding_ids(
            [finding.id for finding in investigation.findings]
        )

        async with self._database.session() as session:
            inv_repo = InvestigationRepository(session)
            if await inv_repo.get(investigation.id) is None:
                raise ValueError(
                    f"Investigation {investigation.id} not found in database"
                )

            snapshot = SnapshotModel(
                investigation_id=investigation.id,
                snapshot_date=datetime.now(UTC),
                findings_hash=findings_hash,
                finding_ids=finding_ids,
            )
            await SnapshotRepository(session).create(snapshot)

    @staticmethod
    def _hash_finding_ids(finding_ids: list[UUID]) -> str:
        """Create a stable hash of finding IDs for change detection."""
        sorted_ids = sorted(str(finding_id) for finding_id in finding_ids)
        return hashlib.sha256("|".join(sorted_ids).encode()).hexdigest()

    async def _audit_event(
        self,
        investigation_id: UUID,
        event_type: str,
        details: dict[str, Any],
    ) -> None:
        """Record a local audit event."""
        async with self._database.session() as session:
            event = AuditEventModel(
                investigation_id=investigation_id,
                event_type=event_type,
                details=details,
            )
            await AuditRepository(session).create(event)


async def run_investigation(
    email: str,
    profile: Profile = Profile.FULL,
    authorization_confirmed: bool = False,
    on_investigation_created: Callable[[Investigation], None] | None = None,
) -> Investigation:
    """Run a complete investigation with a short-lived orchestrator."""
    orchestrator = Orchestrator()
    try:
        await orchestrator.initialize()
        return await orchestrator.run_investigation(
            email,
            profile,
            authorization_confirmed,
            on_investigation_created,
        )
    finally:
        await orchestrator.cleanup()
