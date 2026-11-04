"""DNS provider adapter for domain intelligence."""

import contextlib
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import uuid4

import dns.asyncresolver
import dns.exception
import dns.rdatatype

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


class DNSProvider(BaseProvider):
    """DNS provider for domain intelligence (MX, SPF, DMARC, etc.)."""

    name = "dns"
    display_name = "DNS Intelligence"
    requires_auth = False
    supported_profiles: ClassVar[list[str]] = ["domain", "full"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        resolvers = self.config.get("resolvers", ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
        self.resolvers: list[str] = [str(resolver) for resolver in resolvers]
        self.timeout: float = float(self.config.get("timeout", 10.0))
        self.resolver: dns.asyncresolver.Resolver | None = None

    def _get_default_headers(self) -> dict[str, str]:
        return {}

    def _get_base_url(self) -> str:
        return ""

    async def initialize(self) -> None:
        """Initialize DNS resolver."""
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self.resolvers
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        self.resolver = resolver

    async def cleanup(self) -> None:
        """Cleanup resolver."""
        self.resolver = None

    async def health_check(self) -> dict[str, Any]:
        """Check DNS resolution availability."""
        try:
            if not self.resolver:
                await self.initialize()
            assert self.resolver is not None

            # Test with a known domain
            result = await self.resolver.resolve("google.com", "A")
            if result:
                return {"healthy": True, "message": "DNS resolution working", "details": {"nameservers": self.resolvers}}
            return {"healthy": False, "message": "DNS resolution failed", "details": {}}
        except Exception as e:
            return {"healthy": False, "message": f"Health check failed: {e}", "details": {}}

    async def check_email(self, email: str, run: ProviderRun) -> list[Finding]:
        """Perform DNS intelligence on email domain."""
        findings: list[Finding] = []

        domain = self._extract_domain(email)
        if not domain:
            self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)
            return findings

        if not self.resolver:
            await self.initialize()
        assert self.resolver is not None

        try:
            # Run all DNS checks
            mx_records = await self._query_mx(domain)
            spf_records = await self._query_spf(domain)
            dmarc_records = await self._query_dmarc(domain)
            ns_records = await self._query_ns(domain)

            # Create findings for each record type
            if mx_records:
                findings.append(self._create_mx_finding(domain, mx_records, run))

            if spf_records:
                findings.append(self._create_spf_finding(domain, spf_records, run))

            if dmarc_records:
                findings.append(self._create_dmarc_finding(domain, dmarc_records, run))

            if ns_records:
                findings.append(self._create_ns_finding(domain, ns_records, run))

            # Update run status
            if findings:
                run.result_count = len(findings)
                self._update_run_status(run, ProviderStatus.COMPLETED_WITH_FINDINGS)
            else:
                self._update_run_status(run, ProviderStatus.COMPLETED_NO_MATCHES)

        except Exception as e:
            self._update_run_status(run, ProviderStatus.FAILED, "error", str(e))
            raise

        return findings

    async def _query_mx(self, domain: str) -> list[dict[str, Any]]:
        """Query MX records."""
        assert self.resolver is not None
        try:
            result = await self.resolver.resolve(domain, "MX")
            return [
                {
                    "preference": r.preference,
                    "exchange": str(r.exchange).rstrip("."),
                }
                for r in result
            ]
        except (dns.exception.DNSException, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []

    async def _query_spf(self, domain: str) -> list[str]:
        """Query SPF records (TXT records starting with v=spf1)."""
        assert self.resolver is not None
        try:
            result = await self.resolver.resolve(domain, "TXT")
            spf_records = []
            for r in result:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
                if txt.startswith("v=spf1"):
                    spf_records.append(txt)
            return spf_records
        except (dns.exception.DNSException, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []

    async def _query_dmarc(self, domain: str) -> list[str]:
        """Query DMARC records (_dmarc.domain TXT)."""
        assert self.resolver is not None
        try:
            dmarc_domain = f"_dmarc.{domain}"
            result = await self.resolver.resolve(dmarc_domain, "TXT")
            dmarc_records = []
            for r in result:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
                if txt.startswith("v=DMARC1"):
                    dmarc_records.append(txt)
            return dmarc_records
        except (dns.exception.DNSException, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []

    async def _query_ns(self, domain: str) -> list[str]:
        """Query NS records."""
        assert self.resolver is not None
        try:
            result = await self.resolver.resolve(domain, "NS")
            return [str(r.target).rstrip(".") for r in result]
        except (dns.exception.DNSException, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []

    def _create_mx_finding(
        self, domain: str, mx_records: list[dict[str, Any]], run: ProviderRun
    ) -> Finding:
        """Create finding for MX records."""
        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.DOMAIN_INTELLIGENCE,
            title=f"MX records for {domain}",
            service_name="DNS",
            domain=domain,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.VERIFIED,
            verification_status=VerificationStatus.VERIFIED,
            raw_data={
                "record_type": "MX",
                "records": mx_records,
                "count": len(mx_records),
            },
        )

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_reference=f"MX:{domain}",
            evidence_type=EvidenceType.DNS_RECORD,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(f"MX_{domain}_{len(mx_records)}"),
            notes=f"{len(mx_records)} MX record(s) found",
        )
        finding.add_evidence(evidence)

        return finding

    def _create_spf_finding(self, domain: str, spf_records: list[str], run: ProviderRun) -> Finding:
        """Create finding for SPF record."""
        # Analyze SPF record
        spf_record = spf_records[0] if spf_records else ""
        spf_analysis = self._analyze_spf(spf_record)

        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.DOMAIN_INTELLIGENCE,
            title=f"SPF record for {domain}",
            service_name="DNS",
            domain=domain,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.VERIFIED,
            verification_status=VerificationStatus.VERIFIED,
            raw_data={
                "record_type": "SPF",
                "records": spf_records,
                "analysis": spf_analysis,
            },
        )

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_reference=f"SPF:{domain}",
            evidence_type=EvidenceType.DNS_RECORD,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(f"SPF_{domain}_{spf_record}"),
            notes=f"SPF: {spf_record[:100]}",
        )
        finding.add_evidence(evidence)

        return finding

    def _create_dmarc_finding(self, domain: str, dmarc_records: list[str], run: ProviderRun) -> Finding:
        """Create finding for DMARC record."""
        dmarc_record = dmarc_records[0] if dmarc_records else ""
        dmarc_analysis = self._analyze_dmarc(dmarc_record)

        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.DOMAIN_INTELLIGENCE,
            title=f"DMARC record for {domain}",
            service_name="DNS",
            domain=domain,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.VERIFIED,
            verification_status=VerificationStatus.VERIFIED,
            raw_data={
                "record_type": "DMARC",
                "records": dmarc_records,
                "analysis": dmarc_analysis,
            },
        )

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_reference=f"DMARC:{domain}",
            evidence_type=EvidenceType.DNS_RECORD,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(f"DMARC_{domain}_{dmarc_record}"),
            notes=f"DMARC: {dmarc_record[:100]}",
        )
        finding.add_evidence(evidence)

        return finding

    def _create_ns_finding(self, domain: str, ns_records: list[str], run: ProviderRun) -> Finding:
        """Create finding for NS records."""
        finding = self._create_finding(
            investigation_id=run.investigation_id,
            finding_type=FindingType.DOMAIN_INTELLIGENCE,
            title=f"Nameservers for {domain}",
            service_name="DNS",
            domain=domain,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.VERIFIED,
            verification_status=VerificationStatus.VERIFIED,
            raw_data={
                "record_type": "NS",
                "records": ns_records,
                "count": len(ns_records),
            },
        )

        evidence = EvidenceRecord(
            id=uuid4(),
            provider=self.name,
            source_reference=f"NS:{domain}",
            evidence_type=EvidenceType.DNS_RECORD,
            verification_status=VerificationStatus.VERIFIED,
            collected_at=datetime.now(UTC),
            verified_at=datetime.now(UTC),
            evidence_hash=self._create_evidence_hash(f"NS_{domain}_{len(ns_records)}"),
            notes=f"{len(ns_records)} nameserver(s) found",
        )
        finding.add_evidence(evidence)

        return finding

    def _analyze_spf(self, spf_record: str) -> dict[str, Any]:
        """Analyze SPF record for common issues."""
        analysis: dict[str, Any] = {
            "record": spf_record,
            "has_all": False,
            "all_mechanism": None,
            "includes": [],
            "ip4": [],
            "ip6": [],
            "redirect": None,
            "issues": [],
        }

        parts = spf_record.split()
        for part in parts:
            if part == "v=spf1":
                continue
            if part.startswith("include:"):
                analysis["includes"].append(part[8:])
            elif part.startswith("ip4:"):
                analysis["ip4"].append(part[4:])
            elif part.startswith("ip6:"):
                analysis["ip6"].append(part[4:])
            elif part.startswith("redirect="):
                analysis["redirect"] = part[9:]
            elif part in ("-all", "~all", "+all", "?all"):
                analysis["has_all"] = True
                analysis["all_mechanism"] = part

        if not analysis["has_all"]:
            analysis["issues"].append("No 'all' mechanism defined")

        if analysis["all_mechanism"] == "+all":
            analysis["issues"].append("Permissive '+all' mechanism allows any sender")

        return analysis

    def _analyze_dmarc(self, dmarc_record: str) -> dict[str, Any]:
        """Analyze DMARC record."""
        analysis: dict[str, Any] = {
            "record": dmarc_record,
            "policy": None,
            "subdomain_policy": None,
            "percentage": 100,
            "rua": [],
            "ruf": [],
            "alignment": {"dkim": "r", "spf": "r"},
            "issues": [],
        }

        parts = dmarc_record.split(";")
        for part in parts:
            part = part.strip()
            if part.startswith("v="):
                continue
            if part.startswith("p="):
                analysis["policy"] = part[2:]
            elif part.startswith("sp="):
                analysis["subdomain_policy"] = part[3:]
            elif part.startswith("pct="):
                with contextlib.suppress(ValueError):
                    analysis["percentage"] = int(part[4:])
            elif part.startswith("rua="):
                analysis["rua"].append(part[4:])
            elif part.startswith("ruf="):
                analysis["ruf"].append(part[4:])
            elif part.startswith("adkim="):
                analysis["alignment"]["dkim"] = part[6:]
            elif part.startswith("aspf="):
                analysis["alignment"]["spf"] = part[5:]

        if not analysis["policy"]:
            analysis["issues"].append("No policy defined")
        elif analysis["policy"] == "none":
            analysis["issues"].append("Policy is 'none' (monitoring only)")

        if analysis["subdomain_policy"] == "none":
            analysis["issues"].append("Subdomain policy is 'none'")

        return analysis

    def _extract_domain(self, email: str) -> str | None:
        """Extract domain from email."""
        try:
            return email.split("@", 1)[1].lower()
        except (ValueError, IndexError):
            return None
