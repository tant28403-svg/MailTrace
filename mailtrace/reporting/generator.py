"""Report generation for MailTrace."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any
from xml.sax.saxutils import escape

from mailtrace import __version__
from mailtrace.schemas.finding import (
    ExportFormat,
    Investigation,
    ProviderStatus,
    ReportOptions,
    VerificationStatus,
)


class ReportGenerator:
    """Generate investigation reports in various formats."""

    def __init__(self, investigation: Investigation):
        self.investigation = investigation

    def generate(self, options: ReportOptions) -> str | bytes:
        """Generate a report based on the requested options."""
        if options.format == ExportFormat.JSON:
            return self._generate_json(options)
        if options.format == ExportFormat.CSV:
            return self._generate_csv(options)
        if options.format == ExportFormat.PDF:
            return self._generate_pdf(options)
        if options.format == ExportFormat.TERMINAL:
            return self._generate_terminal(options)
        raise ValueError(f"Unsupported format: {options.format}")

    def _display_target(self, options: ReportOptions) -> str:
        """Return the target appropriate for the requested masking level.

        The full address is intentionally never persisted, so saved cases can
        only ever display the masked form.
        """
        if options.mask_target:
            return self.investigation.target_masked
        return self.investigation.target_email or self.investigation.target_masked

    def _generate_json(self, options: ReportOptions) -> str:
        """Generate a JSON report."""
        data = self._build_report_data(options)
        return json.dumps(data, indent=2, default=str)

    def _generate_csv(self, options: ReportOptions) -> str:
        """Generate a CSV report."""
        output = io.StringIO(newline="")
        writer = csv.writer(output)

        header = [
            "Target",
            "Finding ID",
            "Type",
            "Title",
            "Service",
            "Domain",
            "Severity",
            "Confidence",
            "Verification",
            "First Observed",
            "Collected",
            "Evidence Count",
        ]
        if options.include_evidence:
            header.extend(["Provider(s)", "Source URLs"])
        writer.writerow(header)

        for finding in self.investigation.findings:
            row = [
                self._display_target(options),
                str(finding.id),
                finding.finding_type.value,
                finding.title,
                finding.service_name or "",
                finding.domain or "",
                finding.severity.value,
                finding.confidence.value,
                finding.verification_status.value,
                finding.first_observed_at.isoformat() if finding.first_observed_at else "",
                finding.collected_at.isoformat(),
                len(finding.evidence),
            ]
            if options.include_evidence:
                providers = sorted({evidence.provider for evidence in finding.evidence})
                urls = [
                    str(evidence.source_url)
                    for evidence in finding.evidence
                    if evidence.source_url
                ]
                row.extend([", ".join(providers), "; ".join(urls)])
            writer.writerow(row)

        return output.getvalue()

    def _generate_pdf(self, options: ReportOptions) -> bytes:
        """Generate a PDF report."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_LEFT
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:
            raise RuntimeError(
                "PDF generation requires the 'reportlab' package. "
                "Install it with: uv sync --extra report"
            ) from exc

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )
        styles = getSampleStyleSheet()
        story: list[Any] = []

        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=24,
            textColor=colors.HexColor("#1a1a2e"),
            spaceAfter=6,
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#16213e"),
            spaceBefore=12,
            spaceAfter=6,
        )
        subheading_style = ParagraphStyle(
            "CustomSubHeading",
            parent=styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#0f3460"),
            spaceBefore=8,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "CustomBody",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            spaceAfter=4,
            alignment=TA_LEFT,
        )
        mono_style = ParagraphStyle(
            "Mono",
            parent=styles["Code"],
            fontSize=9,
            fontName="Courier",
            leading=12,
        )

        story.append(Paragraph("MailTrace Investigation Report", title_style))
        story.append(Spacer(1, 12))

        meta_data = [
            ["Case ID", escape(str(self.investigation.id))],
            ["Target", escape(self._display_target(options))],
            ["Profile", escape(self.investigation.profile.value.title())],
            ["Status", escape(self.investigation.status.value.title())],
            ["Created", self.investigation.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
            [
                "Completed",
                self.investigation.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if self.investigation.completed_at
                else "N/A",
            ],
            ["Total Findings", str(len(self.investigation.findings))],
            ["Providers Run", str(len(self.investigation.provider_runs))],
        ]

        meta_table = Table(meta_data, colWidths=[1.5 * inch, 4.5 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1a1a2e")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 20))

        story.append(Paragraph("Provider Summary", heading_style))
        prov_data = [["Provider", "Status", "Findings", "Duration"]]
        for run in self.investigation.provider_runs:
            prov_data.append(
                [
                    escape(run.provider.replace("_", " ").title()),
                    escape(run.status.value.replace("_", " ").title()),
                    str(run.result_count),
                    f"{run.duration_ms}ms" if run.duration_ms else "—",
                ]
            )

        prov_table = Table(
            prov_data, colWidths=[1.5 * inch, 1.5 * inch, 1 * inch, 1.5 * inch]
        )
        prov_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(prov_table)
        story.append(Spacer(1, 20))

        story.append(Paragraph("Findings Summary", heading_style))
        severity_counts = self._count_by_severity()
        sev_data = [["Severity", "Count"]]
        for severity in ("critical", "high", "medium", "low", "informational"):
            if severity in severity_counts:
                sev_data.append([severity.title(), str(severity_counts[severity])])

        sev_table = Table(sev_data, colWidths=[2 * inch, 1 * inch])
        sev_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                ]
            )
        )
        story.append(sev_table)
        story.append(Spacer(1, 20))

        if options.include_evidence:
            story.append(Paragraph("Detailed Findings", heading_style))
            for finding in self.investigation.findings:
                story.append(
                    Paragraph(
                        f"Finding: {escape(finding.title)}",
                        subheading_style,
                    )
                )

                find_data = [
                    ["Type", escape(finding.finding_type.value.replace("_", " ").title())],
                    ["Service", escape(finding.service_name or "N/A")],
                    ["Domain", escape(finding.domain or "N/A")],
                    ["Severity", finding.severity.value.title()],
                    ["Confidence", finding.confidence.value.title()],
                    ["Verification", finding.verification_status.value.title()],
                    [
                        "First Observed",
                        finding.first_observed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                        if finding.first_observed_at
                        else "N/A",
                    ],
                    ["Collected", finding.collected_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
                ]

                find_table = Table(find_data, colWidths=[1.5 * inch, 4.5 * inch])
                find_table.setStyle(
                    TableStyle(
                        [
                            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 9),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
                        ]
                    )
                )
                story.append(find_table)
                story.append(Spacer(1, 8))

                if finding.evidence:
                    story.append(
                        Paragraph(
                            "Evidence:",
                            ParagraphStyle(
                                "EvidenceLabel",
                                parent=body_style,
                                fontSize=10,
                                textColor=colors.HexColor("#16213e"),
                            ),
                        )
                    )
                    for evidence in finding.evidence:
                        ev_text = (
                            f"• <b>{escape(evidence.provider)}</b> — "
                            f"{evidence.evidence_type.value.replace('_', ' ').title()} — "
                            f"{evidence.verification_status.value.title()}"
                        )
                        if evidence.source_url:
                            url = escape(str(evidence.source_url))
                            ev_text += f" — {url}"
                        story.append(Paragraph(ev_text, mono_style))
                    story.append(Spacer(1, 12))

        if options.include_raw:
            story.append(Paragraph("Raw Finding Data", heading_style))
            for finding in self.investigation.findings:
                if finding.raw_data:
                    story.append(
                        Paragraph(
                            escape(json.dumps(finding.raw_data, indent=2, default=str)).replace(
                                "\n", "<br/>"
                            ),
                            mono_style,
                        )
                    )

        doc.build(story)
        buffer.seek(0)
        return buffer.read()

    def _generate_terminal(self, options: ReportOptions) -> str:
        """Generate a terminal-friendly report."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        output = io.StringIO()
        console = Console(
            record=True,
            width=120,
            file=output,
            color_system=None,
        )

        console.print(
            Panel.fit(
                f"[bold cyan]MailTrace Investigation Report[/bold cyan]\n"
                f"Case ID: {self.investigation.id}\n"
                f"Target: {self._display_target(options)}\n"
                f"Profile: {self.investigation.profile.value.title()}\n"
                f"Status: {self.investigation.status.value.title()}\n"
                f"Created: {self.investigation.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"Completed: "
                + (
                    self.investigation.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                    if self.investigation.completed_at
                    else "N/A"
                ),
                title="Investigation Summary",
                border_style="cyan",
            )
        )

        prov_table = Table(
            title="Provider Results", show_header=True, header_style="bold cyan"
        )
        prov_table.add_column("Provider")
        prov_table.add_column("Status")
        prov_table.add_column("Findings", justify="right")
        prov_table.add_column("Duration")

        for run in self.investigation.provider_runs:
            status_style = self._get_rich_status_style(run.status)
            prov_table.add_row(
                run.provider.replace("_", " ").title(),
                f"[{status_style}]{run.status.value.replace('_', ' ').title()}[/{status_style}]",
                str(run.result_count),
                f"{run.duration_ms}ms" if run.duration_ms else "—",
            )
        console.print(prov_table)
        console.print()

        severity_counts = self._count_by_severity()
        sev_table = Table(
            title="Findings by Severity", show_header=True, header_style="bold cyan"
        )
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")

        for severity in ("critical", "high", "medium", "low", "informational"):
            if severity in severity_counts:
                color = self._get_severity_color(severity)
                sev_table.add_row(
                    f"[{color}]{severity.title()}[/{color}]",
                    str(severity_counts[severity]),
                )
        console.print(sev_table)
        console.print()

        if self.investigation.findings:
            find_table = Table(
                title="Findings", show_header=True, header_style="bold cyan"
            )
            find_table.add_column("Type")
            find_table.add_column("Title")
            find_table.add_column("Service")
            find_table.add_column("Domain")
            find_table.add_column("Severity")
            find_table.add_column("Confidence")
            find_table.add_column("Verified")

            for finding in self.investigation.findings:
                sev_color = self._get_severity_color(finding.severity.value)
                conf_color = self._get_confidence_color(finding.confidence.value)
                find_table.add_row(
                    finding.finding_type.value.replace("_", " ").title(),
                    finding.title[:60] + ("..." if len(finding.title) > 60 else ""),
                    finding.service_name or "—",
                    finding.domain or "—",
                    f"[{sev_color}]{finding.severity.value.title()}[/{sev_color}]",
                    f"[{conf_color}]{finding.confidence.value.title()}[/{conf_color}]",
                    "Yes"
                    if finding.verification_status == VerificationStatus.VERIFIED
                    else "Pending",
                )
            console.print(find_table)
            console.print()

        if options.include_evidence:
            for finding in self.investigation.findings:
                if not finding.evidence:
                    continue
                console.print(f"\n[bold]Evidence for: {finding.title}[/bold]")
                ev_table = Table(show_header=True, header_style="bold cyan")
                ev_table.add_column("Provider")
                ev_table.add_column("Type")
                ev_table.add_column("Status")
                ev_table.add_column("Source")
                ev_table.add_column("Collected")
                ev_table.add_column("Verified")

                for evidence in finding.evidence:
                    ev_table.add_row(
                        evidence.provider,
                        evidence.evidence_type.value.replace("_", " ").title(),
                        evidence.verification_status.value.title(),
                        evidence.source_reference
                        or (str(evidence.source_url) if evidence.source_url else "—"),
                        evidence.collected_at.strftime("%Y-%m-%d %H:%M:%S"),
                        evidence.verified_at.strftime("%Y-%m-%d %H:%M:%S")
                        if evidence.verified_at
                        else "—",
                    )
                console.print(ev_table)

        if options.include_raw:
            for finding in self.investigation.findings:
                if finding.raw_data:
                    console.print(f"\n[bold]Raw data for: {finding.title}[/bold]")
                    console.print_json(data=finding.raw_data)

        console.export_text()
        return output.getvalue()

    @staticmethod
    def _get_rich_status_style(status: ProviderStatus) -> str:
        """Get Rich style for provider status."""
        styles = {
            ProviderStatus.COMPLETED_WITH_FINDINGS: "green",
            ProviderStatus.COMPLETED_NO_MATCHES: "green",
            ProviderStatus.UNAUTHORIZED: "red",
            ProviderStatus.RATE_LIMITED: "yellow",
            ProviderStatus.UNAVAILABLE: "red",
            ProviderStatus.TIMEOUT: "yellow",
            ProviderStatus.FAILED: "red",
            ProviderStatus.PENDING: "dim",
            ProviderStatus.RUNNING: "blue",
            ProviderStatus.CONFIGURATION_ERROR: "red",
            ProviderStatus.UNSUPPORTED: "yellow",
            ProviderStatus.PARTIAL: "yellow",
        }
        return styles.get(status, "white")

    @staticmethod
    def _get_severity_color(severity: str) -> str:
        """Get Rich color for severity."""
        colors = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "green",
            "informational": "blue",
        }
        return colors.get(severity, "white")

    @staticmethod
    def _get_confidence_color(confidence: str) -> str:
        """Get Rich color for confidence."""
        colors = {
            "verified": "green",
            "high": "blue",
            "medium": "yellow",
            "low": "orange3",
            "unverified": "dim",
        }
        return colors.get(confidence, "white")

    def _build_report_data(self, options: ReportOptions) -> dict[str, Any]:
        """Build the JSON report data structure."""
        findings = []
        for finding in self.investigation.findings:
            item: dict[str, Any] = {
                "id": str(finding.id),
                "type": finding.finding_type.value,
                "title": finding.title,
                "service": finding.service_name,
                "domain": finding.domain,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "verification": finding.verification_status.value,
                "first_observed": finding.first_observed_at.isoformat()
                if finding.first_observed_at
                else None,
                "collected": finding.collected_at.isoformat(),
            }
            if options.include_evidence:
                item["evidence"] = [
                    {
                        "provider": evidence.provider,
                        "type": evidence.evidence_type.value,
                        "status": evidence.verification_status.value,
                        "source_url": str(evidence.source_url)
                        if evidence.source_url
                        else None,
                        "source_reference": evidence.source_reference,
                        "collected": evidence.collected_at.isoformat(),
                        "verified": evidence.verified_at.isoformat()
                        if evidence.verified_at
                        else None,
                    }
                    for evidence in finding.evidence
                ]
            if options.include_raw:
                item["raw_data"] = finding.raw_data
            findings.append(item)

        return {
            "investigation": {
                "id": str(self.investigation.id),
                "target": self._display_target(options),
                "profile": self.investigation.profile.value,
                "status": self.investigation.status.value,
                "created_at": self.investigation.created_at.isoformat(),
                "completed_at": self.investigation.completed_at.isoformat()
                if self.investigation.completed_at
                else None,
                "authorization_confirmed": self.investigation.authorization_confirmed,
            },
            "providers": [
                {
                    "provider": run.provider,
                    "status": run.status.value,
                    "result_count": run.result_count,
                    "duration_ms": run.duration_ms,
                    "error_code": run.error_code,
                    "error_message": run.error_message,
                }
                for run in self.investigation.provider_runs
            ],
            "findings": findings,
            "summary": {
                "total_findings": len(self.investigation.findings),
                "by_severity": self._count_by_severity(),
                "by_confidence": self._count_by_confidence(),
                "by_type": self._count_by_type(),
            },
            "generated_at": datetime.now(UTC).isoformat(),
            "version": __version__,
        }

    def _count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.investigation.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    def _count_by_confidence(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.investigation.findings:
            counts[finding.confidence.value] = counts.get(finding.confidence.value, 0) + 1
        return counts

    def _count_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.investigation.findings:
            counts[finding.finding_type.value] = (
                counts.get(finding.finding_type.value, 0) + 1
            )
        return counts
