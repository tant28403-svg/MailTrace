"""Initial schema migration.

Revision ID: 0001
Revises:
Create Date: 2026-11-03 00:00:00.000000

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all tables."""
    # Investigations table
    op.create_table(
        "investigations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("target_hash", sa.String(64), nullable=False),
        sa.Column("target_masked", sa.String(255), nullable=False),
        sa.Column("profile", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_investigations_created_at", "investigations", ["created_at"])
    op.create_index("ix_investigations_target_hash", "investigations", ["target_hash"])

    # Provider runs table
    op.create_table(
        "provider_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "provider", name="uq_investigation_provider"),
    )
    op.create_index("ix_provider_runs_investigation_provider", "provider_runs", ["investigation_id", "provider"])

    # Findings table
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("finding_type", sa.String(32), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("service_name", sa.String(255), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="informational"),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="unverified"),
        sa.Column("verification_status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_investigation_type", "findings", ["investigation_id", "finding_type"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_domain", "findings", ["domain"])

    # Evidence table
    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("source_reference", sa.String(512), nullable=True),
        sa.Column("evidence_type", sa.String(32), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=True),
        sa.Column("verification_status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_finding", "evidence", ["finding_id"])
    op.create_index("ix_evidence_provider", "evidence", ["provider"])

    # Breach records table
    op.create_table(
        "breach_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("breach_name", sa.String(255), nullable=False),
        sa.Column("breach_domain", sa.String(255), nullable=True),
        sa.Column("breach_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovery_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("data_classes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("provider_status", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id"),
    )

    # Correlations table
    op.create_table(
        "correlations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("finding_a_id", sa.Uuid(), nullable=False),
        sa.Column("finding_b_id", sa.Uuid(), nullable=False),
        sa.Column("correlation_type", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_a_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_b_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_a_id", "finding_b_id", "correlation_type", name="uq_correlation"),
    )
    op.create_index("ix_correlations_investigation", "correlations", ["investigation_id"])
    op.create_index("ix_correlations_findings", "correlations", ["finding_a_id", "finding_b_id"])

    # Snapshots table
    op.create_table(
        "snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("findings_hash", sa.String(64), nullable=False),
        sa.Column("finding_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_snapshots_investigation_date", "snapshots", ["investigation_id", "snapshot_date"])

    # Audit events table
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_investigation", "audit_events", ["investigation_id"])
    op.create_index("ix_audit_events_type", "audit_events", ["event_type"])


def downgrade() -> None:
    """Drop all tables."""
    op.drop_index("ix_audit_events_type", table_name="audit_events")
    op.drop_index("ix_audit_events_investigation", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_snapshots_investigation_date", table_name="snapshots")
    op.drop_table("snapshots")

    op.drop_index("ix_correlations_findings", table_name="correlations")
    op.drop_index("ix_correlations_investigation", table_name="correlations")
    op.drop_table("correlations")

    op.drop_table("breach_records")

    op.drop_index("ix_evidence_provider", table_name="evidence")
    op.drop_index("ix_evidence_finding", table_name="evidence")
    op.drop_table("evidence")

    op.drop_index("ix_findings_domain", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_investigation_type", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_provider_runs_investigation_provider", table_name="provider_runs")
    op.drop_table("provider_runs")

    op.drop_index("ix_investigations_target_hash", table_name="investigations")
    op.drop_index("ix_investigations_created_at", table_name="investigations")
    op.drop_table("investigations")
