"""MailTrace storage package."""

from mailtrace.storage.database import (
    DatabaseManager,
    close_database,
    get_database_manager,
    init_database,
)
from mailtrace.storage.mappers import investigation_model_to_schema
from mailtrace.storage.models import (
    AuditEventModel,
    BreachRecordModel,
    CorrelationModel,
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ProviderRunModel,
    SnapshotModel,
)
from mailtrace.storage.repositories import (
    AuditRepository,
    CorrelationRepository,
    EvidenceRepository,
    FindingRepository,
    InvestigationRepository,
    ProviderRunRepository,
    SnapshotRepository,
)

__all__ = [
    "AuditEventModel",
    "AuditRepository",
    "BreachRecordModel",
    "CorrelationModel",
    "CorrelationRepository",
    "DatabaseManager",
    "EvidenceModel",
    "EvidenceRepository",
    "FindingModel",
    "FindingRepository",
    "InvestigationModel",
    "InvestigationRepository",
    "ProviderRunModel",
    "ProviderRunRepository",
    "SnapshotModel",
    "SnapshotRepository",
    "close_database",
    "get_database_manager",
    "init_database",
    "investigation_model_to_schema",
]
