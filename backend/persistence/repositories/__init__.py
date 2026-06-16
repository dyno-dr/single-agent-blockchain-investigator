"""backend/persistence/repositories — Repository classes."""
from backend.persistence.repositories.base import BaseRepository
from backend.persistence.repositories.evidence_repo import EvidenceRepository
from backend.persistence.repositories.investigation_repo import InvestigationRepository
from backend.persistence.repositories.report_repo import ReportRepository

__all__ = ["BaseRepository", "EvidenceRepository", "InvestigationRepository", "ReportRepository"]
