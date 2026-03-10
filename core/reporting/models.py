# core/reporting/models.py
"""Data models for the ReportingEngine."""
from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AnalysisSummary(BaseModel):
    """High-level summary of the full pipeline analysis."""
    contract_address: str
    is_vulnerable: bool
    vulnerability_count: int
    actionable_vulnerability_count: int
    confirmed_exploit_count: int
    total_estimated_loss_usd: float
    obfuscation_detected: bool
    coverage_improvement: float  # percentage points
    analysis_duration_seconds: float
    mode_used: str  # "concolic" or "symbolic"

    @property
    def risk_level(self) -> str:
        """Compute risk level from exploit/vulnerability counts and loss."""
        if self.confirmed_exploit_count == 0 and self.actionable_vulnerability_count == 0:
            return "none"
        elif self.confirmed_exploit_count > 0 and self.total_estimated_loss_usd > 1_000_000:
            return "critical"
        elif self.confirmed_exploit_count > 0:
            return "high"
        elif self.actionable_vulnerability_count > 0:
            return "medium"
        return "low"


class ReportFiles(BaseModel):
    """Paths to the generated report files."""
    report_files: List[str] = Field(default_factory=list)
    summary: Optional[AnalysisSummary] = None
