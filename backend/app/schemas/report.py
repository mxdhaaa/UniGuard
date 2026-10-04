"""
UniGuard Report Schemas (Milestone 13)

Typed Pydantic response models for structured SOC investigation reports.
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field

from backend.app.schemas.investigation import InvestigationSubject, InvestigationFinding


class ReportResponse(BaseModel):
    """Structured JSON investigation report response."""
    report_id: str = Field(..., description="Unique report identifier")
    report_type: str = Field(..., description="Type of report: FLOW_INVESTIGATION or ALERT_INVESTIGATION")
    generated_at: str = Field(..., description="ISO 8601 timestamp when report was generated")
    subject: InvestigationSubject = Field(..., description="Target flow and optional alert metadata")
    executive_summary: str = Field(..., description="Deterministic factual summary of the incident")
    classification: Dict[str, Any] = Field(..., description="Persisted ML classification details")
    risk: Dict[str, Any] = Field(..., description="Persisted deterministic risk evaluation details")
    anomaly: Dict[str, Any] = Field(..., description="Persisted IsolationForest anomaly score and outlier status")
    evidence: List[Dict[str, Any]] = Field(..., description="Persisted explainability evidence items")
    findings: List[InvestigationFinding] = Field(..., description="Deterministic findings extracted from persisted data")
    recommended_action: str = Field(..., description="SOC recommended action derived from persisted risk assessment")
    limitations: List[str] = Field(..., description="Explicit methodological constraints and boundary limitations")
