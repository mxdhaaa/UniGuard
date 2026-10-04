"""
UniGuard Investigation Schemas (Milestone 13)

Typed Pydantic response models for the deterministic Reports & Investigation layer.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class InvestigationSubject(BaseModel):
    """Subject of the investigation: target flow and optional associated alert."""
    investigation_id: str = Field(..., description="Unique investigation identifier")
    flow_id: str = Field(..., description="Target traffic flow identifier")
    alert_id: Optional[str] = Field(default=None, description="Associated alert identifier if triggered")


class InvestigationFinding(BaseModel):
    """A single deterministic finding derived strictly from persisted records."""
    finding_id: str = Field(..., description="Unique finding identifier")
    category: str = Field(..., description="Finding category (e.g. CLASSIFICATION, ANOMALY, RISK, TRAFFIC_BEHAVIOR, EVIDENCE, ALERT)")
    title: str = Field(..., description="Concise summary title of the finding")
    description: str = Field(..., description="Detailed explanation of the finding")
    severity: str = Field(..., description="Severity band: LOW, MEDIUM, HIGH, CRITICAL")
    source: str = Field(..., description="Subsystem or source that produced the underlying fact")


class InvestigationTimelineEvent(BaseModel):
    """Chronological event anchored to a persisted database timestamp."""
    timestamp: str = Field(..., description="ISO 8601 timestamp of the event")
    event_type: str = Field(..., description="Type of event (e.g. FLOW_OBSERVED, EVIDENCE_RECORDED, ALERT_GENERATED)")
    title: str = Field(..., description="Concise event title")
    description: str = Field(..., description="Descriptive detail of the event")
    severity: str = Field(..., description="Associated severity: LOW, MEDIUM, HIGH, CRITICAL")
    source: str = Field(..., description="Source subsystem")


class InvestigationResponse(BaseModel):
    """Comprehensive investigation response model for SOC analysis."""
    subject: InvestigationSubject
    flow: Dict[str, Any]
    features: Dict[str, Any]
    ml_assessment: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    findings: List[InvestigationFinding]
    timeline: List[InvestigationTimelineEvent]
    summary: str
    recommended_action: str
    limitations: List[str]
