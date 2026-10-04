"""
UniGuard Evidence Assessment Schemas (Milestone 7)

Typed Pydantic models for the deterministic Evidence Engine output.
These models represent the explainability layer over the ML and Risk engines.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Any
from pydantic import BaseModel, Field

from backend.app.schemas.risk import Severity


class EvidenceCategory(str, Enum):
    """Categorization of evidence items based on their domain."""
    THREAT_CLASSIFICATION = "THREAT_CLASSIFICATION"
    ANOMALY_SIGNAL = "ANOMALY_SIGNAL"
    TRAFFIC_BEHAVIOR = "TRAFFIC_BEHAVIOR"
    DESTINATION_DIVERSITY = "DESTINATION_DIVERSITY"
    PORT_BEHAVIOR = "PORT_BEHAVIOR"
    PACKET_BEHAVIOR = "PACKET_BEHAVIOR"
    RATE_BEHAVIOR = "RATE_BEHAVIOR"
    MODEL_CONFIDENCE = "MODEL_CONFIDENCE"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"


class EvidenceItem(BaseModel):
    """A single deterministic piece of evidence explaining an observation."""
    evidence_id: str = Field(..., description="Deterministic unique identifier for this evidence")
    category: EvidenceCategory = Field(..., description="Domain category of the evidence")
    title: str = Field(..., description="Short human-readable title")
    description: str = Field(..., description="Detailed deterministic explanation")
    value: Any = Field(..., description="The actual numeric or string value underlying this evidence")
    strength: float = Field(..., description="Deterministic strength/contribution metric [0.0, 1.0]")
    source: str = Field(..., description="Originating component (e.g., 'RandomForest', 'FeatureEngine')")
    severity: Severity = Field(..., description="Severity level suggested by this specific evidence")
    feature_name: Optional[str] = Field(default=None, description="Canonical feature name, if applicable")


class TopFeature(BaseModel):
    """Represents a feature importance value from the model."""
    feature_name: str = Field(..., description="Canonical 16-feature name")
    importance: float = Field(..., description="Importance weight [0.0, 1.0]")


class EvidenceAssessment(BaseModel):
    """
    Structured investigation context detailing WHY a flow received its ML
    classification and risk assessment.
    """
    evidence_id: str = Field(..., description="Deterministic ID for this assessment")
    flow_id: str = Field(..., description="Original DirectionalFlowRecord flow_id")
    threat_type: str = Field(..., description="Preserved ML threat type")
    risk_score: float = Field(..., description="Preserved Risk Engine score")
    severity: Severity = Field(..., description="Preserved Risk Engine severity")
    
    summary: str = Field(..., description="Deterministic human-readable summary of the evidence")
    
    evidence_items: List[EvidenceItem] = Field(default_factory=list, description="All gathered evidence items")
    top_features: List[TopFeature] = Field(default_factory=list, description="Top contributing features")
    
    supporting_signals: List[str] = Field(default_factory=list, description="Signals strongly supporting the threat assessment")
    contradictory_signals: List[str] = Field(default_factory=list, description="Signals in tension with the primary assessment")
    limitations: List[str] = Field(default_factory=list, description="Applicable analytical limitations for this assessment")
