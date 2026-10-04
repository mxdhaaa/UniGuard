"""
UniGuard Risk Assessment Schemas (Milestone 6)

Typed Pydantic models for the deterministic Risk Engine output.
The risk_score is always in [0, 100].
The severity is derived exclusively from the risk_score via fixed thresholds.
"""

from __future__ import annotations

from enum import Enum
from typing import List
from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """SOC severity bands derived from risk_score thresholds."""
    LOW = "LOW"           # risk_score  0 – 24
    MEDIUM = "MEDIUM"     # risk_score 25 – 49
    HIGH = "HIGH"         # risk_score 50 – 74
    CRITICAL = "CRITICAL" # risk_score 75 – 100


class RiskFactor(BaseModel):
    """
    A single traceable contributor to the overall risk score.
    Every factor corresponds to an actual input value or deterministic calculation.
    """
    factor: str = Field(..., description="Short name identifying the risk signal")
    contribution: float = Field(..., description="Numeric contribution (points) this factor added to raw_risk")
    description: str = Field(..., description="Human-readable explanation of why this factor was raised")


class RiskAssessment(BaseModel):
    """
    Deterministic SOC risk assessment produced by the RiskEngine.

    The risk_score is a weighted additive heuristic; it is NOT a machine-learned
    probability of compromise.  See docs/RISK_ENGINE.md for the full formula.
    """

    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Deterministic risk score in [0, 100]",
    )
    severity: Severity = Field(..., description="SOC severity band derived from risk_score")
    threat_type: str = Field(..., description="ML-predicted behavioral threat class")
    confidence: float = Field(..., description="Classifier confidence in [0.0, 1.0]")
    anomaly_score: float = Field(..., description="Normalized IsolationForest anomaly score in [0.0, 1.0]")
    is_anomaly: bool = Field(..., description="IsolationForest outlier flag")
    risk_factors: List[RiskFactor] = Field(
        default_factory=list,
        description="Ordered list of risk signals that contributed to the score",
    )
    explanation: str = Field(..., description="Deterministic human-readable risk summary")
    recommended_action: str = Field(..., description="SOC recommended action for this severity level")

    @field_validator("risk_score")
    @classmethod
    def _clamp_score(cls, v: float) -> float:
        """Guarantee risk_score stays in [0, 100] even if a caller supplies an out-of-range value."""
        return max(0.0, min(100.0, v))
