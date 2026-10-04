"""
Schemas for Demo Mode & Synthetic Traffic Pipeline
Provides request/response DTOs for demo controller and synthetic flow generation.
"""

from typing import Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field
from backend.app.schemas.traffic import DirectionalFlowRecord, FeatureVector, PreprocessedFeatureVector


class DemoState(str, Enum):
    STOPPED = "STOPPED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"


class DemoStatusResponse(BaseModel):
    state: DemoState = Field(..., description="Current operational state of demo generator")
    generated_flows: int = Field(default=0, ge=0, description="Total synthetic flows generated in current session")
    seed: Optional[int] = Field(default=None, description="Current PRNG seed if configured")
    active_profile_mix: Dict[str, float] = Field(default_factory=dict, description="Active profile mix ratio")
    disclaimer: str = Field(
        default="Demo traffic is synthetic and is not evidence of real-world malicious activity.",
        description="Defensive non-offensive disclaimer",
    )


class DemoStartRequest(BaseModel):
    seed: Optional[int] = Field(default=42, description="Optional integer seed for reproducible synthetic generation")
    profile_mix: Optional[Dict[str, float]] = Field(default=None, description="Optional custom profile distribution weights")


class DemoBatchRequest(BaseModel):
    count: int = Field(default=20, ge=1, le=1000, description="Number of synthetic flows to generate")
    profile_mix: Optional[Dict[str, float]] = Field(default=None, description="Profile distribution weights")
    seed: Optional[int] = Field(default=None, description="Optional PRNG seed for deterministic batch")


class DemoResultItem(BaseModel):
    flow: DirectionalFlowRecord = Field(..., description="Generated synthetic unidirectional flow record")
    features: FeatureVector = Field(..., description="Extracted 16-feature behavioral vector")
    preprocessed: PreprocessedFeatureVector = Field(..., description="Sanitized ordered numeric feature vector")
    simulated_profile: str = Field(..., description="Simulated behavioral profile label (metadata only)")
