"""
Risk Assessment API Endpoint (Milestone 6)

Exposes a single POST /api/risk/assess endpoint that accepts a DirectionalFlowRecord,
runs it through the existing Milestone 5 ML pipeline, then through the Risk Engine,
and returns a RiskAssessment.

No WebSockets, PostgreSQL, live capture, authentication, or automated response is
implemented here.  Those belong to later milestones.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.app.schemas.traffic import DirectionalFlowRecord
from backend.app.schemas.risk import RiskAssessment
from backend.app.schemas.ml import ModelReadinessState
from backend.app.ml.model_manager import get_state
from backend.app.ml.inference import run_inference
from backend.app.core.risk_engine import risk_engine

router = APIRouter(prefix="/risk", tags=["Risk Assessment"])


@router.post("/assess", response_model=RiskAssessment)
def assess_flow(flow: DirectionalFlowRecord) -> RiskAssessment:
    """
    Assess the risk of a single unidirectional flow record.

    Pipeline:
        DirectionalFlowRecord
            → FeatureEngine
            → FeaturePreprocessor
            → RandomForest classifier
            → IsolationForest anomaly detector
            → RiskEngine
            → RiskAssessment

    Returns HTTP 503 if ML models are not yet trained.
    """
    state = get_state()
    if state != ModelReadinessState.READY:
        raise HTTPException(
            status_code=503,
            detail=(
                f"ML models are not ready (state={state.value}). "
                "Train models via the training pipeline first."
            ),
        )

    try:
        ml_result = run_inference(flow)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"ML inference error: {exc}")

    assessment = risk_engine.assess(ml_result)
    return assessment


@router.get("/status")
def get_risk_status() -> dict:
    """Returns the current ML model readiness state for the risk engine."""
    state = get_state()
    return {
        "ml_model_state": state.value,
        "risk_engine": "ready" if state == ModelReadinessState.READY else "waiting_for_models",
    }
