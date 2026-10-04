"""
Evidence Assessment API Endpoint (Milestone 7)

Exposes a POST /api/evidence/assess endpoint that accepts a DirectionalFlowRecord,
runs it through ML inference, Risk Engine, and finally the Evidence Engine.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.app.schemas.traffic import DirectionalFlowRecord
from backend.app.schemas.evidence import EvidenceAssessment
from backend.app.schemas.ml import ModelReadinessState
from backend.app.ml.model_manager import get_state
from backend.app.ml.inference import run_inference
from backend.app.core.risk_engine import risk_engine
from backend.app.core.evidence_engine import evidence_engine

router = APIRouter(prefix="/evidence", tags=["Evidence Assessment"])


@router.post("/assess", response_model=EvidenceAssessment)
def assess_evidence(flow: DirectionalFlowRecord) -> EvidenceAssessment:
    """
    Generate a full SOC evidence assessment for a single flow.

    Pipeline:
        DirectionalFlowRecord
            → ML Inference (RandomForest + IsolationForest)
            → Risk Engine
            → Evidence Engine
            → EvidenceAssessment

    Returns HTTP 503 if ML models are not yet trained.
    """
    state = get_state()
    if state != ModelReadinessState.READY:
        raise HTTPException(
            status_code=503,
            detail="ML models are not ready. Train models via the training pipeline first.",
        )

    try:
        ml_result = run_inference(flow)
        risk_assessment = risk_engine.assess(ml_result)
        evidence = evidence_engine.assess(flow, ml_result, risk_assessment)
        return evidence
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evidence generation error: {exc}")
