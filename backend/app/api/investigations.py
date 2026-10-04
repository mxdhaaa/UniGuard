"""
UniGuard Investigation API Routes (Milestone 13)

Read-only endpoints for SOC deep-dive investigations:
- Flow-level investigation: /api/investigations/flows/{flow_id}
- Alert-level investigation: /api/investigations/alerts/{alert_id}
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.schemas.investigation import InvestigationResponse
from backend.app.services.investigation_service import investigation_service

router = APIRouter(prefix="/investigations", tags=["Investigations"])


@router.get(
    "/flows/{flow_id}",
    response_model=InvestigationResponse,
    summary="Get flow investigation",
    description="Returns deep-dive investigation data for a specific traffic flow including deterministic summary, findings, and evidence timeline.",
)
def get_flow_investigation(
    flow_id: str, db: Session = Depends(get_db)
) -> InvestigationResponse:
    investigation = investigation_service.get_flow_investigation(db, flow_id)
    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation target flow '{flow_id}' not found",
        )
    return investigation


@router.get(
    "/alerts/{alert_id}",
    response_model=InvestigationResponse,
    summary="Get alert investigation",
    description="Returns deep-dive investigation data for a security alert including the parent flow, deterministic summary, findings, and evidence timeline.",
)
def get_alert_investigation(
    alert_id: str, db: Session = Depends(get_db)
) -> InvestigationResponse:
    investigation = investigation_service.get_alert_investigation(db, alert_id)
    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation target alert '{alert_id}' not found",
        )
    return investigation
