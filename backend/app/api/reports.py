"""
UniGuard Report API Routes (Milestone 13)

Read-only endpoints for generating formal SOC investigation reports:
- Flow report: /api/reports/flows/{flow_id}
- Alert report: /api/reports/alerts/{alert_id}
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.schemas.report import ReportResponse
from backend.app.services.report_service import report_service

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get(
    "/flows/{flow_id}",
    response_model=ReportResponse,
    summary="Generate flow investigation report",
    description="Generates a structured JSON report for a specific flow from persisted investigation data.",
)
def get_flow_report(
    flow_id: str, db: Session = Depends(get_db)
) -> ReportResponse:
    report = report_service.generate_flow_report(db, flow_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report target flow '{flow_id}' not found",
        )
    return report


@router.get(
    "/alerts/{alert_id}",
    response_model=ReportResponse,
    summary="Generate alert investigation report",
    description="Generates a structured JSON report for a specific alert from persisted investigation data.",
)
def get_alert_report(
    alert_id: str, db: Session = Depends(get_db)
) -> ReportResponse:
    report = report_service.generate_alert_report(db, alert_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report target alert '{alert_id}' not found",
        )
    return report
