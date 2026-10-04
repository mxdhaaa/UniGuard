"""
UniGuard Dashboard API Routes (Milestone 12)

Read-only endpoints for SOC dashboards:
- Overview stats
- Flow exploration with filtering and pagination
- Flow details
- Alert triage with filtering and pagination
- Alert details
- Threat analytics
- Timeline aggregation
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.schemas.dashboard import (
    DashboardOverview,
    PaginatedFlowResponse,
    DashboardFlowDetail,
    PaginatedAlertResponse,
    DashboardAlertDetail,
    ThreatAnalytics,
    DashboardTimeline,
)
from backend.app.services.dashboard_service import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/overview",
    response_model=DashboardOverview,
    summary="Get SOC dashboard overview",
    description="Returns aggregate flow counts, alert metrics, threat distribution, ingestion state, and ML readiness.",
)
def get_dashboard_overview(db: Session = Depends(get_db)) -> DashboardOverview:
    return dashboard_service.get_overview(db)


@router.get(
    "/flows",
    response_model=PaginatedFlowResponse,
    summary="List and filter traffic flows",
    description="Returns a paginated list of traffic flows with SOC risk and ML classification summaries.",
)
def list_flows(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    threat_type: Optional[str] = Query(None, description="Filter by ML threat type"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    is_anomaly: Optional[bool] = Query(None, description="Filter by anomaly flag"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    start_time: Optional[str] = Query(None, description="Filter flows at or after timestamp"),
    end_time: Optional[str] = Query(None, description="Filter flows at or before timestamp"),
    db: Session = Depends(get_db),
) -> PaginatedFlowResponse:
    return dashboard_service.list_flows(
        db=db,
        page=page,
        page_size=page_size,
        threat_type=threat_type,
        severity=severity,
        is_anomaly=is_anomaly,
        source_ip=source_ip,
        destination_ip=destination_ip,
        start_time=start_time,
        end_time=end_time,
    )


@router.get(
    "/flows/{flow_id}",
    response_model=DashboardFlowDetail,
    summary="Get flow details",
    description="Returns comprehensive details for a specific flow including features, ML classification, risk assessment, evidence, and associated alert.",
)
def get_flow_detail(flow_id: str, db: Session = Depends(get_db)) -> DashboardFlowDetail:
    detail = dashboard_service.get_flow_detail(db, flow_id)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow '{flow_id}' not found",
        )
    return detail


@router.get(
    "/alerts",
    response_model=PaginatedAlertResponse,
    summary="List and filter alerts",
    description="Returns a paginated list of security alerts with filtering by severity, status, threat type, and time range.",
)
def list_alerts(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    status: Optional[str] = Query(None, description="Filter by alert status (OPEN, ACKNOWLEDGED, RESOLVED)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    start_time: Optional[str] = Query(None, description="Filter alerts created at or after timestamp"),
    end_time: Optional[str] = Query(None, description="Filter alerts created at or before timestamp"),
    db: Session = Depends(get_db),
) -> PaginatedAlertResponse:
    return dashboard_service.list_alerts(
        db=db,
        page=page,
        page_size=page_size,
        severity=severity,
        status=status,
        threat_type=threat_type,
        start_time=start_time,
        end_time=end_time,
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=DashboardAlertDetail,
    summary="Get alert details",
    description="Returns comprehensive alert details including the associated flow, ML results, risk assessment, and evidence items.",
)
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)) -> DashboardAlertDetail:
    detail = dashboard_service.get_alert_detail(db, alert_id)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )
    return detail


@router.get(
    "/threats",
    response_model=ThreatAnalytics,
    summary="Get threat analytics",
    description="Returns distributions of detected threat types and severity levels, along with overall anomaly count.",
)
def get_threat_analytics(db: Session = Depends(get_db)) -> ThreatAnalytics:
    return dashboard_service.get_threat_analytics(db)


@router.get(
    "/timeline",
    response_model=DashboardTimeline,
    summary="Get timeline analytics",
    description="Returns chronological time buckets with counts of flows, alerts, high alerts, critical alerts, and anomalies.",
)
def get_timeline(
    interval: str = Query("hour", description="Bucket interval: 'hour' or 'day'"),
    start_time: Optional[str] = Query(None, description="Optional start timestamp for filtering"),
    end_time: Optional[str] = Query(None, description="Optional end timestamp for filtering"),
    db: Session = Depends(get_db),
) -> DashboardTimeline:
    interval_clean = interval.lower().strip()
    if interval_clean not in ("hour", "day"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid interval '{interval}'. Supported values are 'hour' and 'day'.",
        )
    return dashboard_service.get_timeline(
        db=db,
        interval=interval_clean,
        start_time=start_time,
        end_time=end_time,
    )
