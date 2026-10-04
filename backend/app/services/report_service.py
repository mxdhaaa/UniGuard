"""
UniGuard Report Service (Milestone 13)

Deterministic business logic layer for structured SOC investigation reports.
Transforms persisted investigation state into formal ReportResponse objects.
Does not perform new ML/risk/evidence inference.
"""

import uuid
import datetime
from typing import Optional
from sqlalchemy.orm import Session

from backend.app.schemas.report import ReportResponse
from backend.app.services.investigation_service import investigation_service


class ReportService:
    """Read-only SOC Report Service."""

    def generate_flow_report(
        self, db: Session, flow_id: str
    ) -> Optional[ReportResponse]:
        inv = investigation_service.get_flow_investigation(db, flow_id)
        if not inv:
            return None

        anomaly_dict = {
            "is_anomaly": inv.ml_assessment.get("is_anomaly", False),
            "anomaly_score": inv.ml_assessment.get("anomaly_score", 0.0),
            "model_version": inv.ml_assessment.get("model_version", "unknown"),
        }

        return ReportResponse(
            report_id=f"rep-{uuid.uuid4()}",
            report_type="FLOW_INVESTIGATION",
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            subject=inv.subject,
            executive_summary=inv.summary,
            classification=inv.ml_assessment,
            risk=inv.risk_assessment,
            anomaly=anomaly_dict,
            evidence=inv.evidence,
            findings=inv.findings,
            recommended_action=inv.recommended_action,
            limitations=inv.limitations,
        )

    def generate_alert_report(
        self, db: Session, alert_id: str
    ) -> Optional[ReportResponse]:
        inv = investigation_service.get_alert_investigation(db, alert_id)
        if not inv:
            return None

        anomaly_dict = {
            "is_anomaly": inv.ml_assessment.get("is_anomaly", False),
            "anomaly_score": inv.ml_assessment.get("anomaly_score", 0.0),
            "model_version": inv.ml_assessment.get("model_version", "unknown"),
        }

        return ReportResponse(
            report_id=f"rep-{uuid.uuid4()}",
            report_type="ALERT_INVESTIGATION",
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            subject=inv.subject,
            executive_summary=inv.summary,
            classification=inv.ml_assessment,
            risk=inv.risk_assessment,
            anomaly=anomaly_dict,
            evidence=inv.evidence,
            findings=inv.findings,
            recommended_action=inv.recommended_action,
            limitations=inv.limitations,
        )


report_service = ReportService()
