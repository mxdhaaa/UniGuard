"""
UniGuard Dashboard Service (Milestone 12)

Read-only business logic layer for SOC dashboard analytics, flows, alerts, and timeline.
Delegates database queries to the repository layer.
Does not perform new ML/risk/evidence inference.
"""

from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.db import repositories, models
from backend.app.schemas.dashboard import (
    DashboardOverview,
    PaginatedFlowResponse,
    DashboardFlowSummary,
    DashboardFlowDetail,
    PaginatedAlertResponse,
    DashboardAlertSummary,
    DashboardAlertDetail,
    ThreatAnalytics,
    DashboardTimeline,
    TimelineBucket,
    PaginationMeta,
)
from backend.app.services.ingestion_service import ingestion_service
from backend.app.ml import model_manager


def _serialize_flow(flow: Optional[models.TrafficFlowModel]) -> Dict[str, Any]:
    if not flow:
        return {}
    return {
        "flow_id": flow.flow_id,
        "source_ip": flow.source_ip,
        "destination_ip": flow.destination_ip,
        "source_port": flow.source_port,
        "destination_port": flow.destination_port,
        "protocol": flow.protocol,
        "duration": flow.duration,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "feature_schema_version": flow.feature_schema_version,
        "timestamp": flow.timestamp,
        "created_at": flow.created_at.isoformat() if flow.created_at else None,
    }


def _serialize_features(feat: Optional[models.FeatureModel]) -> Dict[str, Any]:
    if not feat:
        return {}
    return {
        "flow_id": feat.flow_id,
        "flow_duration": feat.flow_duration,
        "packet_count": feat.packet_count,
        "byte_count": feat.byte_count,
        "packets_per_second": feat.packets_per_second,
        "bytes_per_second": feat.bytes_per_second,
        "average_packet_size": feat.average_packet_size,
        "packet_size_std": feat.packet_size_std,
        "unique_destination_count": feat.unique_destination_count,
        "unique_destination_port_count": feat.unique_destination_port_count,
        "destination_port_entropy": feat.destination_port_entropy,
        "packet_size_entropy": feat.packet_size_entropy,
        "burst_score": feat.burst_score,
        "source_activity_rate": feat.source_activity_rate,
        "destination_diversity": feat.destination_diversity,
        "port_diversity": feat.port_diversity,
        "protocol_indicator": feat.protocol_indicator,
        "feature_schema_version": feat.feature_schema_version,
    }


def _serialize_ml(ml: Optional[models.MLResultModel]) -> Dict[str, Any]:
    if not ml:
        return {}
    return {
        "flow_id": ml.flow_id,
        "threat_type": ml.threat_type,
        "classifier_confidence": ml.classifier_confidence,
        "anomaly_score": ml.anomaly_score,
        "is_anomaly": ml.is_anomaly,
        "model_version": ml.model_version,
        "class_probabilities": ml.class_probabilities,
        "feature_importances": ml.feature_importances,
    }


def _serialize_risk(risk: Optional[models.RiskAssessmentModel]) -> Dict[str, Any]:
    if not risk:
        return {}
    return {
        "flow_id": risk.flow_id,
        "risk_score": risk.risk_score,
        "severity": risk.severity,
        "threat_type": risk.threat_type,
        "confidence": risk.confidence,
        "anomaly_score": risk.anomaly_score,
        "is_anomaly": risk.is_anomaly,
        "explanation": risk.explanation,
        "recommended_action": risk.recommended_action,
        "risk_factors": risk.risk_factors,
    }


def _serialize_evidence_item(ev: models.EvidenceModel) -> Dict[str, Any]:
    return {
        "evidence_id": ev.evidence_id,
        "flow_id": ev.flow_id,
        "category": ev.category,
        "title": ev.title,
        "description": ev.description,
        "value": ev.value_str,
        "strength": ev.contribution,
        "source": ev.source,
        "severity": ev.severity,
        "feature_name": ev.feature_name,
    }


def _serialize_alert_summary(alert: models.AlertModel) -> DashboardAlertSummary:
    return DashboardAlertSummary(
        alert_id=alert.alert_id,
        flow_id=alert.flow_id,
        threat_type=alert.threat_type,
        risk_score=float(alert.risk_score),
        severity=alert.severity,
        status=alert.status,
        summary=alert.summary,
        created_at=alert.created_at.isoformat() if alert.created_at else "",
        updated_at=alert.updated_at.isoformat() if alert.updated_at else "",
    )


class DashboardService:
    """Read-only SOC Dashboard Service."""

    def get_overview(self, db: Session) -> DashboardOverview:
        stats = repositories.get_dashboard_overview_stats(db)
        ingestion_status = ingestion_service.get_status().state
        ml_state = model_manager.get_state().value
        return DashboardOverview(
            total_flows=stats["total_flows"],
            total_alerts=stats["total_alerts"],
            high_alerts=stats["high_alerts"],
            critical_alerts=stats["critical_alerts"],
            anomaly_count=stats["anomaly_count"],
            threat_type_distribution=stats["threat_type_distribution"],
            severity_distribution=stats["severity_distribution"],
            ingestion_state=ingestion_status,
            ml_readiness=ml_state,
        )

    def list_flows(
        self,
        db: Session,
        page: int = 1,
        page_size: int = 20,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        is_anomaly: Optional[bool] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> PaginatedFlowResponse:
        items, total = repositories.get_dashboard_flows(
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

        summaries: List[DashboardFlowSummary] = []
        for flow, ml, risk in items:
            t_type = ml.threat_type if ml else (risk.threat_type if risk else "UNKNOWN")
            c_conf = float(ml.classifier_confidence) if ml else 0.0
            a_score = float(ml.anomaly_score) if ml else 0.0
            is_anom = bool(ml.is_anomaly) if ml else False
            r_score = float(risk.risk_score) if risk else 0.0
            sev = str(risk.severity) if risk else "LOW"

            summaries.append(
                DashboardFlowSummary(
                    flow_id=flow.flow_id,
                    timestamp=flow.timestamp,
                    source_ip=flow.source_ip,
                    source_port=flow.source_port,
                    destination_ip=flow.destination_ip,
                    destination_port=flow.destination_port,
                    protocol=flow.protocol,
                    threat_type=t_type,
                    classifier_confidence=c_conf,
                    anomaly_score=a_score,
                    is_anomaly=is_anom,
                    risk_score=r_score,
                    severity=sev,
                )
            )

        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        meta = PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total,
            total_pages=total_pages,
        )
        return PaginatedFlowResponse(data=summaries, meta=meta)

    def get_flow_detail(self, db: Session, flow_id: str) -> Optional[DashboardFlowDetail]:
        records = repositories.get_flow_detail_records(db, flow_id)
        if not records:
            return None

        flow_dict = _serialize_flow(records["flow"])
        features_dict = _serialize_features(records["features"])
        ml_dict = _serialize_ml(records["ml_result"])
        risk_dict = _serialize_risk(records["risk"])
        evidence_list = (
            [_serialize_evidence_item(e) for e in records["evidence"]]
            if records.get("evidence")
            else []
        )
        alert_dict = (
            _serialize_alert_summary(records["alert"]).model_dump()
            if records.get("alert")
            else None
        )

        return DashboardFlowDetail(
            flow=flow_dict,
            features=features_dict,
            ml_result=ml_dict,
            risk_assessment=risk_dict,
            evidence=evidence_list,
            alert=alert_dict,
        )

    def list_alerts(
        self,
        db: Session,
        page: int = 1,
        page_size: int = 20,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        threat_type: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> PaginatedAlertResponse:
        items, total = repositories.get_dashboard_alerts(
            db=db,
            page=page,
            page_size=page_size,
            severity=severity,
            status=status,
            threat_type=threat_type,
            start_time=start_time,
            end_time=end_time,
        )

        summaries = [_serialize_alert_summary(a) for a in items]
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        meta = PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total,
            total_pages=total_pages,
        )
        return PaginatedAlertResponse(data=summaries, meta=meta)

    def get_alert_detail(self, db: Session, alert_id: str) -> Optional[DashboardAlertDetail]:
        records = repositories.get_alert_detail_records(db, alert_id)
        if not records:
            return None

        alert_summary = _serialize_alert_summary(records["alert"])
        flow_dict = _serialize_flow(records["flow"])
        ml_dict = _serialize_ml(records["ml_result"])
        risk_dict = _serialize_risk(records["risk"])
        evidence_list = (
            [_serialize_evidence_item(e) for e in records["evidence"]]
            if records.get("evidence")
            else []
        )

        return DashboardAlertDetail(
            alert=alert_summary,
            flow=flow_dict,
            ml_result=ml_dict,
            risk_assessment=risk_dict,
            evidence=evidence_list,
        )

    def get_threat_analytics(self, db: Session) -> ThreatAnalytics:
        stats = repositories.get_dashboard_overview_stats(db)
        return ThreatAnalytics(
            threat_type_distribution=stats["threat_type_distribution"],
            severity_distribution=stats["severity_distribution"],
            anomaly_count=stats["anomaly_count"],
        )

    def get_timeline(
        self,
        db: Session,
        interval: str = "hour",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> DashboardTimeline:
        raw_buckets = repositories.get_timeline_buckets(
            db=db,
            interval=interval,
            start_time=start_time,
            end_time=end_time,
        )
        buckets = [TimelineBucket(**b) for b in raw_buckets]
        return DashboardTimeline(interval=interval, buckets=buckets)


dashboard_service = DashboardService()
