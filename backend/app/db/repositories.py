"""
UniGuard Database Repository Layer (Milestone 8)

Handles translation between Domain Pydantic models and SQLAlchemy ORM models.
Exposes clean CRUD operations for the persistence service.
"""

import json
import datetime
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from backend.app.db import models
from backend.app.schemas.traffic import DirectionalFlowRecord, FeatureVector
from backend.app.schemas.ml import UnifiedMLResult
from backend.app.schemas.risk import RiskAssessment, Severity
from backend.app.schemas.evidence import EvidenceAssessment, EvidenceItem


def save_flow(db: Session, flow: DirectionalFlowRecord) -> models.TrafficFlowModel:
    """Persist a traffic flow record."""
    db_flow = models.TrafficFlowModel(
        flow_id=flow.flow_id,
        source_ip=flow.source_ip,
        destination_ip=flow.destination_ip,
        source_port=flow.source_port,
        destination_port=flow.destination_port,
        protocol=flow.protocol,
        duration=flow.duration,
        packet_count=flow.packet_count,
        byte_count=flow.byte_count,
        timestamp=flow.timestamp
    )
    db.add(db_flow)
    return db_flow

def save_features(db: Session, flow_id: str, features: FeatureVector) -> models.FeatureModel:
    """Persist the 16 canonical features associated with a flow."""
    db_feat = models.FeatureModel(
        flow_id=flow_id,
        flow_duration=features.flow_duration,
        packet_count=features.packet_count,
        byte_count=features.byte_count,
        packets_per_second=features.packets_per_second,
        bytes_per_second=features.bytes_per_second,
        average_packet_size=features.average_packet_size,
        packet_size_std=features.packet_size_std,
        unique_destination_count=features.unique_destination_count,
        unique_destination_port_count=features.unique_destination_port_count,
        destination_port_entropy=features.destination_port_entropy,
        packet_size_entropy=features.packet_size_entropy,
        burst_score=features.burst_score,
        source_activity_rate=features.source_activity_rate,
        destination_diversity=features.destination_diversity,
        port_diversity=features.port_diversity,
        protocol_indicator=features.protocol_indicator,
    )
    db.add(db_feat)
    return db_feat

def save_ml_result(db: Session, flow_id: str, ml_result: UnifiedMLResult) -> models.MLResultModel:
    """Persist the UnifiedMLResult."""
    db_ml = models.MLResultModel(
        flow_id=flow_id,
        threat_type=ml_result.threat_type,
        classifier_confidence=ml_result.classifier_confidence,
        anomaly_score=ml_result.anomaly_score,
        is_anomaly=ml_result.is_anomaly,
        model_version=ml_result.model_version,
        class_probabilities=ml_result.class_probabilities,
        feature_importances=ml_result.feature_importances
    )
    db.add(db_ml)
    return db_ml

def save_risk_assessment(db: Session, flow_id: str, risk: RiskAssessment) -> models.RiskAssessmentModel:
    """Persist the RiskAssessment."""
    # Convert risk_factors objects to dicts for JSON storage
    factors = [rf.model_dump() for rf in risk.risk_factors]
    
    db_risk = models.RiskAssessmentModel(
        flow_id=flow_id,
        risk_score=risk.risk_score,
        severity=risk.severity.value,
        threat_type=risk.threat_type,
        confidence=risk.confidence,
        anomaly_score=risk.anomaly_score,
        is_anomaly=risk.is_anomaly,
        explanation=risk.explanation,
        recommended_action=risk.recommended_action,
        risk_factors=factors
    )
    db.add(db_risk)
    return db_risk

def save_evidence(db: Session, flow_id: str, evidence: EvidenceAssessment) -> List[models.EvidenceModel]:
    """Persist all evidence items from an EvidenceAssessment."""
    db_items = []
    for item in evidence.evidence_items:
        db_item = models.EvidenceModel(
            evidence_id=item.evidence_id,
            flow_id=flow_id,
            category=item.category.value,
            title=item.title,
            description=item.description,
            value_str=str(item.value),
            contribution=item.strength,
            source=item.source,
            severity=item.severity.value,
            feature_name=item.feature_name
        )
        db.add(db_item)
        db_items.append(db_item)
    return db_items

def save_alert(
    db: Session,
    alert_id: str,
    flow_id: str,
    threat_type: str,
    risk_score: float,
    severity: str,
    summary: str
) -> models.AlertModel:
    """Create an alert for a high/critical flow."""
    db_alert = models.AlertModel(
        alert_id=alert_id,
        flow_id=flow_id,
        threat_type=threat_type,
        risk_score=risk_score,
        severity=severity,
        summary=summary,
        status="OPEN"
    )
    db.add(db_alert)
    return db_alert

def get_flow(db: Session, flow_id: str) -> Optional[models.TrafficFlowModel]:
    return db.query(models.TrafficFlowModel).filter(models.TrafficFlowModel.flow_id == flow_id).first()

def list_flows(db: Session, limit: int = 100) -> List[models.TrafficFlowModel]:
    return db.query(models.TrafficFlowModel).order_by(models.TrafficFlowModel.created_at.desc()).limit(limit).all()

def get_alert(db: Session, alert_id: str) -> Optional[models.AlertModel]:
    return db.query(models.AlertModel).filter(models.AlertModel.alert_id == alert_id).first()

def list_alerts(
    db: Session,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    threat_type: Optional[str] = None,
    limit: int = 100
) -> List[models.AlertModel]:
    query = db.query(models.AlertModel)
    if severity:
        query = query.filter(models.AlertModel.severity == severity)
    if status:
        query = query.filter(models.AlertModel.status == status)
    if threat_type:
        query = query.filter(models.AlertModel.threat_type == threat_type)
        
    return query.order_by(models.AlertModel.created_at.desc()).limit(limit).all()

# --- M12 Dashboard Extensions ---

def _parse_datetime(time_str: Optional[str]) -> Optional[datetime.datetime]:
    if not time_str:
        return None
    try:
        clean = time_str.replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(clean)
    except Exception:
        pass
    try:
        return datetime.datetime.strptime(time_str[:19], "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None

def _extract_bucket_time(ts: str, interval: str) -> str:
    if not ts:
        return "UNKNOWN"
    if len(ts) >= 10 and ts[4] == '-' and ts[7] == '-':
        if interval == "day":
            return ts[:10]
        if len(ts) >= 13:
            return ts[:13]
        return ts[:10]
    return ts

def get_dashboard_flows(
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
) -> Tuple[List[Any], int]:
    query = db.query(
        models.TrafficFlowModel, 
        models.MLResultModel, 
        models.RiskAssessmentModel
    ).outerjoin(
        models.MLResultModel, models.TrafficFlowModel.flow_id == models.MLResultModel.flow_id
    ).outerjoin(
        models.RiskAssessmentModel, models.TrafficFlowModel.flow_id == models.RiskAssessmentModel.flow_id
    )

    if threat_type:
        query = query.filter(
            (models.MLResultModel.threat_type == threat_type) |
            (models.RiskAssessmentModel.threat_type == threat_type)
        )
    if severity:
        query = query.filter(models.RiskAssessmentModel.severity == severity.upper())
    if is_anomaly is not None:
        query = query.filter(models.MLResultModel.is_anomaly == is_anomaly)
    if source_ip:
        query = query.filter(models.TrafficFlowModel.source_ip == source_ip)
    if destination_ip:
        query = query.filter(models.TrafficFlowModel.destination_ip == destination_ip)
    if start_time:
        query = query.filter(models.TrafficFlowModel.timestamp >= start_time)
    if end_time:
        query = query.filter(models.TrafficFlowModel.timestamp <= end_time)

    total = query.count()
    items = query.order_by(
        models.TrafficFlowModel.timestamp.desc(),
        models.TrafficFlowModel.flow_id.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()
    return items, total

def get_dashboard_alerts(
    db: Session,
    page: int = 1,
    page_size: int = 20,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    threat_type: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> Tuple[List[models.AlertModel], int]:
    query = db.query(models.AlertModel)
    if severity:
        query = query.filter(models.AlertModel.severity == severity.upper())
    if status:
        query = query.filter(models.AlertModel.status == status.upper())
    if threat_type:
        query = query.filter(models.AlertModel.threat_type == threat_type)
    if start_time:
        dt_start = _parse_datetime(start_time)
        if dt_start:
            query = query.filter(models.AlertModel.created_at >= dt_start)
    if end_time:
        dt_end = _parse_datetime(end_time)
        if dt_end:
            query = query.filter(models.AlertModel.created_at <= dt_end)

    total = query.count()
    items = query.order_by(
        models.AlertModel.created_at.desc(),
        models.AlertModel.alert_id.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()
    return items, total

def get_flow_detail_records(db: Session, flow_id: str) -> Optional[Dict[str, Any]]:
    flow = db.query(models.TrafficFlowModel).filter_by(flow_id=flow_id).first()
    if not flow:
        return None
    features = db.query(models.FeatureModel).filter_by(flow_id=flow_id).first()
    ml_result = db.query(models.MLResultModel).filter_by(flow_id=flow_id).first()
    risk = db.query(models.RiskAssessmentModel).filter_by(flow_id=flow_id).first()
    evidence = db.query(models.EvidenceModel).filter_by(flow_id=flow_id).all()
    alert = db.query(models.AlertModel).filter_by(flow_id=flow_id).first()
    return {
        "flow": flow,
        "features": features,
        "ml_result": ml_result,
        "risk": risk,
        "evidence": evidence,
        "alert": alert
    }

def get_alert_detail_records(db: Session, alert_id: str) -> Optional[Dict[str, Any]]:
    alert = db.query(models.AlertModel).filter_by(alert_id=alert_id).first()
    if not alert:
        return None
    flow = db.query(models.TrafficFlowModel).filter_by(flow_id=alert.flow_id).first()
    ml_result = db.query(models.MLResultModel).filter_by(flow_id=alert.flow_id).first()
    risk = db.query(models.RiskAssessmentModel).filter_by(flow_id=alert.flow_id).first()
    evidence = db.query(models.EvidenceModel).filter_by(flow_id=alert.flow_id).all()
    return {
        "alert": alert,
        "flow": flow,
        "ml_result": ml_result,
        "risk": risk,
        "evidence": evidence
    }

def get_dashboard_overview_stats(db: Session) -> Dict[str, Any]:
    total_flows = db.query(models.TrafficFlowModel).count()
    total_alerts = db.query(models.AlertModel).count()
    high_alerts = db.query(models.AlertModel).filter(models.AlertModel.severity == 'HIGH').count()
    critical_alerts = db.query(models.AlertModel).filter(models.AlertModel.severity == 'CRITICAL').count()
    anomaly_count = db.query(models.MLResultModel).filter(models.MLResultModel.is_anomaly == True).count()
    
    from sqlalchemy import func
    threat_dist = db.query(
        models.RiskAssessmentModel.threat_type, func.count(models.RiskAssessmentModel.flow_id)
    ).group_by(models.RiskAssessmentModel.threat_type).all()
    
    sev_dist = db.query(
        models.RiskAssessmentModel.severity, func.count(models.RiskAssessmentModel.flow_id)
    ).group_by(models.RiskAssessmentModel.severity).all()

    threat_type_distribution = dict(threat_dist)
    severity_distribution = dict(sev_dist)

    return {
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "critical_alerts": critical_alerts,
        "anomaly_count": anomaly_count,
        "threat_dist": threat_type_distribution,
        "sev_dist": severity_distribution,
        "threat_type_distribution": threat_type_distribution,
        "severity_distribution": severity_distribution,
    }

def get_timeline_buckets(
    db: Session,
    interval: str = "hour",
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
) -> List[Dict[str, Any]]:
    flow_query = db.query(
        models.TrafficFlowModel, 
        models.MLResultModel, 
        models.AlertModel
    ).outerjoin(
        models.MLResultModel, models.TrafficFlowModel.flow_id == models.MLResultModel.flow_id
    ).outerjoin(
        models.AlertModel, models.TrafficFlowModel.flow_id == models.AlertModel.flow_id
    )

    if start_time:
        flow_query = flow_query.filter(models.TrafficFlowModel.timestamp >= start_time)
    if end_time:
        flow_query = flow_query.filter(models.TrafficFlowModel.timestamp <= end_time)

    rows = flow_query.all()
    buckets: Dict[str, Dict[str, Any]] = {}

    for flow, ml, alert in rows:
        ts = flow.timestamp or ""
        bucket_key = _extract_bucket_time(ts, interval)
        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "bucket_time": bucket_key,
                "flow_count": 0,
                "alert_count": 0,
                "high_alert_count": 0,
                "critical_alert_count": 0,
                "anomaly_count": 0,
            }
        b = buckets[bucket_key]
        b["flow_count"] += 1
        if ml and ml.is_anomaly:
            b["anomaly_count"] += 1
        if alert:
            b["alert_count"] += 1
            if alert.severity == "HIGH":
                b["high_alert_count"] += 1
            elif alert.severity == "CRITICAL":
                b["critical_alert_count"] += 1

    seen_alert_ids = {alert.alert_id for _, _, alert in rows if alert}
    alert_query = db.query(models.AlertModel)
    if start_time:
        dt_start = _parse_datetime(start_time)
        if dt_start:
            alert_query = alert_query.filter(models.AlertModel.created_at >= dt_start)
    if end_time:
        dt_end = _parse_datetime(end_time)
        if dt_end:
            alert_query = alert_query.filter(models.AlertModel.created_at <= dt_end)

    for alert in alert_query.all():
        if alert.alert_id in seen_alert_ids:
            continue
        ts = alert.created_at.isoformat() if alert.created_at else ""
        bucket_key = _extract_bucket_time(ts, interval)
        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "bucket_time": bucket_key,
                "flow_count": 0,
                "alert_count": 0,
                "high_alert_count": 0,
                "critical_alert_count": 0,
                "anomaly_count": 0,
            }
        b = buckets[bucket_key]
        b["alert_count"] += 1
        if alert.severity == "HIGH":
            b["high_alert_count"] += 1
        elif alert.severity == "CRITICAL":
            b["critical_alert_count"] += 1

    sorted_keys = sorted(buckets.keys())
    return [buckets[k] for k in sorted_keys]

# --- M13 Reports & Investigation Extensions ---

def get_investigation_by_flow(db: Session, flow_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve all persisted records associated with a flow for investigation."""
    flow = db.query(models.TrafficFlowModel).filter_by(flow_id=flow_id).first()
    if not flow:
        return None
    features = db.query(models.FeatureModel).filter_by(flow_id=flow_id).first()
    ml_result = db.query(models.MLResultModel).filter_by(flow_id=flow_id).first()
    risk = db.query(models.RiskAssessmentModel).filter_by(flow_id=flow_id).first()
    evidence = db.query(models.EvidenceModel).filter_by(flow_id=flow_id).all()
    alert = db.query(models.AlertModel).filter_by(flow_id=flow_id).first()
    return {
        "flow": flow,
        "features": features,
        "ml_result": ml_result,
        "risk": risk,
        "evidence": evidence,
        "alert": alert,
    }

def get_investigation_by_alert(db: Session, alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve all persisted records associated with an alert for investigation."""
    alert = db.query(models.AlertModel).filter_by(alert_id=alert_id).first()
    if not alert:
        return None
    flow = db.query(models.TrafficFlowModel).filter_by(flow_id=alert.flow_id).first()
    features = db.query(models.FeatureModel).filter_by(flow_id=alert.flow_id).first()
    ml_result = db.query(models.MLResultModel).filter_by(flow_id=alert.flow_id).first()
    risk = db.query(models.RiskAssessmentModel).filter_by(flow_id=alert.flow_id).first()
    evidence = db.query(models.EvidenceModel).filter_by(flow_id=alert.flow_id).all()
    return {
        "alert": alert,
        "flow": flow,
        "features": features,
        "ml_result": ml_result,
        "risk": risk,
        "evidence": evidence,
    }

