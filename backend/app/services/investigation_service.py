"""
UniGuard Investigation Service (Milestone 13)

Deterministic business logic layer for Reports & Investigation.
Operates exclusively on persisted UniGuard database records.
Does not perform new ML/risk/evidence inference.
"""

from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session

from backend.app.db import repositories, models
from backend.app.schemas.investigation import (
    InvestigationResponse,
    InvestigationSubject,
    InvestigationFinding,
    InvestigationTimelineEvent,
)


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


def _generate_summary(
    flow_id: str,
    flow: Optional[models.TrafficFlowModel],
    ml_result: Optional[models.MLResultModel],
    risk: Optional[models.RiskAssessmentModel],
    evidence: List[models.EvidenceModel],
    alert: Optional[models.AlertModel],
) -> str:
    parts: List[str] = []
    threat_type = (
        ml_result.threat_type
        if ml_result
        else (risk.threat_type if risk else "UNKNOWN")
    )
    risk_score = risk.risk_score if risk else 0.0
    severity = str(risk.severity) if risk else "LOW"
    conf = (
        ml_result.classifier_confidence
        if ml_result
        else (risk.confidence if risk else 0.0)
    )

    parts.append(
        f"Flow {flow_id} was classified as {threat_type} with a risk score of {risk_score:.1f} and severity {severity}."
    )
    if ml_result:
        parts.append(f"Classifier confidence was {conf:.2f}.")
        if ml_result.is_anomaly:
            parts.append(
                f"The anomaly detector flagged the flow as an outlier with an anomaly score of {ml_result.anomaly_score:.2f}."
            )
        else:
            parts.append(
                f"The anomaly detector did not flag the flow (anomaly score: {ml_result.anomaly_score:.2f})."
            )

    if flow:
        parts.append(
            f"Observed 5-tuple: {flow.source_ip}:{flow.source_port} -> {flow.destination_ip}:{flow.destination_port} ({flow.protocol}), transmitting {flow.packet_count} packets ({flow.byte_count} bytes) over {flow.duration:.2f}s."
        )

    if alert:
        parts.append(
            f"Security alert {alert.alert_id} was generated with status {alert.status} and severity {alert.severity}."
        )

    if evidence:
        ev_summaries = [f"'{e.title}' ({e.source})" for e in evidence[:3]]
        parts.append(f"Key evidence items recorded: {', '.join(ev_summaries)}.")

    return " ".join(parts)


def _generate_findings(
    flow_id: str,
    flow: Optional[models.TrafficFlowModel],
    ml_result: Optional[models.MLResultModel],
    risk: Optional[models.RiskAssessmentModel],
    evidence: List[models.EvidenceModel],
    alert: Optional[models.AlertModel],
) -> List[InvestigationFinding]:
    findings: List[InvestigationFinding] = []

    # 1. CLASSIFICATION finding
    if ml_result:
        findings.append(
            InvestigationFinding(
                finding_id=f"finding-cls-{flow_id}",
                category="CLASSIFICATION",
                title=f"Threat Classification: {ml_result.threat_type}",
                description=f"Model classified traffic flow as {ml_result.threat_type} with confidence {ml_result.classifier_confidence:.2f}.",
                severity=str(risk.severity) if risk else "LOW",
                source=f"ThreatClassifier ({ml_result.model_version})",
            )
        )

    # 2. ANOMALY finding
    if ml_result and ml_result.is_anomaly:
        sev = "MEDIUM" if (risk and risk.severity == "LOW") else (str(risk.severity) if risk else "MEDIUM")
        findings.append(
            InvestigationFinding(
                finding_id=f"finding-anom-{flow_id}",
                category="ANOMALY",
                title="Statistical Anomaly Detected",
                description=f"IsolationForest detector flagged flow as an outlier with anomaly score {ml_result.anomaly_score:.2f}.",
                severity=sev,
                source="AnomalyDetector",
            )
        )

    # 3. RISK finding
    if risk:
        findings.append(
            InvestigationFinding(
                finding_id=f"finding-risk-{flow_id}",
                category="RISK",
                title=f"SOC Risk Assessment: {risk.severity}",
                description=f"Deterministic risk score evaluated at {risk.risk_score:.1f} ({risk.severity}). {risk.explanation}",
                severity=str(risk.severity),
                source="RiskEngine",
            )
        )

    # 4. TRAFFIC_BEHAVIOR finding
    if flow:
        findings.append(
            InvestigationFinding(
                finding_id=f"finding-traffic-{flow_id}",
                category="TRAFFIC_BEHAVIOR",
                title="Unidirectional Flow Profile",
                description=f"Flow from {flow.source_ip}:{flow.source_port} to {flow.destination_ip}:{flow.destination_port} ({flow.protocol}) generated {flow.packet_count} packets and {flow.byte_count} bytes over {flow.duration:.2f}s.",
                severity="LOW",
                source="FlowProcessor",
            )
        )

    # 5. EVIDENCE findings
    for item in evidence:
        findings.append(
            InvestigationFinding(
                finding_id=f"finding-ev-{item.evidence_id}",
                category="EVIDENCE",
                title=item.title,
                description=item.description,
                severity=str(item.severity),
                source=item.source,
            )
        )

    # 6. ALERT finding
    if alert:
        findings.append(
            InvestigationFinding(
                finding_id=f"finding-alert-{alert.alert_id}",
                category="ALERT",
                title=f"Security Alert: {alert.threat_type} ({alert.severity})",
                description=f"Alert {alert.alert_id} status is {alert.status}: {alert.summary}",
                severity=str(alert.severity),
                source="AlertManager",
            )
        )

    return findings


def _generate_timeline(
    flow: Optional[models.TrafficFlowModel],
    evidence: List[models.EvidenceModel],
    alert: Optional[models.AlertModel],
) -> List[InvestigationTimelineEvent]:
    raw_events: List[Tuple[str, str, str, InvestigationTimelineEvent]] = []

    # 1. Flow observation event
    if flow:
        ts = flow.timestamp or (flow.created_at.isoformat() if flow.created_at else "")
        ev = InvestigationTimelineEvent(
            timestamp=ts,
            event_type="FLOW_OBSERVED",
            title="Unidirectional Flow Observed",
            description=f"Traffic flow {flow.flow_id} observed from {flow.source_ip}:{flow.source_port} to {flow.destination_ip}:{flow.destination_port} ({flow.protocol}).",
            severity="LOW",
            source="FlowCollector",
        )
        raw_events.append((ts, "FLOW_OBSERVED", flow.flow_id, ev))

    # 2. Evidence events
    for item in evidence:
        ts = item.created_at.isoformat() if item.created_at else (flow.timestamp if flow else "")
        ev = InvestigationTimelineEvent(
            timestamp=ts,
            event_type="EVIDENCE_RECORDED",
            title=f"Evidence: {item.title}",
            description=item.description,
            severity=str(item.severity),
            source=item.source,
        )
        raw_events.append((ts, "EVIDENCE_RECORDED", item.evidence_id, ev))

    # 3. Alert creation event
    if alert:
        ts = alert.created_at.isoformat() if alert.created_at else (flow.timestamp if flow else "")
        ev = InvestigationTimelineEvent(
            timestamp=ts,
            event_type="ALERT_GENERATED",
            title=f"Security Alert Raised: {alert.threat_type}",
            description=alert.summary,
            severity=str(alert.severity),
            source="AlertManager",
        )
        raw_events.append((ts, "ALERT_GENERATED", alert.alert_id, ev))

    # Sort deterministically by timestamp ascending, then event_type, then stable identifier
    raw_events.sort(key=lambda x: (x[0], x[1], x[2]))
    return [item[3] for item in raw_events]


STANDARD_LIMITATIONS = [
    "Analysis is based on unidirectional flow telemetry.",
    "No packet payload contents are persisted or inspected by the investigation layer.",
    "Threat classification reflects the persisted model result and is not recomputed during investigation.",
    "Risk assessment reflects the persisted deterministic risk result.",
    "Evidence reflects the persisted evidence assessment.",
    "No external threat-intelligence enrichment is performed.",
]


class InvestigationService:
    """Read-only SOC Investigation Service."""

    def get_flow_investigation(
        self, db: Session, flow_id: str
    ) -> Optional[InvestigationResponse]:
        records = repositories.get_investigation_by_flow(db, flow_id)
        if not records:
            return None

        flow = records.get("flow")
        features = records.get("features")
        ml_result = records.get("ml_result")
        risk = records.get("risk")
        evidence: List[models.EvidenceModel] = records.get("evidence") or []
        alert = records.get("alert")

        subject = InvestigationSubject(
            investigation_id=f"inv-{flow_id}",
            flow_id=flow_id,
            alert_id=alert.alert_id if alert else None,
        )

        flow_dict = _serialize_flow(flow)
        features_dict = _serialize_features(features)
        ml_dict = _serialize_ml(ml_result)
        risk_dict = _serialize_risk(risk)
        evidence_list = [_serialize_evidence_item(e) for e in evidence]

        summary = _generate_summary(
            flow_id=flow_id,
            flow=flow,
            ml_result=ml_result,
            risk=risk,
            evidence=evidence,
            alert=alert,
        )
        findings = _generate_findings(
            flow_id=flow_id,
            flow=flow,
            ml_result=ml_result,
            risk=risk,
            evidence=evidence,
            alert=alert,
        )
        timeline = _generate_timeline(flow=flow, evidence=evidence, alert=alert)

        recommended_action = (
            risk.recommended_action
            if risk and risk.recommended_action
            else "No immediate action required."
        )

        return InvestigationResponse(
            subject=subject,
            flow=flow_dict,
            features=features_dict,
            ml_assessment=ml_dict,
            risk_assessment=risk_dict,
            evidence=evidence_list,
            findings=findings,
            timeline=timeline,
            summary=summary,
            recommended_action=recommended_action,
            limitations=list(STANDARD_LIMITATIONS),
        )

    def get_alert_investigation(
        self, db: Session, alert_id: str
    ) -> Optional[InvestigationResponse]:
        records = repositories.get_investigation_by_alert(db, alert_id)
        if not records:
            return None

        alert = records.get("alert")
        flow = records.get("flow")
        features = records.get("features")
        ml_result = records.get("ml_result")
        risk = records.get("risk")
        evidence: List[models.EvidenceModel] = records.get("evidence") or []

        flow_id = alert.flow_id if alert else (flow.flow_id if flow else "unknown")

        subject = InvestigationSubject(
            investigation_id=f"inv-alert-{alert_id}",
            flow_id=flow_id,
            alert_id=alert.alert_id if alert else None,
        )

        flow_dict = _serialize_flow(flow)
        features_dict = _serialize_features(features)
        ml_dict = _serialize_ml(ml_result)
        risk_dict = _serialize_risk(risk)
        evidence_list = [_serialize_evidence_item(e) for e in evidence]

        summary = _generate_summary(
            flow_id=flow_id,
            flow=flow,
            ml_result=ml_result,
            risk=risk,
            evidence=evidence,
            alert=alert,
        )
        findings = _generate_findings(
            flow_id=flow_id,
            flow=flow,
            ml_result=ml_result,
            risk=risk,
            evidence=evidence,
            alert=alert,
        )
        timeline = _generate_timeline(flow=flow, evidence=evidence, alert=alert)

        recommended_action = (
            risk.recommended_action
            if risk and risk.recommended_action
            else "No immediate action required."
        )

        return InvestigationResponse(
            subject=subject,
            flow=flow_dict,
            features=features_dict,
            ml_assessment=ml_dict,
            risk_assessment=risk_dict,
            evidence=evidence_list,
            findings=findings,
            timeline=timeline,
            summary=summary,
            recommended_action=recommended_action,
            limitations=list(STANDARD_LIMITATIONS),
        )


investigation_service = InvestigationService()
