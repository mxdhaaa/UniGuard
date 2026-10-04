"""
Unit & Integration Tests for Milestone 13 Report API Endpoints

Covers:
1. flow report
2. alert report
3. missing flow -> 404
4. missing alert -> 404
5. report contains executive summary
6. report contains classification
7. report contains risk
8. report contains anomaly
9. report contains evidence
10. report contains findings
11. report contains recommended action
12. report contains limitations
13. verify report generation does NOT modify DB records
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.models import (
    Base,
    TrafficFlowModel,
    FeatureModel,
    MLResultModel,
    RiskAssessmentModel,
    EvidenceModel,
    AlertModel,
)
from backend.app.db.database import get_db
from backend.app.schemas.traffic import DirectionalFlowRecord, FeatureVector
from backend.app.schemas.ml import UnifiedMLResult
from backend.app.schemas.risk import RiskAssessment, Severity, RiskFactor
from backend.app.schemas.evidence import EvidenceAssessment, EvidenceItem, EvidenceCategory
from backend.app.services.persistence_service import persistence_service


@pytest.fixture
def test_setup():
    """Provides an isolated in-memory SQLite database and test client."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    yield client, db

    db.close()
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


def _create_sample_flow(
    flow_id: str,
    timestamp: str = "2026-10-04T14:00:00Z",
    source_ip: str = "192.168.1.50",
    destination_ip: str = "10.0.0.10",
    threat_type: str = "EXFILTRATION",
    severity: Severity = Severity.CRITICAL,
    risk_score: float = 90.0,
    is_anomaly: bool = True,
    anomaly_score: float = 0.95,
):
    flow = DirectionalFlowRecord(
        flow_id=flow_id,
        timestamp=timestamp,
        source_ip=source_ip,
        source_port=54321,
        destination_ip=destination_ip,
        destination_port=443,
        protocol="TCP",
        duration=10.0,
        packet_count=1000,
        byte_count=1000000,
        packet_sizes=[1000] * 1000,
        packet_timestamps=[0.01 * i for i in range(1000)],
        inter_arrival_times=[0.01] * 999,
    )
    features = FeatureVector(
        flow_duration=10.0,
        packet_count=1000.0,
        byte_count=1000000.0,
        packets_per_second=100.0,
        bytes_per_second=100000.0,
        average_packet_size=1000.0,
        packet_size_std=0.0,
        unique_destination_count=1.0,
        unique_destination_port_count=1.0,
        destination_port_entropy=0.0,
        packet_size_entropy=0.0,
        burst_score=0.9,
        source_activity_rate=100.0,
        destination_diversity=0.0,
        port_diversity=0.0,
        protocol_indicator=1.0,
    )
    ml_result = UnifiedMLResult(
        threat_type=threat_type,
        class_probabilities={threat_type: 0.98, "NORMAL": 0.02},
        classifier_confidence=0.98,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        model_version="1.0.0",
        feature_importances={"bytes_per_second": 0.5},
    )
    risk = RiskAssessment(
        risk_score=risk_score,
        severity=severity,
        threat_type=threat_type,
        confidence=0.98,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        risk_factors=[
            RiskFactor(
                factor="EXTREME_VOLUME",
                contribution=50.0,
                description="Megabyte-scale unidirectional exfiltration burst detected",
            )
        ],
        explanation="Large volumetric outbound transfer consistent with data exfiltration",
        recommended_action="Immediately quarantine endpoint and revoke network access credentials",
    )
    evidence = EvidenceAssessment(
        evidence_id=f"ev_{flow_id}",
        flow_id=flow_id,
        threat_type=threat_type,
        risk_score=risk_score,
        severity=severity,
        summary=f"Critical exfiltration evidence for {flow_id}",
        evidence_items=[
            EvidenceItem(
                evidence_id=f"item_{flow_id}_1",
                category=EvidenceCategory.THREAT_CLASSIFICATION,
                title="RandomForest Exfiltration Classifier",
                description="High confidence exfiltration pattern identified",
                value=threat_type,
                strength=0.98,
                source="RandomForest",
                severity=severity,
            )
        ],
        top_features=[],
        supporting_signals=[],
        contradictory_signals=[],
        limitations=[],
    )
    return flow, features, ml_result, risk, evidence


# 1. Flow report
def test_flow_report_generation(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_1")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_1")
    assert res.status_code == 200
    data = res.json()
    assert data["report_type"] == "FLOW_INVESTIGATION"
    assert data["subject"]["flow_id"] == "rep_flow_1"
    assert data["report_id"].startswith("rep-")
    assert "generated_at" in data


# 2. Alert report
def test_alert_report_generation(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_2")
    res_pers = persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)
    alert_id = res_pers["alert_id"]
    assert alert_id is not None

    res = client.get(f"/api/reports/alerts/{alert_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["report_type"] == "ALERT_INVESTIGATION"
    assert data["subject"]["alert_id"] == alert_id
    assert data["subject"]["flow_id"] == "rep_flow_2"


# 3. Missing flow -> 404
def test_missing_flow_report_404(test_setup):
    client, _ = test_setup
    res = client.get("/api/reports/flows/non_existent_flow")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# 4. Missing alert -> 404
def test_missing_alert_report_404(test_setup):
    client, _ = test_setup
    res = client.get("/api/reports/alerts/non_existent_alert")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# 5. Report contains executive summary
def test_report_contains_executive_summary(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_summary")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_summary")
    assert res.status_code == 200
    summary = res.json()["executive_summary"]
    assert isinstance(summary, str)
    assert "EXFILTRATION" in summary
    assert "90.0" in summary
    assert "CRITICAL" in summary


# 6. Report contains classification
def test_report_contains_classification(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_cls")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_cls")
    assert res.status_code == 200
    cls_data = res.json()["classification"]
    assert cls_data["threat_type"] == "EXFILTRATION"
    assert cls_data["classifier_confidence"] == 0.98


# 7. Report contains risk
def test_report_contains_risk(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_risk")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_risk")
    assert res.status_code == 200
    risk_data = res.json()["risk"]
    assert risk_data["risk_score"] == 90.0
    assert risk_data["severity"] == "CRITICAL"
    assert len(risk_data["risk_factors"]) >= 1


# 8. Report contains anomaly
def test_report_contains_anomaly(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_anom")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_anom")
    assert res.status_code == 200
    anom_data = res.json()["anomaly"]
    assert anom_data["is_anomaly"] is True
    assert anom_data["anomaly_score"] == 0.95
    assert anom_data["model_version"] == "1.0.0"


# 9. Report contains evidence
def test_report_contains_evidence(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_ev")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_ev")
    assert res.status_code == 200
    evidence = res.json()["evidence"]
    assert len(evidence) >= 1
    assert evidence[0]["category"] == "THREAT_CLASSIFICATION"


# 10. Report contains findings
def test_report_contains_findings(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_find")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_find")
    assert res.status_code == 200
    findings = res.json()["findings"]
    assert len(findings) >= 4
    categories = {find["category"] for find in findings}
    assert "CLASSIFICATION" in categories
    assert "RISK" in categories
    assert "ANOMALY" in categories


# 11. Report contains recommended action
def test_report_contains_recommended_action(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_action")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_action")
    assert res.status_code == 200
    action = res.json()["recommended_action"]
    assert "quarantine endpoint" in action.lower()


# 12. Report contains limitations
def test_report_contains_limitations(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_lim")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/reports/flows/rep_flow_lim")
    assert res.status_code == 200
    limitations = res.json()["limitations"]
    assert len(limitations) >= 5
    assert any("unidirectional" in lim.lower() for lim in limitations)
    assert any("payload" in lim.lower() for lim in limitations)


# 13. Verify report generation does NOT modify DB records
def test_report_generation_does_not_modify_db(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("rep_flow_ro")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    count_flows_before = db.query(TrafficFlowModel).count()
    count_features_before = db.query(FeatureModel).count()
    count_ml_before = db.query(MLResultModel).count()
    count_risk_before = db.query(RiskAssessmentModel).count()
    count_evidence_before = db.query(EvidenceModel).count()
    count_alerts_before = db.query(AlertModel).count()

    # Generate report
    res = client.get("/api/reports/flows/rep_flow_ro")
    assert res.status_code == 200

    # Counts must remain completely unchanged
    assert db.query(TrafficFlowModel).count() == count_flows_before
    assert db.query(FeatureModel).count() == count_features_before
    assert db.query(MLResultModel).count() == count_ml_before
    assert db.query(RiskAssessmentModel).count() == count_risk_before
    assert db.query(EvidenceModel).count() == count_evidence_before
    assert db.query(AlertModel).count() == count_alerts_before
