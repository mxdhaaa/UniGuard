"""
Unit & Integration Tests for Milestone 13 Investigation API Endpoints

Covers:
1. flow investigation for persisted flow
2. missing flow -> 404
3. alert investigation for persisted alert
4. missing alert -> 404
5. investigation contains 16 features
6. investigation contains ML result
7. investigation contains risk assessment
8. investigation contains evidence
9. investigation contains associated alert when present
10. investigation works when optional records are missing
11. deterministic findings
12. deterministic summary
13. timeline ordering
14. limitations are present
15. no raw ORM serialization leakage
16. verify investigation queries do NOT modify DB records
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
from backend.app.db import repositories
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
    timestamp: str = "2026-10-04T12:00:00Z",
    source_ip: str = "10.0.0.1",
    destination_ip: str = "10.0.0.2",
    threat_type: str = "DOS_LIKE",
    severity: Severity = Severity.HIGH,
    risk_score: float = 72.0,
    is_anomaly: bool = True,
    anomaly_score: float = 0.85,
    source_port: int = 12345,
    destination_port: int = 80,
    protocol: str = "TCP",
):
    flow = DirectionalFlowRecord(
        flow_id=flow_id,
        timestamp=timestamp,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=protocol,
        duration=2.5,
        packet_count=50,
        byte_count=5000,
        packet_sizes=[100] * 50,
        packet_timestamps=[0.0] * 50,
        inter_arrival_times=[0.0] * 49,
    )
    features = FeatureVector(
        flow_duration=2.5,
        packet_count=50.0,
        byte_count=5000.0,
        packets_per_second=20.0,
        bytes_per_second=2000.0,
        average_packet_size=100.0,
        packet_size_std=0.0,
        unique_destination_count=1.0,
        unique_destination_port_count=1.0,
        destination_port_entropy=0.0,
        packet_size_entropy=0.0,
        burst_score=0.5,
        source_activity_rate=0.5,
        destination_diversity=0.0,
        port_diversity=0.0,
        protocol_indicator=1.0,
    )
    ml_result = UnifiedMLResult(
        threat_type=threat_type,
        class_probabilities={threat_type: 0.92, "NORMAL": 0.08},
        classifier_confidence=0.92,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        model_version="1.0.0",
        feature_importances={"packets_per_second": 0.4},
    )
    risk = RiskAssessment(
        risk_score=risk_score,
        severity=severity,
        threat_type=threat_type,
        confidence=0.92,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        risk_factors=[
            RiskFactor(
                factor="HIGH_RATE",
                contribution=risk_score,
                description="Packet rate exceeded baseline thresholds",
            )
        ],
        explanation=f"Traffic pattern aligns with {threat_type} high rate profile",
        recommended_action="Isolate source IP and monitor perimeter firewall",
    )
    evidence = EvidenceAssessment(
        evidence_id=f"ev_{flow_id}",
        flow_id=flow_id,
        threat_type=threat_type,
        risk_score=risk_score,
        severity=severity,
        summary=f"Evidence collected for {flow_id}",
        evidence_items=[
            EvidenceItem(
                evidence_id=f"item_{flow_id}_1",
                category=EvidenceCategory.THREAT_CLASSIFICATION,
                title="RandomForest Classification",
                description=f"Classified as {threat_type} with 92% confidence",
                value=threat_type,
                strength=0.92,
                source="RandomForest",
                severity=severity,
            ),
            EvidenceItem(
                evidence_id=f"item_{flow_id}_2",
                category=EvidenceCategory.ANOMALY_SIGNAL,
                title="IsolationForest Anomaly",
                description="Anomaly score 0.85 indicates substantial outlier divergence",
                value="0.85",
                strength=0.85,
                source="IsolationForest",
                severity=severity,
            ),
        ],
        top_features=[],
        supporting_signals=[],
        contradictory_signals=[],
        limitations=[],
    )
    return flow, features, ml_result, risk, evidence


# 1. Flow investigation for persisted flow
def test_flow_investigation_persisted_flow(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_1")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_1")
    assert res.status_code == 200
    data = res.json()
    assert data["subject"]["flow_id"] == "inv_flow_1"
    assert data["subject"]["investigation_id"] == "inv-inv_flow_1"
    assert data["subject"]["alert_id"] is not None


# 2. Missing flow -> 404
def test_missing_flow_404(test_setup):
    client, _ = test_setup
    res = client.get("/api/investigations/flows/non_existent_flow")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# 3. Alert investigation for persisted alert
def test_alert_investigation_persisted_alert(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_2")
    res_pers = persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)
    alert_id = res_pers["alert_id"]
    assert alert_id is not None

    res = client.get(f"/api/investigations/alerts/{alert_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["subject"]["alert_id"] == alert_id
    assert data["subject"]["flow_id"] == "inv_flow_2"
    assert data["subject"]["investigation_id"] == f"inv-alert-{alert_id}"


# 4. Missing alert -> 404
def test_missing_alert_404(test_setup):
    client, _ = test_setup
    res = client.get("/api/investigations/alerts/non_existent_alert")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# 5. Investigation contains 16 features
def test_investigation_contains_16_features(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_feat")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_feat")
    assert res.status_code == 200
    features = res.json()["features"]

    expected_16_canonical = [
        "flow_duration",
        "packet_count",
        "byte_count",
        "packets_per_second",
        "bytes_per_second",
        "average_packet_size",
        "packet_size_std",
        "unique_destination_count",
        "unique_destination_port_count",
        "destination_port_entropy",
        "packet_size_entropy",
        "burst_score",
        "source_activity_rate",
        "destination_diversity",
        "port_diversity",
        "protocol_indicator",
    ]
    for canon in expected_16_canonical:
        assert canon in features
        assert features[canon] is not None


# 6. Investigation contains ML result
def test_investigation_contains_ml_result(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_ml")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_ml")
    assert res.status_code == 200
    ml_data = res.json()["ml_assessment"]
    assert ml_data["threat_type"] == "DOS_LIKE"
    assert ml_data["classifier_confidence"] == 0.92
    assert ml_data["anomaly_score"] == 0.85
    assert ml_data["is_anomaly"] is True
    assert ml_data["model_version"] == "1.0.0"
    assert "class_probabilities" in ml_data


# 7. Investigation contains risk assessment
def test_investigation_contains_risk_assessment(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_risk")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_risk")
    assert res.status_code == 200
    risk_data = res.json()["risk_assessment"]
    assert risk_data["risk_score"] == 72.0
    assert risk_data["severity"] == "HIGH"
    assert risk_data["threat_type"] == "DOS_LIKE"
    assert "risk_factors" in risk_data
    assert len(risk_data["risk_factors"]) >= 1


# 8. Investigation contains evidence
def test_investigation_contains_evidence(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_ev")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_ev")
    assert res.status_code == 200
    evidence = res.json()["evidence"]
    assert len(evidence) == 2
    assert evidence[0]["category"] == "THREAT_CLASSIFICATION"
    assert evidence[1]["category"] == "ANOMALY_SIGNAL"


# 9. Investigation contains associated alert when present
def test_investigation_associated_alert_present(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_al", severity=Severity.HIGH, risk_score=75.0)
    res_pers = persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)
    alert_id = res_pers["alert_id"]
    assert alert_id is not None

    res = client.get("/api/investigations/flows/inv_flow_al")
    assert res.status_code == 200
    data = res.json()
    assert data["subject"]["alert_id"] == alert_id

    # Check alert finding in findings
    alert_findings = [f for f in data["findings"] if f["category"] == "ALERT"]
    assert len(alert_findings) == 1
    assert alert_id in alert_findings[0]["finding_id"]


# 10. Investigation works when optional records are missing
def test_investigation_optional_records_missing(test_setup):
    client, db = test_setup
    # Save bare flow record without ML, risk, features, evidence, or alert
    flow = DirectionalFlowRecord(
        flow_id="inv_bare",
        timestamp="2026-10-04T12:00:00Z",
        source_ip="10.0.0.1",
        source_port=80,
        destination_ip="10.0.0.2",
        destination_port=8080,
        protocol="TCP",
        duration=1.0,
        packet_count=10,
        byte_count=1000,
        packet_sizes=[100] * 10,
        packet_timestamps=[0.0] * 10,
        inter_arrival_times=[0.0] * 9,
    )
    repositories.save_flow(db, flow)
    db.commit()

    res = client.get("/api/investigations/flows/inv_bare")
    assert res.status_code == 200
    data = res.json()
    assert data["subject"]["flow_id"] == "inv_bare"
    assert data["subject"]["alert_id"] is None
    assert data["features"] == {}
    assert data["ml_assessment"] == {}
    assert data["risk_assessment"] == {}
    assert data["evidence"] == []
    assert len(data["findings"]) >= 1  # Should still have TRAFFIC_BEHAVIOR finding
    assert len(data["timeline"]) == 1  # Flow observed event
    assert isinstance(data["summary"], str)
    assert len(data["summary"]) > 0


# 11. Deterministic findings
def test_deterministic_findings(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_find")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_find")
    assert res.status_code == 200
    findings = res.json()["findings"]

    categories = {f["category"] for f in findings}
    assert "CLASSIFICATION" in categories
    assert "ANOMALY" in categories
    assert "RISK" in categories
    assert "TRAFFIC_BEHAVIOR" in categories
    assert "EVIDENCE" in categories
    assert "ALERT" in categories

    for f in findings:
        assert f["finding_id"] is not None
        assert f["title"] is not None
        assert f["description"] is not None
        assert f["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert f["source"] is not None


# 12. Deterministic summary
def test_deterministic_summary(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow(
        "inv_flow_sum",
        threat_type="DOS_LIKE",
        severity=Severity.HIGH,
        risk_score=72.0,
        is_anomaly=True,
        anomaly_score=0.85,
    )
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_sum")
    assert res.status_code == 200
    summary = res.json()["summary"]

    assert "DOS_LIKE" in summary
    assert "72.0" in summary
    assert "HIGH" in summary
    assert "0.92" in summary
    assert "flagged" in summary
    assert "0.85" in summary


# 13. Timeline ordering
def test_timeline_ordering(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_time")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_time")
    assert res.status_code == 200
    timeline = res.json()["timeline"]

    assert len(timeline) >= 3  # Flow, 2 evidence items, alert
    timestamps = [t["timestamp"] for t in timeline]
    assert timestamps == sorted(timestamps)

    for item in timeline:
        assert item["event_type"] in ("FLOW_OBSERVED", "EVIDENCE_RECORDED", "ALERT_GENERATED")
        assert item["title"] is not None
        assert item["source"] is not None


# 14. Limitations are present
def test_limitations_present(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_lim")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_lim")
    assert res.status_code == 200
    limitations = res.json()["limitations"]

    assert len(limitations) >= 5
    assert any("unidirectional" in lim.lower() for lim in limitations)
    assert any("payload" in lim.lower() for lim in limitations)
    assert any("not recomputed" in lim.lower() for lim in limitations)


# 15. No raw ORM serialization leakage
def test_no_raw_orm_leakage(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_leak")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/investigations/flows/inv_flow_leak")
    assert res.status_code == 200
    raw_text = res.text

    assert "_sa_instance_state" not in raw_text
    assert "backend.app.db.models" not in raw_text


# 16. Verify investigation queries do NOT modify DB records
def test_investigation_is_strictly_read_only(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow("inv_flow_ro")
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    count_flows_before = db.query(TrafficFlowModel).count()
    count_features_before = db.query(FeatureModel).count()
    count_ml_before = db.query(MLResultModel).count()
    count_risk_before = db.query(RiskAssessmentModel).count()
    count_evidence_before = db.query(EvidenceModel).count()
    count_alerts_before = db.query(AlertModel).count()

    # Query investigation
    res = client.get("/api/investigations/flows/inv_flow_ro")
    assert res.status_code == 200

    # Counts must remain completely unchanged
    assert db.query(TrafficFlowModel).count() == count_flows_before
    assert db.query(FeatureModel).count() == count_features_before
    assert db.query(MLResultModel).count() == count_ml_before
    assert db.query(RiskAssessmentModel).count() == count_risk_before
    assert db.query(EvidenceModel).count() == count_evidence_before
    assert db.query(AlertModel).count() == count_alerts_before
