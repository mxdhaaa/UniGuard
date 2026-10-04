"""
Unit & Integration Tests for Milestone 12 Dashboard API Endpoints

Covers:
1. overview on empty DB
2. flow list empty DB
3. alert list empty DB
4. persisted normal flow appears in flow list
5. flow filters
6. pagination
7. flow detail
8. missing flow -> 404
9. alert list
10. alert filters
11. alert detail
12. missing alert -> 404
13. threat analytics
14. hourly timeline
15. daily timeline
16. time-range filtering
17. deterministic ordering
18. overview ingestion state
19. overview ML readiness
"""

import pytest
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.models import Base
from backend.app.db.database import get_db
from backend.app.db import repositories
from backend.app.schemas.traffic import DirectionalFlowRecord, FeatureVector
from backend.app.schemas.ml import UnifiedMLResult, ModelReadinessState
from backend.app.schemas.risk import RiskAssessment, Severity, RiskFactor
from backend.app.schemas.evidence import EvidenceAssessment, EvidenceItem, EvidenceCategory
from backend.app.schemas.ingestion import IngestionStatusResponse
from backend.app.services.persistence_service import persistence_service
from backend.app.services.ingestion_service import ingestion_service
from backend.app.ml import model_manager


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
    threat_type: str = "NORMAL",
    severity: Severity = Severity.LOW,
    risk_score: float = 10.0,
    is_anomaly: bool = False,
    anomaly_score: float = 0.1,
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
        duration=1.5,
        packet_count=20,
        byte_count=2000,
        packet_sizes=[100] * 20,
        packet_timestamps=[0.0] * 20,
        inter_arrival_times=[0.0] * 19,
    )
    features = FeatureVector(
        flow_duration=1.5,
        packet_count=20.0,
        byte_count=2000.0,
        packets_per_second=13.3,
        bytes_per_second=1333.3,
        average_packet_size=100.0,
        packet_size_std=0.0,
        unique_destination_count=1.0,
        unique_destination_port_count=1.0,
        destination_port_entropy=0.0,
        packet_size_entropy=0.0,
        burst_score=0.0,
        source_activity_rate=0.0,
        destination_diversity=0.0,
        port_diversity=0.0,
        protocol_indicator=1.0,
    )
    ml_result = UnifiedMLResult(
        threat_type=threat_type,
        class_probabilities={threat_type: 0.95},
        classifier_confidence=0.95,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        model_version="1.0.0",
        feature_importances={"flow_duration": 0.3},
    )
    risk = RiskAssessment(
        risk_score=risk_score,
        severity=severity,
        threat_type=threat_type,
        confidence=0.95,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        risk_factors=[
            RiskFactor(
                factor="HIGH_RISK_FACTOR" if severity in (Severity.HIGH, Severity.CRITICAL) else "LOW_FACTOR",
                contribution=risk_score,
                description="Sample risk factor description",
            )
        ],
        explanation=f"Flow evaluated as {severity.value} risk",
        recommended_action="Investigate immediately" if severity in (Severity.HIGH, Severity.CRITICAL) else "No action",
    )
    evidence = EvidenceAssessment(
        evidence_id=f"ev_{flow_id}",
        flow_id=flow_id,
        threat_type=threat_type,
        risk_score=risk_score,
        severity=severity,
        summary=f"Evidence for {flow_id}",
        evidence_items=[
            EvidenceItem(
                evidence_id=f"item_{flow_id}_1",
                category=EvidenceCategory.THREAT_CLASSIFICATION,
                title="Classification Evidence",
                description=f"Classified as {threat_type}",
                value=threat_type,
                strength=0.9,
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


# 1. Overview on empty DB
def test_overview_empty_db(test_setup):
    client, _ = test_setup
    response = client.get("/api/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["total_flows"] == 0
    assert data["total_alerts"] == 0
    assert data["high_alerts"] == 0
    assert data["critical_alerts"] == 0
    assert data["anomaly_count"] == 0
    assert data["threat_type_distribution"] == {}
    assert data["severity_distribution"] == {}
    assert isinstance(data["ingestion_state"], str)
    assert isinstance(data["ml_readiness"], str)


# 2. Flow list empty DB
def test_flow_list_empty_db(test_setup):
    client, _ = test_setup
    response = client.get("/api/dashboard/flows")
    assert response.status_code == 200
    data = response.json()
    assert data["data"] == []
    assert data["meta"]["total_items"] == 0
    assert data["meta"]["total_pages"] == 0
    assert data["meta"]["page"] == 1
    assert data["meta"]["page_size"] == 20


# 3. Alert list empty DB
def test_alert_list_empty_db(test_setup):
    client, _ = test_setup
    response = client.get("/api/dashboard/alerts")
    assert response.status_code == 200
    data = response.json()
    assert data["data"] == []
    assert data["meta"]["total_items"] == 0
    assert data["meta"]["total_pages"] == 0
    assert data["meta"]["page"] == 1


# 4. Persisted normal flow appears in flow list
def test_persisted_normal_flow_appears_in_flow_list(test_setup):
    client, db = test_setup
    flow, feat, ml, risk, ev = _create_sample_flow("f_normal_1")
    persistence_service.save_analysis_result(db, flow, feat, ml, risk, ev)

    response = client.get("/api/dashboard/flows")
    assert response.status_code == 200
    data = response.json()
    assert len(data["data"]) == 1
    assert data["meta"]["total_items"] == 1
    item = data["data"][0]
    assert item["flow_id"] == "f_normal_1"
    assert item["source_ip"] == "10.0.0.1"
    assert item["destination_ip"] == "10.0.0.2"
    assert item["threat_type"] == "NORMAL"
    assert item["severity"] == "LOW"
    assert item["risk_score"] == 10.0
    assert item["is_anomaly"] is False
    assert item["protocol"] == "TCP"


# 5. Flow filters
def test_flow_filters(test_setup):
    client, db = test_setup
    f1, feat1, ml1, risk1, ev1 = _create_sample_flow(
        "f_dos",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        threat_type="DOS_LIKE",
        severity=Severity.HIGH,
        risk_score=65.0,
        is_anomaly=True,
    )
    f2, feat2, ml2, risk2, ev2 = _create_sample_flow(
        "f_scan",
        source_ip="172.16.0.20",
        destination_ip="10.0.0.6",
        threat_type="SCANNING_LIKE",
        severity=Severity.CRITICAL,
        risk_score=85.0,
        is_anomaly=False,
    )
    persistence_service.save_analysis_result(db, f1, feat1, ml1, risk1, ev1)
    persistence_service.save_analysis_result(db, f2, feat2, ml2, risk2, ev2)

    # Filter by threat_type
    res = client.get("/api/dashboard/flows?threat_type=DOS_LIKE")
    assert res.status_code == 200
    assert len(res.json()["data"]) == 1
    assert res.json()["data"][0]["flow_id"] == "f_dos"

    # Filter by severity
    res = client.get("/api/dashboard/flows?severity=CRITICAL")
    assert res.status_code == 200
    assert len(res.json()["data"]) == 1
    assert res.json()["data"][0]["flow_id"] == "f_scan"

    # Filter by is_anomaly
    res = client.get("/api/dashboard/flows?is_anomaly=true")
    assert res.status_code == 200
    assert len(res.json()["data"]) == 1
    assert res.json()["data"][0]["flow_id"] == "f_dos"

    # Filter by source_ip
    res = client.get("/api/dashboard/flows?source_ip=172.16.0.20")
    assert res.status_code == 200
    assert len(res.json()["data"]) == 1
    assert res.json()["data"][0]["flow_id"] == "f_scan"

    # Filter by destination_ip
    res = client.get("/api/dashboard/flows?destination_ip=10.0.0.5")
    assert res.status_code == 200
    assert len(res.json()["data"]) == 1
    assert res.json()["data"][0]["flow_id"] == "f_dos"


# 6. Pagination
def test_flow_pagination(test_setup):
    client, db = test_setup
    for i in range(5):
        f, feat, ml, risk, ev = _create_sample_flow(f"flow_p_{i:02d}", timestamp=f"2026-10-04T12:0{i}:00Z")
        persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res_p1 = client.get("/api/dashboard/flows?page=1&page_size=2")
    assert res_p1.status_code == 200
    d1 = res_p1.json()
    assert len(d1["data"]) == 2
    assert d1["meta"]["page"] == 1
    assert d1["meta"]["page_size"] == 2
    assert d1["meta"]["total_items"] == 5
    assert d1["meta"]["total_pages"] == 3

    res_p2 = client.get("/api/dashboard/flows?page=2&page_size=2")
    assert len(res_p2.json()["data"]) == 2

    res_p3 = client.get("/api/dashboard/flows?page=3&page_size=2")
    assert len(res_p3.json()["data"]) == 1

    res_p4 = client.get("/api/dashboard/flows?page=4&page_size=2")
    assert len(res_p4.json()["data"]) == 0


# 7. Flow detail
def test_flow_detail_endpoint(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow(
        "flow_detailed",
        threat_type="DOS_LIKE",
        severity=Severity.HIGH,
        risk_score=70.0,
    )
    persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res = client.get("/api/dashboard/flows/flow_detailed")
    assert res.status_code == 200
    data = res.json()
    assert "flow" in data
    assert "features" in data
    assert "ml_result" in data
    assert "risk_assessment" in data
    assert "evidence" in data
    assert "alert" in data

    assert data["flow"]["flow_id"] == "flow_detailed"
    assert data["features"]["flow_duration"] == 1.5
    assert data["ml_result"]["threat_type"] == "DOS_LIKE"
    assert data["risk_assessment"]["risk_score"] == 70.0
    assert len(data["evidence"]) >= 1
    assert data["alert"] is not None
    assert data["alert"]["flow_id"] == "flow_detailed"


# 8. Missing flow -> 404
def test_missing_flow_404(test_setup):
    client, _ = test_setup
    res = client.get("/api/dashboard/flows/non_existent_flow_id")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# 9. Alert list
def test_alert_list(test_setup):
    client, db = test_setup
    f1, feat1, ml1, risk1, ev1 = _create_sample_flow(
        "flow_alert_1",
        threat_type="DOS_LIKE",
        severity=Severity.HIGH,
        risk_score=60.0,
    )
    f2, feat2, ml2, risk2, ev2 = _create_sample_flow(
        "flow_alert_2",
        threat_type="EXFILTRATION",
        severity=Severity.CRITICAL,
        risk_score=90.0,
    )
    persistence_service.save_analysis_result(db, f1, feat1, ml1, risk1, ev1)
    persistence_service.save_analysis_result(db, f2, feat2, ml2, risk2, ev2)

    res = client.get("/api/dashboard/alerts")
    assert res.status_code == 200
    data = res.json()
    assert len(data["data"]) == 2
    assert data["meta"]["total_items"] == 2
    alert_item = data["data"][0]
    assert "alert_id" in alert_item
    assert "flow_id" in alert_item
    assert "severity" in alert_item
    assert "status" in alert_item
    assert "created_at" in alert_item


# 10. Alert filters
def test_alert_filters(test_setup):
    client, db = test_setup
    f1, feat1, ml1, risk1, ev1 = _create_sample_flow(
        "fa1",
        threat_type="DOS_LIKE",
        severity=Severity.HIGH,
        risk_score=60.0,
    )
    f2, feat2, ml2, risk2, ev2 = _create_sample_flow(
        "fa2",
        threat_type="EXFILTRATION",
        severity=Severity.CRITICAL,
        risk_score=90.0,
    )
    persistence_service.save_analysis_result(db, f1, feat1, ml1, risk1, ev1)
    persistence_service.save_analysis_result(db, f2, feat2, ml2, risk2, ev2)

    # Filter by severity
    res_crit = client.get("/api/dashboard/alerts?severity=CRITICAL")
    assert res_crit.status_code == 200
    assert len(res_crit.json()["data"]) == 1
    assert res_crit.json()["data"][0]["severity"] == "CRITICAL"

    # Filter by status
    res_status = client.get("/api/dashboard/alerts?status=OPEN")
    assert res_status.status_code == 200
    assert len(res_status.json()["data"]) == 2

    # Filter by threat_type
    res_threat = client.get("/api/dashboard/alerts?threat_type=EXFILTRATION")
    assert res_threat.status_code == 200
    assert len(res_threat.json()["data"]) == 1


# 11. Alert detail
def test_alert_detail_endpoint(test_setup):
    client, db = test_setup
    f, feat, ml, risk, ev = _create_sample_flow(
        "flow_alert_det",
        threat_type="DOS_LIKE",
        severity=Severity.HIGH,
        risk_score=72.0,
    )
    res_pers = persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)
    alert_id = res_pers["alert_id"]
    assert alert_id is not None

    res = client.get(f"/api/dashboard/alerts/{alert_id}")
    assert res.status_code == 200
    data = res.json()
    assert "alert" in data
    assert "flow" in data
    assert "ml_result" in data
    assert "risk_assessment" in data
    assert "evidence" in data

    assert data["alert"]["alert_id"] == alert_id
    assert data["flow"]["flow_id"] == "flow_alert_det"
    assert data["ml_result"]["threat_type"] == "DOS_LIKE"
    assert data["risk_assessment"]["risk_score"] == 72.0
    assert len(data["evidence"]) >= 1


# 12. Missing alert -> 404
def test_missing_alert_404(test_setup):
    client, _ = test_setup
    res = client.get("/api/dashboard/alerts/non_existent_alert_id")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# 13. Threat analytics
def test_threat_analytics(test_setup):
    client, db = test_setup
    f1, feat1, ml1, risk1, ev1 = _create_sample_flow(
        "t1", threat_type="DOS_LIKE", severity=Severity.HIGH, risk_score=60.0, is_anomaly=True
    )
    f2, feat2, ml2, risk2, ev2 = _create_sample_flow(
        "t2", threat_type="NORMAL", severity=Severity.LOW, risk_score=10.0, is_anomaly=False
    )
    persistence_service.save_analysis_result(db, f1, feat1, ml1, risk1, ev1)
    persistence_service.save_analysis_result(db, f2, feat2, ml2, risk2, ev2)

    res = client.get("/api/dashboard/threats")
    assert res.status_code == 200
    data = res.json()
    assert data["threat_type_distribution"]["DOS_LIKE"] == 1
    assert data["threat_type_distribution"]["NORMAL"] == 1
    assert data["severity_distribution"]["HIGH"] == 1
    assert data["severity_distribution"]["LOW"] == 1
    assert data["anomaly_count"] == 1


# 14. Hourly timeline
def test_hourly_timeline(test_setup):
    client, db = test_setup
    f1, feat1, ml1, risk1, ev1 = _create_sample_flow(
        "th1", timestamp="2026-10-04T10:15:00Z", threat_type="DOS_LIKE", severity=Severity.HIGH, is_anomaly=True
    )
    f2, feat2, ml2, risk2, ev2 = _create_sample_flow(
        "th2", timestamp="2026-10-04T10:45:00Z", threat_type="NORMAL", severity=Severity.LOW, is_anomaly=False
    )
    f3, feat3, ml3, risk3, ev3 = _create_sample_flow(
        "th3", timestamp="2026-10-04T11:20:00Z", threat_type="EXFILTRATION", severity=Severity.CRITICAL, is_anomaly=True
    )
    persistence_service.save_analysis_result(db, f1, feat1, ml1, risk1, ev1)
    persistence_service.save_analysis_result(db, f2, feat2, ml2, risk2, ev2)
    persistence_service.save_analysis_result(db, f3, feat3, ml3, risk3, ev3)

    res = client.get("/api/dashboard/timeline?interval=hour")
    assert res.status_code == 200
    data = res.json()
    assert data["interval"] == "hour"
    buckets = data["buckets"]
    assert len(buckets) == 2

    # Oldest bucket first
    b10 = buckets[0]
    assert b10["bucket_time"] == "2026-10-04T10"
    assert b10["flow_count"] == 2
    assert b10["alert_count"] == 1
    assert b10["high_alert_count"] == 1
    assert b10["anomaly_count"] == 1

    b11 = buckets[1]
    assert b11["bucket_time"] == "2026-10-04T11"
    assert b11["flow_count"] == 1
    assert b11["alert_count"] == 1
    assert b11["critical_alert_count"] == 1
    assert b11["anomaly_count"] == 1


# 15. Daily timeline
def test_daily_timeline(test_setup):
    client, db = test_setup
    f1, feat1, ml1, risk1, ev1 = _create_sample_flow(
        "td1", timestamp="2026-10-04T10:00:00Z", threat_type="NORMAL", severity=Severity.LOW
    )
    f2, feat2, ml2, risk2, ev2 = _create_sample_flow(
        "td2", timestamp="2026-10-05T14:00:00Z", threat_type="DOS_LIKE", severity=Severity.HIGH
    )
    persistence_service.save_analysis_result(db, f1, feat1, ml1, risk1, ev1)
    persistence_service.save_analysis_result(db, f2, feat2, ml2, risk2, ev2)

    res = client.get("/api/dashboard/timeline?interval=day")
    assert res.status_code == 200
    data = res.json()
    assert data["interval"] == "day"
    buckets = data["buckets"]
    assert len(buckets) == 2
    assert buckets[0]["bucket_time"] == "2026-10-04"
    assert buckets[0]["flow_count"] == 1
    assert buckets[1]["bucket_time"] == "2026-10-05"
    assert buckets[1]["flow_count"] == 1


# 16. Time-range filtering
def test_time_range_filtering(test_setup):
    client, db = test_setup
    f1, feat1, ml1, risk1, ev1 = _create_sample_flow("tr1", timestamp="2026-10-04T08:00:00Z")
    f2, feat2, ml2, risk2, ev2 = _create_sample_flow("tr2", timestamp="2026-10-04T12:00:00Z")
    f3, feat3, ml3, risk3, ev3 = _create_sample_flow("tr3", timestamp="2026-10-04T18:00:00Z")
    persistence_service.save_analysis_result(db, f1, feat1, ml1, risk1, ev1)
    persistence_service.save_analysis_result(db, f2, feat2, ml2, risk2, ev2)
    persistence_service.save_analysis_result(db, f3, feat3, ml3, risk3, ev3)

    # Filter flows within window
    res_flows = client.get("/api/dashboard/flows?start_time=2026-10-04T10:00:00Z&end_time=2026-10-04T14:00:00Z")
    assert res_flows.status_code == 200
    flows = res_flows.json()["data"]
    assert len(flows) == 1
    assert flows[0]["flow_id"] == "tr2"

    # Filter timeline within window
    res_tl = client.get("/api/dashboard/timeline?interval=hour&start_time=2026-10-04T10:00:00Z&end_time=2026-10-04T14:00:00Z")
    assert res_tl.status_code == 200
    tl_buckets = res_tl.json()["buckets"]
    assert len(tl_buckets) == 1
    assert tl_buckets[0]["bucket_time"] == "2026-10-04T12"


# 17. Deterministic ordering
def test_deterministic_ordering(test_setup):
    client, db = test_setup
    # Insert multiple flows with the same timestamp
    same_ts = "2026-10-04T15:00:00Z"
    for fid in ["flow_c", "flow_a", "flow_b", "flow_d"]:
        f, feat, ml, risk, ev = _create_sample_flow(fid, timestamp=same_ts)
        persistence_service.save_analysis_result(db, f, feat, ml, risk, ev)

    res1 = client.get("/api/dashboard/flows?page=1&page_size=10")
    assert res1.status_code == 200
    ids_1 = [item["flow_id"] for item in res1.json()["data"]]

    res2 = client.get("/api/dashboard/flows?page=1&page_size=10")
    assert res2.status_code == 200
    ids_2 = [item["flow_id"] for item in res2.json()["data"]]

    # Secondary order by flow_id DESC
    assert ids_1 == ["flow_d", "flow_c", "flow_b", "flow_a"]
    assert ids_1 == ids_2


# 18. Overview ingestion state
def test_overview_ingestion_state(test_setup, monkeypatch):
    client, _ = test_setup

    def mock_get_status_running():
        return IngestionStatusResponse(
            state="RUNNING",
            interface="eth0",
            capture_filter="ip",
            active_flows=3,
            packets_captured=100,
            flows_completed=10,
            errors=0,
        )

    monkeypatch.setattr(ingestion_service, "get_status", mock_get_status_running)
    res = client.get("/api/dashboard/overview")
    assert res.status_code == 200
    assert res.json()["ingestion_state"] == "RUNNING"


# 19. Overview ML readiness
def test_overview_ml_readiness(test_setup, monkeypatch):
    client, _ = test_setup

    def mock_get_state_not_trained():
        return ModelReadinessState.NOT_TRAINED

    monkeypatch.setattr(model_manager, "get_state", mock_get_state_not_trained)
    res = client.get("/api/dashboard/overview")
    assert res.status_code == 200
    assert res.json()["ml_readiness"] == "NOT_TRAINED"


def test_timeline_invalid_interval(test_setup):
    client, _ = test_setup
    res = client.get("/api/dashboard/timeline?interval=invalid_interval")
    assert res.status_code == 400
    assert "invalid interval" in res.json()["detail"].lower()


def test_flow_detail_partial_data(test_setup):
    client, db = test_setup
    # Save only flow record without ML, risk, features, evidence, or alert
    flow = DirectionalFlowRecord(
        flow_id="f_solo",
        timestamp="2026-10-04T12:00:00Z",
        source_ip="10.0.0.1",
        source_port=80,
        destination_ip="10.0.0.2",
        destination_port=8080,
        protocol="TCP",
        duration=1.0,
        packet_count=5,
        byte_count=500,
        packet_sizes=[100] * 5,
        packet_timestamps=[0.0] * 5,
        inter_arrival_times=[0.0] * 4,
    )
    repositories.save_flow(db, flow)
    db.commit()

    # Flow should appear in flow list with defaults
    res_list = client.get("/api/dashboard/flows")
    assert res_list.status_code == 200
    assert len(res_list.json()["data"]) == 1
    assert res_list.json()["data"][0]["flow_id"] == "f_solo"
    assert res_list.json()["data"][0]["threat_type"] == "UNKNOWN"
    assert res_list.json()["data"][0]["severity"] == "LOW"

    # Flow detail should return gracefully
    res_det = client.get("/api/dashboard/flows/f_solo")
    assert res_det.status_code == 200
    data = res_det.json()
    assert data["flow"]["flow_id"] == "f_solo"
    assert data["features"] == {}
    assert data["ml_result"] == {}
    assert data["risk_assessment"] == {}
    assert data["evidence"] == []
    assert data["alert"] is None


def test_pagination_validation_errors(test_setup):
    client, _ = test_setup
    # Page must be >= 1
    res_page_zero = client.get("/api/dashboard/flows?page=0")
    assert res_page_zero.status_code == 422

    # Page size must be <= 100
    res_page_huge = client.get("/api/dashboard/flows?page_size=101")
    assert res_page_huge.status_code == 422

