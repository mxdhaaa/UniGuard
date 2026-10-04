"""
Tests for the persistence orchestration service.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import Base, TrafficFlowModel, MLResultModel, FeatureModel, RiskAssessmentModel, EvidenceModel, AlertModel
from backend.app.services.persistence_service import persistence_service
from backend.app.schemas.traffic import DirectionalFlowRecord, FeatureVector
from backend.app.schemas.ml import UnifiedMLResult
from backend.app.schemas.risk import RiskAssessment, Severity, RiskFactor
from backend.app.schemas.evidence import EvidenceAssessment, EvidenceItem, EvidenceCategory


@pytest.fixture
def db_session():
    """Provides a clean in-memory SQLite database per test."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _make_dummy_data(flow_id="t1"):
    flow = DirectionalFlowRecord(
        flow_id=flow_id, timestamp="Z", source_ip="1.1.1.1", source_port=1,
        destination_ip="2.2.2.2", destination_port=2, protocol="TCP",
        duration=1.0, packet_count=10, byte_count=1000,
        packet_sizes=[], packet_timestamps=[], inter_arrival_times=[]
    )
    features = FeatureVector(
        flow_duration=1.0, packet_count=10.0, byte_count=1000.0,
        packets_per_second=10.0, bytes_per_second=1000.0,
        average_packet_size=100.0, packet_size_std=0.0,
        unique_destination_count=1.0, unique_destination_port_count=1.0,
        destination_port_entropy=0.0, packet_size_entropy=0.0,
        burst_score=0.0, source_activity_rate=0.0,
        destination_diversity=0.0, port_diversity=0.0,
        protocol_indicator=0.0
    )
    ml_result = UnifiedMLResult(
        threat_type="NORMAL",
        class_probabilities={"NORMAL": 1.0},
        classifier_confidence=1.0,
        anomaly_score=0.0,
        is_anomaly=False,
        model_version="1.0",
        feature_importances={}
    )
    risk = RiskAssessment(
        risk_score=10.0,
        severity=Severity.LOW,
        threat_type="NORMAL",
        confidence=1.0,
        anomaly_score=0.0,
        is_anomaly=False,
        risk_factors=[RiskFactor(factor="f", contribution=1.0, description="d")],
        explanation="e",
        recommended_action="a"
    )
    evidence = EvidenceAssessment(
        evidence_id="e1",
        flow_id=flow_id,
        threat_type="NORMAL",
        risk_score=10.0,
        severity=Severity.LOW,
        summary="sum",
        evidence_items=[
            EvidenceItem(evidence_id="i1", category=EvidenceCategory.THREAT_CLASSIFICATION,
                         title="t", description="d", value="v", strength=1.0, source="s", severity=Severity.LOW)
        ],
        top_features=[],
        supporting_signals=[],
        contradictory_signals=[],
        limitations=[]
    )
    return flow, features, ml_result, risk, evidence


def test_complete_analysis_persistence(db_session):
    flow, feat, ml, risk, ev = _make_dummy_data("c1")
    
    result = persistence_service.save_analysis_result(db_session, flow, feat, ml, risk, ev)
    assert result["status"] == "success"
    assert result["flow_id"] == "c1"
    assert result["alert_id"] is None  # LOW risk, no alert
    
    # Verify records
    assert db_session.query(TrafficFlowModel).count() == 1
    assert db_session.query(FeatureModel).count() == 1
    assert db_session.query(MLResultModel).count() == 1
    assert db_session.query(RiskAssessmentModel).count() == 1
    assert db_session.query(EvidenceModel).count() == 1
    assert db_session.query(AlertModel).count() == 0


def test_alert_created_for_high_severity(db_session):
    flow, feat, ml, risk, ev = _make_dummy_data("c2")
    risk.severity = Severity.HIGH
    
    result = persistence_service.save_analysis_result(db_session, flow, feat, ml, risk, ev)
    assert result["status"] == "success"
    assert result["alert_id"] is not None
    
    alert = db_session.query(AlertModel).filter_by(flow_id="c2").first()
    assert alert is not None
    assert alert.severity == "HIGH"
    assert alert.status == "OPEN"


def test_alert_created_for_critical_severity(db_session):
    flow, feat, ml, risk, ev = _make_dummy_data("c3")
    risk.severity = Severity.CRITICAL
    
    result = persistence_service.save_analysis_result(db_session, flow, feat, ml, risk, ev)
    assert result["status"] == "success"
    assert result["alert_id"] is not None


def test_duplicate_flow_handled_gracefully(db_session):
    flow, feat, ml, risk, ev = _make_dummy_data("c4")
    
    res1 = persistence_service.save_analysis_result(db_session, flow, feat, ml, risk, ev)
    assert res1["status"] == "success"
    
    res2 = persistence_service.save_analysis_result(db_session, flow, feat, ml, risk, ev)
    assert res2["status"] == "skipped"
    assert db_session.query(TrafficFlowModel).count() == 1


def test_transaction_rollback_on_error(db_session, monkeypatch):
    from backend.app.db import repositories
    
    # Force a failure during saving evidence to trigger rollback
    def raise_error(*args, **kwargs):
        raise ValueError("Simulated failure")
        
    monkeypatch.setattr(repositories, "save_evidence", raise_error)
    
    flow, feat, ml, risk, ev = _make_dummy_data("c5")
    
    with pytest.raises(ValueError):
        persistence_service.save_analysis_result(db_session, flow, feat, ml, risk, ev)
        
    # Entire transaction should have rolled back
    assert db_session.query(TrafficFlowModel).count() == 0
    assert db_session.query(FeatureModel).count() == 0
    assert db_session.query(MLResultModel).count() == 0
