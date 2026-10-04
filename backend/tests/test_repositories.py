"""
Tests for repository CRUD operations.
Uses an isolated in-memory SQLite database.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import Base, TrafficFlowModel, MLResultModel, FeatureModel
from backend.app.db import repositories
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


def test_save_and_get_flow(db_session):
    flow = DirectionalFlowRecord(
        flow_id="f1", timestamp="Z", source_ip="1.1.1.1", source_port=1,
        destination_ip="2.2.2.2", destination_port=2, protocol="TCP",
        duration=1.0, packet_count=10, byte_count=1000,
        packet_sizes=[], packet_timestamps=[], inter_arrival_times=[]
    )
    repositories.save_flow(db_session, flow)
    db_session.commit()
    
    retrieved = repositories.get_flow(db_session, "f1")
    assert retrieved is not None
    assert retrieved.source_ip == "1.1.1.1"


def test_duplicate_flow_fails(db_session):
    flow = DirectionalFlowRecord(
        flow_id="f2", timestamp="Z", source_ip="1.1.1.1", source_port=1,
        destination_ip="2.2.2.2", destination_port=2, protocol="TCP",
        duration=1.0, packet_count=10, byte_count=1000,
        packet_sizes=[], packet_timestamps=[], inter_arrival_times=[]
    )
    repositories.save_flow(db_session, flow)
    db_session.commit()
    
    # Attempting to save same flow_id again
    repositories.save_flow(db_session, flow)
    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_save_features_canonical(db_session):
    flow = DirectionalFlowRecord(
        flow_id="f3", timestamp="Z", source_ip="1.1.1.1", source_port=1,
        destination_ip="2.2.2.2", destination_port=2, protocol="TCP",
        duration=1.0, packet_count=10, byte_count=1000,
        packet_sizes=[], packet_timestamps=[], inter_arrival_times=[]
    )
    repositories.save_flow(db_session, flow)
    db_session.commit()
    
    fv = FeatureVector(
        flow_duration=1.0, packet_count=10.0, byte_count=1000.0,
        packets_per_second=10.0, bytes_per_second=1000.0,
        average_packet_size=100.0, packet_size_std=0.0,
        unique_destination_count=1.0, unique_destination_port_count=1.0,
        destination_port_entropy=0.0, packet_size_entropy=0.0,
        burst_score=0.0, source_activity_rate=0.0,
        destination_diversity=0.0, port_diversity=0.0,
        protocol_indicator=0.0
    )
    
    db_feat = repositories.save_features(db_session, "f3", fv)
    db_session.commit()
    
    assert db_feat.packets_per_second == 10.0
    assert db_feat.flow_duration == 1.0


def test_save_ml_result_json_roundtrip(db_session):
    flow = DirectionalFlowRecord(
        flow_id="f4", timestamp="Z", source_ip="1.1.1.1", source_port=1,
        destination_ip="2.2.2.2", destination_port=2, protocol="TCP",
        duration=1.0, packet_count=10, byte_count=1000,
        packet_sizes=[], packet_timestamps=[], inter_arrival_times=[]
    )
    repositories.save_flow(db_session, flow)
    db_session.commit()
    
    ml = UnifiedMLResult(
        threat_type="NORMAL",
        class_probabilities={"NORMAL": 0.9, "DOS_LIKE": 0.1},
        classifier_confidence=0.9,
        anomaly_score=0.2,
        is_anomaly=False,
        model_version="1.0",
        feature_importances={"f1": 0.5, "f2": 0.5}
    )
    
    repositories.save_ml_result(db_session, "f4", ml)
    db_session.commit()
    
    retrieved = db_session.query(MLResultModel).filter_by(flow_id="f4").first()
    assert retrieved.class_probabilities["NORMAL"] == 0.9
    assert retrieved.feature_importances["f1"] == 0.5


def test_list_alerts_filtering(db_session):
    flow1 = DirectionalFlowRecord(
        flow_id="f5", timestamp="Z", source_ip="1.1.1.1", source_port=1,
        destination_ip="2.2.2.2", destination_port=2, protocol="TCP",
        duration=1.0, packet_count=10, byte_count=1000,
        packet_sizes=[], packet_timestamps=[], inter_arrival_times=[]
    )
    flow2 = DirectionalFlowRecord(
        flow_id="f6", timestamp="Z", source_ip="1.1.1.1", source_port=1,
        destination_ip="2.2.2.2", destination_port=2, protocol="TCP",
        duration=1.0, packet_count=10, byte_count=1000,
        packet_sizes=[], packet_timestamps=[], inter_arrival_times=[]
    )
    repositories.save_flow(db_session, flow1)
    repositories.save_flow(db_session, flow2)
    
    repositories.save_alert(db_session, "a1", "f5", "DOS_LIKE", 80.0, "CRITICAL", "High risk")
    repositories.save_alert(db_session, "a2", "f6", "SCANNING_LIKE", 60.0, "HIGH", "Med risk")
    db_session.commit()
    
    assert len(repositories.list_alerts(db_session)) == 2
    assert len(repositories.list_alerts(db_session, severity="CRITICAL")) == 1
    assert len(repositories.list_alerts(db_session, threat_type="SCANNING_LIKE")) == 1
    assert repositories.get_alert(db_session, "a1").status == "OPEN"
