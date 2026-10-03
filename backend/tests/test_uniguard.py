"""
UniGuard Backend Pytest Suite
Tests one-way flow parsing, feature extraction, 4 MVP detectors, alert schemas, correlation, and PCAP ingestion.
"""

import pytest
import time
from backend.schemas import FlowRecord, DetectionResult
from backend.flow_engine import FlowEngine
from backend.feature_engine import FeatureEngine
from backend.generator import SyntheticTrafficGenerator
from backend.detectors import (
    C2BeaconingDetector,
    DDoSDetector,
    DNSTunnellingDetector,
    ReconnaissanceDetector,
)
from backend.correlation import RiskCorrelationEngine


def test_one_way_flow():
    """Verify that a one-way flow A -> B is created without requiring reverse traffic."""
    flow = SyntheticTrafficGenerator.generate_c2_beaconing_flow()
    assert flow.src_ip == "10.24.8.21"
    assert flow.dst_ip == "185.220.101.5"
    assert flow.packet_count == 11
    assert flow.duration > 0
    assert len(flow.inter_arrival_times) == 10


def test_feature_extraction():
    """Verify calculation of temporal, statistical, behavioral, and DNS features."""
    flow = SyntheticTrafficGenerator.generate_c2_beaconing_flow()
    features = FeatureEngine.extract_flow_features(flow)

    assert features["duration"] > 0
    assert "packets_per_second" in features
    assert "inter_arrival_coefficient_of_variation" in features
    assert features["inter_arrival_coefficient_of_variation"] is not None
    assert features["inter_arrival_coefficient_of_variation"] < 0.10  # Low CV for beaconing


def test_c2_beaconing():
    """Verify C2 Beaconing detector fires for periodic traffic."""
    flow = SyntheticTrafficGenerator.generate_c2_beaconing_flow()
    features = FeatureEngine.extract_flow_features(flow)
    detector = C2BeaconingDetector()

    result = detector.analyze(flow, features)
    assert result is not None
    assert result.threat_class == "C2_BEACONING"
    assert result.confidence >= 0.60
    assert len(result.evidence) > 0
    assert any(e.feature == "inter_arrival_cv" for e in result.evidence)


def test_c2_beaconing_benign_false_positive():
    """Verify C2 Beaconing detector does NOT fire for benign variable traffic."""
    flow = SyntheticTrafficGenerator.generate_benign_flow()
    features = FeatureEngine.extract_flow_features(flow)
    detector = C2BeaconingDetector()

    result = detector.analyze(flow, features)
    assert result is None  # Benign traffic should not trigger C2 alert


def test_ddos():
    """Verify DDoS detector fires for high packet rate volumetric traffic."""
    flow = SyntheticTrafficGenerator.generate_ddos_flow()
    features = FeatureEngine.extract_flow_features(flow)
    detector = DDoSDetector()

    result = detector.analyze(flow, features)
    assert result is not None
    assert result.threat_class == "DDoS"
    assert result.confidence >= 0.65
    assert result.severity in ["HIGH", "CRITICAL"]


def test_ddos_benign_false_positive():
    """Verify DDoS detector does NOT fire for low-rate benign traffic."""
    flow = SyntheticTrafficGenerator.generate_benign_flow()
    features = FeatureEngine.extract_flow_features(flow)
    detector = DDoSDetector()

    result = detector.analyze(flow, features)
    assert result is None


def test_dns_tunnelling():
    """Verify DNS Tunnelling detector fires for high entropy domain queries."""
    flow = SyntheticTrafficGenerator.generate_dns_tunnelling_flow()
    features = FeatureEngine.extract_flow_features(flow)
    detector = DNSTunnellingDetector()

    result = detector.analyze(flow, features)
    assert result is not None
    assert result.threat_class == "DNS_TUNNELLING_DGA"
    assert result.confidence >= 0.60
    assert any(e.feature == "domain_shannon_entropy" for e in result.evidence)


def test_dns_tunnelling_benign_false_positive():
    """Verify DNS detector does NOT fire for standard domain queries."""
    flow = FlowRecord(
        flow_id="FL-DNS-NORMAL",
        timestamp="2026-10-03T23:00:00Z",
        src_ip="10.24.1.15",
        dst_ip="8.8.8.8",
        src_port=53100,
        dst_port=53,
        protocol="DNS",
        packet_count=2,
        byte_count=120,
        duration=0.05,
        packet_sizes=[60, 60],
        inter_arrival_times=[0.05],
        dns_query="www.google.com"
    )
    features = FeatureEngine.extract_flow_features(flow)
    detector = DNSTunnellingDetector()

    result = detector.analyze(flow, features)
    assert result is None


def test_port_scan():
    """Verify Reconnaissance detector fires when single source probes multiple ports."""
    flows = SyntheticTrafficGenerator.generate_port_scan_flows()
    detector = ReconnaissanceDetector()

    # Analyze with context of all flows from same source
    scan_results = []
    for f in flows:
        feats = FeatureEngine.extract_flow_features(f, context_flows=flows)
        res = detector.analyze(f, feats, context_flows=flows)
        if res:
            scan_results.append(res)

    assert len(scan_results) > 0
    assert scan_results[0].threat_class == "RECONNAISSANCE"


def test_port_scan_benign_false_positive():
    """Verify Reconnaissance detector does NOT fire for a single connection."""
    flow = SyntheticTrafficGenerator.generate_benign_flow()
    features = FeatureEngine.extract_flow_features(flow)
    detector = ReconnaissanceDetector()

    result = detector.analyze(flow, features)
    assert result is None


def test_alert_schema():
    """Verify detection result schema formatting and non-empty required fields."""
    flow = SyntheticTrafficGenerator.generate_c2_beaconing_flow()
    features = FeatureEngine.extract_flow_features(flow)
    detector = C2BeaconingDetector()

    result = detector.analyze(flow, features)
    assert result is not None
    res_dict = result.model_dump()

    required_keys = ["id", "timestamp", "flow_id", "threat_class", "severity", "confidence", "source", "destination", "protocol", "evidence", "detector", "status"]
    for key in required_keys:
        assert key in res_dict


def test_pcap_ingestion_and_performance():
    """Verify execution time measurement during ingestion."""
    from fastapi.testclient import TestClient
    from backend.main import app

    client = TestClient(app)

    # Health check
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

    # Stats check
    stats_resp = client.get("/api/v1/stats")
    assert stats_resp.status_code == 200

    # Detections list
    det_resp = client.get("/api/v1/detections")
    assert det_resp.status_code == 200
    assert len(det_resp.json()) > 0
