"""
Unit Tests for Deterministic FeatureEngine
Verifies mathematical safety, edge-case resilience, and contract compliance.
"""

import math
import pytest
from backend.app.core.flow_processor import DirectionalFlowProcessor
from backend.app.core.feature_engine import FeatureEngine, EPSILON
from backend.app.schemas.traffic import FeatureVector


def test_basic_feature_extraction():
    """Verify standard directional flow extraction produces all 16 features."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="192.168.1.50",
        destination_ip="142.250.190.46",
        source_port=51200,
        destination_port=443,
        protocol="HTTPS",
        duration=2.0,
        packet_count=5,
        byte_count=1000,
        packet_sizes=[100, 200, 300, 200, 200],
        packet_timestamps=[0.0, 0.5, 1.0, 1.5, 2.0],
    )

    features = FeatureEngine.extract_features(flow)

    assert isinstance(features, FeatureVector)
    assert features.flow_duration == pytest.approx(2.0, rel=1e-3)
    assert features.packet_count == 5
    assert features.byte_count == 1000
    assert features.packets_per_second == pytest.approx(2.5, rel=1e-3)
    assert features.bytes_per_second == pytest.approx(500.0, rel=1e-3)
    assert features.average_packet_size == pytest.approx(200.0, rel=1e-3)
    assert features.packet_size_std > 0.0
    assert features.protocol_indicator == 6.0  # HTTPS


def test_empty_flow_zero_division():
    """Verify zero packets, zero bytes, and zero duration do not cause division by zero or NaN."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=1000,
        destination_port=80,
        protocol="TCP",
        duration=0.0,
        packet_count=0,
        byte_count=0,
        packet_sizes=[],
        packet_timestamps=[],
    )

    features = FeatureEngine.extract_features(flow)

    assert features.flow_duration == 0.0
    assert features.packet_count == 0
    assert features.byte_count == 0
    assert features.packets_per_second == 0.0
    assert features.bytes_per_second == 0.0
    assert features.average_packet_size == 0.0
    assert features.packet_size_std == 0.0
    assert features.packet_size_entropy == 0.0
    assert features.burst_score == 0.0
    assert not math.isnan(features.packets_per_second)
    assert not math.isinf(features.packets_per_second)


def test_single_packet_flow():
    """Verify single-packet flow features (std dev is 0, burst score is 0)."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=1000,
        destination_port=53,
        protocol="DNS",
        duration=0.0,
        packet_count=1,
        byte_count=64,
        packet_sizes=[64],
        packet_timestamps=[10.0],
    )

    features = FeatureEngine.extract_features(flow)

    assert features.packet_count == 1
    assert features.byte_count == 64
    assert features.average_packet_size == 64.0
    assert features.packet_size_std == 0.0
    assert features.packet_size_entropy == 0.0
    assert features.burst_score == 0.0
    assert features.protocol_indicator == 4.0  # DNS


def test_zero_duration_multiple_packets():
    """Verify multiple packets at identical timestamp (zero duration) compute rates without ZeroDivisionError."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="10.0.0.5",
        destination_ip="10.0.0.6",
        source_port=2000,
        destination_port=80,
        protocol="TCP",
        duration=0.0,
        packet_sizes=[100, 100, 100],
        packet_timestamps=[5.0, 5.0, 5.0],
    )

    features = FeatureEngine.extract_features(flow)

    assert features.flow_duration == 0.0
    assert features.packet_count == 3
    # Packets per second uses EPSILON to prevent crash
    assert features.packets_per_second == pytest.approx(3.0 / EPSILON, rel=1e-3)
    assert features.burst_score == 1.0  # Simultaneous arrival indicates maximal burst
    assert features.packet_size_entropy == 0.0  # All sizes identical (100)


def test_shannon_entropy_calculation():
    """Verify Shannon entropy mathematical properties."""
    # Empty or single element -> 0.0
    assert FeatureEngine.calculate_shannon_entropy([]) == 0.0
    assert FeatureEngine.calculate_shannon_entropy([443]) == 0.0
    assert FeatureEngine.calculate_shannon_entropy([443, 443, 443]) == 0.0

    # Two equally likely outcomes -> 1.0 bit
    entropy_binary = FeatureEngine.calculate_shannon_entropy([80, 443])
    assert entropy_binary == pytest.approx(1.0, abs=1e-4)

    # Four equally likely outcomes -> 2.0 bits
    entropy_quad = FeatureEngine.calculate_shannon_entropy([21, 22, 80, 443])
    assert entropy_quad == pytest.approx(2.0, abs=1e-4)


def test_burst_score_periodic_vs_bursty():
    """Verify burst score increases from 0 (periodic) towards 1 (bursty)."""
    # Perfectly periodic arrivals (interval 1.0s) -> CV = 0 -> burst_score = 0.0
    periodic_iats = [1.0, 1.0, 1.0, 1.0, 1.0]
    score_periodic = FeatureEngine.calculate_burst_score(periodic_iats)
    assert score_periodic == 0.0

    # Variable arrivals -> score > 0
    jittery_iats = [0.1, 2.0, 0.05, 4.0, 0.2]
    score_jittery = FeatureEngine.calculate_burst_score(jittery_iats)
    assert 0.0 < score_jittery < 1.0
    assert score_jittery > score_periodic


def test_context_flow_aggregation():
    """Verify destination diversity, port diversity, and port entropy with context flows."""
    src = "10.24.1.10"
    flow1 = DirectionalFlowProcessor.create_flow(src, "10.0.0.1", 1000, 80, "TCP", duration=1.0)
    flow2 = DirectionalFlowProcessor.create_flow(src, "10.0.0.2", 1001, 443, "TCP", duration=1.0)
    flow3 = DirectionalFlowProcessor.create_flow(src, "10.0.0.3", 1002, 8080, "TCP", duration=1.0)
    flow4 = DirectionalFlowProcessor.create_flow(src, "10.0.0.1", 1003, 80, "TCP", duration=1.0)

    context = [flow1, flow2, flow3, flow4]
    features = FeatureEngine.extract_features(flow1, context_flows=context)

    assert features.unique_destination_count == 3  # 10.0.0.1, 10.0.0.2, 10.0.0.3
    assert features.unique_destination_port_count == 3  # 80, 443, 8080
    assert features.destination_diversity == pytest.approx(3 / 4, abs=1e-4)
    assert features.port_diversity == pytest.approx(3 / 4, abs=1e-4)
    assert features.destination_port_entropy > 0.0


def test_deterministic_repeated_execution():
    """Verify identical inputs always yield bit-for-bit identical feature vectors."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="172.16.0.5",
        destination_ip="8.8.8.8",
        source_port=49152,
        destination_port=53,
        protocol="DNS",
        duration=1.234,
        packet_count=4,
        byte_count=320,
        packet_sizes=[80, 80, 80, 80],
        packet_timestamps=[100.0, 100.4, 100.8, 101.2],
    )

    feat1 = FeatureEngine.extract_features(flow)
    feat2 = FeatureEngine.extract_features(flow)

    assert feat1.model_dump() == feat2.model_dump()
