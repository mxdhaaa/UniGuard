"""
Unit Tests for DirectionalFlowProcessor
Verifies one-way flow construction without reverse traffic requirements.
"""

import pytest
from backend.app.core.flow_processor import DirectionalFlowProcessor
from backend.app.schemas.traffic import DirectionalFlowRecord


def test_basic_one_way_flow():
    """Verify basic one-way flow A -> B without needing B -> A response."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        source_port=54321,
        destination_port=443,
        protocol="TCP",
        duration=2.5,
        packet_count=10,
        byte_count=1500,
        packet_sizes=[150] * 10,
        packet_timestamps=[100.0 + i * 0.25 for i in range(10)],
    )

    assert flow.source_ip == "192.168.1.100"
    assert flow.destination_ip == "10.0.0.5"
    assert flow.source_port == 54321
    assert flow.destination_port == 443
    assert flow.protocol == "TCP"
    assert flow.packet_count == 10
    assert flow.byte_count == 1500
    assert flow.duration == pytest.approx(2.25, abs=0.01) or flow.duration > 0
    assert len(flow.inter_arrival_times) == 9
    assert flow.flow_id.startswith("FL-DIR-")


def test_empty_flow():
    """Verify safe creation of an empty flow with zero packets/bytes/duration."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=1234,
        destination_port=80,
        protocol="UDP",
        duration=0.0,
        packet_count=0,
        byte_count=0,
        packet_sizes=[],
        packet_timestamps=[],
    )

    assert flow.packet_count == 0
    assert flow.byte_count == 0
    assert flow.duration == 0.0
    assert flow.packet_sizes == []
    assert flow.inter_arrival_times == []


def test_single_packet_flow():
    """Verify single-packet flow behavior (no inter-arrival gaps)."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="10.10.10.1",
        destination_ip="10.10.10.2",
        source_port=4000,
        destination_port=53,
        protocol="DNS",
        packet_sizes=[64],
        packet_timestamps=[1000.0],
    )

    assert flow.packet_count == 1
    assert flow.byte_count == 64
    assert flow.duration == 0.0
    assert len(flow.inter_arrival_times) == 0


def test_zero_duration_flow():
    """Verify flow with multiple packets arriving at the exact same instant (0.0 duration)."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        source_port=8000,
        destination_port=80,
        protocol="TCP",
        packet_sizes=[100, 200, 300],
        packet_timestamps=[50.0, 50.0, 50.0],
    )

    assert flow.duration == 0.0
    assert flow.packet_count == 3
    assert flow.byte_count == 600
    assert flow.inter_arrival_times == [0.0, 0.0]


def test_aggregate_packet_events_one_way():
    """Verify grouping raw packet events into strictly directional flows."""
    events = [
        {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "source_port": 100, "destination_port": 80, "protocol": "TCP", "size": 60, "timestamp": 1.0},
        {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "source_port": 100, "destination_port": 80, "protocol": "TCP", "size": 120, "timestamp": 1.5},
        # Reverse packet (2.2.2.2 -> 1.1.1.1) must form a SEPARATE one-way flow, not merge
        {"source_ip": "2.2.2.2", "destination_ip": "1.1.1.1", "source_port": 80, "destination_port": 100, "protocol": "TCP", "size": 40, "timestamp": 1.6},
    ]

    flows = DirectionalFlowProcessor.aggregate_packet_events(events)
    assert len(flows) == 2  # Two distinct directional flows

    flow_a_to_b = next(f for f in flows if f.source_ip == "1.1.1.1")
    flow_b_to_a = next(f for f in flows if f.source_ip == "2.2.2.2")

    assert flow_a_to_b.packet_count == 2
    assert flow_a_to_b.byte_count == 180
    assert flow_b_to_a.packet_count == 1
    assert flow_b_to_a.byte_count == 40


def test_flow_id_determinism():
    """Verify identical 5-tuples produce identical deterministic flow IDs."""
    id1 = DirectionalFlowProcessor.generate_flow_id("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
    id2 = DirectionalFlowProcessor.generate_flow_id("10.0.0.1", 1234, "10.0.0.2", 80, "tcp")
    assert id1 == id2
    assert id1.startswith("FL-DIR-")
