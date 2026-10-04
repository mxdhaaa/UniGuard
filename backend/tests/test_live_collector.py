"""
Tests for Live Flow Ingestion (Milestone 10)
Uses synthetic Scapy packets rather than live interfaces to ensure deterministic tests.
"""

import time
import pytest
import scapy.all as scapy

from backend.app.collectors.live_collector import LiveTrafficCollector, ActiveFlowState
from backend.app.schemas.traffic import DirectionalFlowRecord
from backend.app.services.ingestion_service import ingestion_service


class MockTime:
    def __init__(self, start=1000.0):
        self.current = start
    def __call__(self):
        return self.current
    def advance(self, amount):
        self.current += amount


def test_directional_flow_aggregation():
    """Verify 5-tuple separation of forward/reverse traffic."""
    collector = LiveTrafficCollector(interface="", bpf_filter="")
    
    # Forward packet
    pkt1 = scapy.IP(src="1.1.1.1", dst="2.2.2.2") / scapy.TCP(sport=1000, dport=80)
    pkt1.time = 1000.0
    collector._process_packet(pkt1)
    
    # Reverse packet
    pkt2 = scapy.IP(src="2.2.2.2", dst="1.1.1.1") / scapy.TCP(sport=80, dport=1000)
    pkt2.time = 1001.0
    collector._process_packet(pkt2)
    
    # Same forward packet again
    pkt3 = scapy.IP(src="1.1.1.1", dst="2.2.2.2") / scapy.TCP(sport=1000, dport=80)
    pkt3.time = 1002.0
    collector._process_packet(pkt3)
    
    assert len(collector.active_flows) == 2
    fwd_key = "TCP:1.1.1.1:1000->2.2.2.2:80"
    rev_key = "TCP:2.2.2.2:80->1.1.1.1:1000"
    
    assert collector.active_flows[fwd_key].packet_count == 2
    assert collector.active_flows[rev_key].packet_count == 1
    assert collector.packets_captured == 3


def test_unsupported_protocol_handled_safely():
    """Verify non-IP or unhandled transport doesn't crash."""
    collector = LiveTrafficCollector(interface="", bpf_filter="")
    
    # Non-IP
    pkt1 = scapy.ARP()
    collector._process_packet(pkt1)
    
    # Unsupported IP protocol
    pkt2 = scapy.IP(src="1.1.1.1", dst="2.2.2.2") / scapy.IGMP()
    collector._process_packet(pkt2)
    
    assert len(collector.active_flows) == 0


def test_idle_timeout_expiration():
    """Verify flow expires when idle timeout is exceeded."""
    mock_time = MockTime()
    expired_flows = []
    
    collector = LiveTrafficCollector(
        interface="", bpf_filter="", 
        idle_timeout=30.0, max_duration=120.0,
        on_flow_expired=lambda f: expired_flows.append(f),
        _time_func=mock_time
    )
    
    pkt = scapy.IP(src="1.1.1.1", dst="2.2.2.2") / scapy.TCP(sport=1000, dport=80)
    pkt.time = mock_time.current
    collector._process_packet(pkt)
    
    # Advance time by 20s (under timeout)
    mock_time.advance(20.0)
    collector._check_expirations()
    assert len(expired_flows) == 0
    assert len(collector.active_flows) == 1
    
    # Advance time by 11s (over 30s timeout)
    mock_time.advance(11.0)
    collector._check_expirations()
    
    assert len(expired_flows) == 1
    assert len(collector.active_flows) == 0
    assert expired_flows[0].packet_count == 1
    assert expired_flows[0].source_ip == "1.1.1.1"


def test_max_duration_expiration():
    """Verify flow expires if max duration is hit, even if not idle."""
    mock_time = MockTime()
    expired_flows = []
    
    collector = LiveTrafficCollector(
        interface="", bpf_filter="", 
        idle_timeout=30.0, max_duration=120.0,
        on_flow_expired=lambda f: expired_flows.append(f),
        _time_func=mock_time
    )
    
    # Packet 1
    pkt = scapy.IP(src="1.1.1.1", dst="2.2.2.2") / scapy.TCP(sport=1000, dport=80)
    pkt.time = mock_time.current
    collector._process_packet(pkt)
    
    # Packet 2 at 110s (resets idle timer)
    mock_time.advance(110.0)
    pkt.time = mock_time.current
    collector._process_packet(pkt)
    
    collector._check_expirations()
    assert len(expired_flows) == 0
    
    # Packet 3 at 121s (hits max duration)
    mock_time.advance(11.0)
    pkt.time = mock_time.current
    collector._process_packet(pkt)
    
    collector._check_expirations()
    assert len(expired_flows) == 1
    assert expired_flows[0].packet_count == 3


def test_explicit_flush():
    """Verify flush explicitly pushes out active flows."""
    expired_flows = []
    collector = LiveTrafficCollector(
        interface="", bpf_filter="", 
        on_flow_expired=lambda f: expired_flows.append(f)
    )
    
    pkt = scapy.IP(src="1.1.1.1", dst="2.2.2.2") / scapy.TCP(sport=1000, dport=80)
    pkt.time = 1000.0
    collector._process_packet(pkt)
    
    assert len(collector.active_flows) == 1
    collector.flush()
    assert len(collector.active_flows) == 0
    assert len(expired_flows) == 1


def test_api_status_and_control(monkeypatch):
    """Test the ingestion service lifecycle controls."""
    # Mock sniff to do nothing instead of blowing up on winpcap
    monkeypatch.setattr(scapy, "sniff", lambda **kwargs: time.sleep(0.5))
    
    # Ensure starting clean
    ingestion_service.stop()
    
    status = ingestion_service.get_status()
    assert status.state == "STOPPED"
    
    # Test start
    status = ingestion_service.start()
    assert status.state == "RUNNING"
    
    # Test stop
    status = ingestion_service.stop()
    assert status.state == "STOPPED"


def test_malformed_packet_handling(monkeypatch):
    """Ensure malformed packets don't throw uncaught exceptions."""
    collector = LiveTrafficCollector(interface="", bpf_filter="")
    
    # We will simulate a scapy error by forcing an exception in the processor
    original = collector._process_packet
    def buggy_processor(pkt):
        raise ValueError("Simulated malformed packet parsing error")
        
    monkeypatch.setattr(collector, "_process_packet", buggy_processor)
    
    # This should not raise directly out to the sniffer loop theoretically,
    # but the internal _process_packet is wrapped in a try/except in our implementation!
    # Wait, in the actual implementation, the try/except is inside _process_packet itself.
    # To test the try/except inside _process_packet, we just pass something really broken
    # or mock pkt.haslayer to throw.
    
    class BrokenPacket:
        def haslayer(self, layer):
            raise ValueError("Corrupt")
            
    # Should catch the error and increment error count
    original(BrokenPacket())
    assert collector.errors == 1


def test_pipeline_integration(monkeypatch):
    """Ensure the callback pushes through the pipeline successfully."""
    from backend.app.services.persistence_service import persistence_service
    from backend.app.schemas.traffic import FeatureVector
    
    # We will mock the persistence_service to just record success, preventing real DB writes
    persisted = []
    def mock_save(*args, **kwargs):
        persisted.append(True)
        return {"status": "success", "flow_id": "test"}
        
    monkeypatch.setattr(persistence_service, "save_analysis_result", mock_save)
    
    flow = DirectionalFlowRecord(
        flow_id="test", timestamp="Z", source_ip="1.1.1.1", source_port=1,
        destination_ip="2.2.2.2", destination_port=2, protocol="TCP",
        duration=1.0, packet_count=10, byte_count=1000,
        packet_sizes=[100]*10, packet_timestamps=[0.1*i for i in range(10)],
        inter_arrival_times=[0.1]*9
    )
    
    ingestion_service._process_expired_flow(flow)
    assert len(persisted) == 1
