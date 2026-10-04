"""
Tests for PCAP File Ingestion (Milestone 11)
"""

import os
import tempfile
import time
import pytest
import scapy.all as scapy
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.collectors.pcap_collector import PcapCollector
from backend.app.schemas.traffic import DirectionalFlowRecord

client = TestClient(app)

@pytest.fixture
def sample_pcap_path():
    """Generates a small deterministic PCAP file for testing."""
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    
    # Generate 3 packets spanning 35 seconds to trigger a 30s idle timeout
    pkt1 = scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(sport=1000, dport=80)
    pkt1.time = 1000.0
    
    pkt2 = scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(sport=1000, dport=80)
    pkt2.time = 1005.0
    
    pkt3 = scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(sport=1000, dport=80)
    pkt3.time = 1040.0 # 35s later
    
    scapy.wrpcap(path, [pkt1, pkt2, pkt3])
    
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_pcap_collector_timestamp_expiration(sample_pcap_path):
    """Test that pkt.time properly drives idle expiration without wall-clock waiting."""
    expired_flows = []
    
    collector = PcapCollector(
        pcap_path=sample_pcap_path,
        idle_timeout=30.0,
        max_duration=120.0,
        on_flow_expired=lambda f: expired_flows.append(f)
    )
    
    total_pkts, flows_completed, errors = collector.process()
    
    assert total_pkts == 3
    assert errors == 0
    # The first 2 packets form flow 1. Packet 3 arrives at +35s, triggering idle expiration 
    # for the first flow. Then at EOF, the second flow (containing pkt3) is flushed.
    assert len(expired_flows) == 2
    
    flow1, flow2 = expired_flows
    assert flow1.packet_count == 2
    assert flow1.duration == 5.0
    
    assert flow2.packet_count == 1
    assert flow2.duration == 0.0


def test_api_upload_and_status(sample_pcap_path):
    """Test the POST /api/pcap/upload and GET status lifecycle."""
    with open(sample_pcap_path, "rb") as f:
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("test.pcap", f, "application/vnd.tcpdump.pcap")}
        )
        
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "PROCESSING"
    
    job_id = data["job_id"]
    
    # Wait briefly for background thread to finish the tiny PCAP
    for _ in range(20):
        status_resp = client.get(f"/api/pcap/status/{job_id}")
        status_data = status_resp.json()
        if status_data["status"] == "COMPLETED":
            break
        time.sleep(0.1)
        
    assert status_data["status"] == "COMPLETED"
    assert status_data["total_packets"] == 3
    assert status_data["flows_completed"] == 2
    assert status_data["errors"] == 0


def test_api_invalid_extension():
    """Ensure non-pcap files are rejected immediately."""
    response = client.post(
        "/api/pcap/upload",
        files={"file": ("test.txt", b"dummy content", "text/plain")}
    )
    assert response.status_code == 400
    assert "Only .pcap and .pcapng files are supported" in response.text


def test_api_missing_job():
    """Ensure missing job IDs return 404."""
    response = client.get("/api/pcap/status/job-does-not-exist")
    assert response.status_code == 404
