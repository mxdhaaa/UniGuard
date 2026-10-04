"""
Unit Tests for DemoTrafficCollector
Verifies synthetic flow generation across all 6 behavioral profiles, reproducibility, and diversity.
"""

import pytest
from backend.app.collectors.demo_collector import DemoTrafficCollector, VALID_PROFILES
from backend.app.schemas.traffic import DirectionalFlowRecord


def test_valid_profiles_list():
    """Verify all 6 behavioral profiles are defined."""
    expected = {"NORMAL", "SCANNING_LIKE", "DOS_LIKE", "BOTNET_LIKE", "EXFILTRATION_LIKE", "OTHER_SUSPICIOUS"}
    assert set(VALID_PROFILES) == expected


def test_normal_profile_generation():
    """Verify NORMAL profile generates expected moderate rates and standard protocols."""
    collector = DemoTrafficCollector(seed=123)
    flow = collector.generate_normal_flow()

    assert isinstance(flow, DirectionalFlowRecord)
    assert flow.packet_count >= 8
    assert flow.byte_count > 0
    assert flow.duration > 0.0
    assert flow.protocol in ["TCP", "UDP"]
    assert flow.metadata["simulated_profile"] == "NORMAL"


def test_scanning_like_profile_generation():
    """Verify SCANNING_LIKE generates short, 1-2 packet probes on scan ports."""
    collector = DemoTrafficCollector(seed=123)
    flow = collector.generate_scanning_like_flow()

    assert isinstance(flow, DirectionalFlowRecord)
    assert flow.packet_count in [1, 2]
    assert flow.duration <= 0.05
    assert flow.source_ip == "10.24.8.44"
    assert flow.metadata["simulated_profile"] == "SCANNING_LIKE"


def test_dos_like_profile_generation():
    """Verify DOS_LIKE generates high packet count, volumetric byte stream."""
    collector = DemoTrafficCollector(seed=123)
    flow = collector.generate_dos_like_flow()

    assert isinstance(flow, DirectionalFlowRecord)
    assert flow.packet_count >= 300
    assert flow.byte_count >= 100_000
    assert flow.duration > 0.0
    assert flow.metadata["simulated_profile"] == "DOS_LIKE"


def test_botnet_like_profile_generation():
    """Verify BOTNET_LIKE generates periodic pulses with very low inter-arrival jitter."""
    collector = DemoTrafficCollector(seed=123)
    flow = collector.generate_botnet_like_flow()

    assert isinstance(flow, DirectionalFlowRecord)
    assert flow.packet_count >= 8
    assert flow.source_ip == "10.24.8.21"
    assert flow.destination_ip == "203.0.113.88"
    assert flow.destination_port == 443
    # Check that payload sizes are identical
    assert len(set(flow.packet_sizes)) == 1
    assert flow.metadata["simulated_profile"] == "BOTNET_LIKE"


def test_exfiltration_like_profile_generation():
    """Verify EXFILTRATION_LIKE generates large volume with high average packet size."""
    collector = DemoTrafficCollector(seed=123)
    flow = collector.generate_exfiltration_like_flow()

    assert isinstance(flow, DirectionalFlowRecord)
    assert flow.packet_count >= 80
    assert flow.byte_count >= 100_000
    # Average packet size should be close to MTU (~1400)
    avg_size = flow.byte_count / flow.packet_count
    assert avg_size > 1300.0
    assert flow.metadata["simulated_profile"] == "EXFILTRATION_LIKE"


def test_other_suspicious_profile_generation():
    """Verify OTHER_SUSPICIOUS generates irregular packet sizes and durations."""
    collector = DemoTrafficCollector(seed=123)
    flow = collector.generate_other_suspicious_flow()

    assert isinstance(flow, DirectionalFlowRecord)
    assert flow.packet_count >= 10
    assert flow.metadata["simulated_profile"] == "OTHER_SUSPICIOUS"


def test_seed_reproducibility():
    """Verify same seed produces identical flow metadata."""
    c1 = DemoTrafficCollector(seed=999)
    c2 = DemoTrafficCollector(seed=999)

    b1 = [f.model_dump() for f in c1.generate_batch(count=5)]
    b2 = [f.model_dump() for f in c2.generate_batch(count=5)]

    assert b1 == b2


def test_different_seeds_produce_different_output():
    """Verify different seeds produce distinct flows."""
    c1 = DemoTrafficCollector(seed=111)
    c2 = DemoTrafficCollector(seed=222)

    f1 = c1.generate_normal_flow().model_dump()
    f2 = c2.generate_normal_flow().model_dump()

    assert f1 != f2


def test_invalid_profile_rejected():
    """Verify unknown profile names raise ValueError."""
    collector = DemoTrafficCollector(seed=1)
    with pytest.raises(ValueError, match="Unknown behavioral profile"):
        collector.generate_flow_by_profile("MALWARE_EXPLOIT_ATTACK")


def test_invalid_count_rejected():
    """Verify non-positive batch count raises ValueError."""
    collector = DemoTrafficCollector(seed=1)
    with pytest.raises(ValueError, match="Count must be a positive integer"):
        collector.generate_batch(count=0)


def test_profile_mix_validation():
    """Verify invalid profile keys and invalid weight sums are rejected."""
    collector = DemoTrafficCollector(seed=1)

    # Invalid profile key
    with pytest.raises(ValueError, match="Invalid profile key"):
        collector.generate_batch(count=5, profile_mix={"INVALID_PROFILE": 1.0})

    # Weight sum != 1.0
    with pytest.raises(ValueError, match="weights must sum to approximately 1.0"):
        collector.generate_batch(count=5, profile_mix={"NORMAL": 0.20})
