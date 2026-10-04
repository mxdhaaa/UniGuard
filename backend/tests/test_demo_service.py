"""
Unit Tests for DemoService Pipeline & Lifecycle Controls
"""

import math
import pytest
from backend.app.services.demo_service import DemoService
from backend.app.schemas.demo import DemoState, DemoResultItem


def test_service_lifecycle_states():
    """Verify state transitions: START -> PAUSE -> STOP -> CLEAR."""
    svc = DemoService(default_seed=42)
    assert svc.state == DemoState.STOPPED

    # Start
    status = svc.start()
    assert status.state == DemoState.RUNNING

    # Pause
    status = svc.pause()
    assert status.state == DemoState.PAUSED

    # Stop
    status = svc.stop()
    assert status.state == DemoState.STOPPED

    # Clear
    svc.generated_flows_count = 50
    status = svc.clear()
    assert status.state == DemoState.STOPPED
    assert status.generated_flows == 0


def test_complete_demo_pipeline_batch():
    """Verify that batch generation processes flows through the complete feature & preprocessing pipeline."""
    svc = DemoService(default_seed=777)
    results = svc.generate_batch(count=15)

    assert len(results) == 15
    for item in results:
        assert isinstance(item, DemoResultItem)
        assert item.flow.flow_id.startswith("FL-DIR-")
        assert item.simulated_profile in [
            "NORMAL", "SCANNING_LIKE", "DOS_LIKE", "BOTNET_LIKE", "EXFILTRATION_LIKE", "OTHER_SUSPICIOUS"
        ]

        # Verify FeatureVector properties
        assert len(item.preprocessed.values) == 16
        assert item.preprocessed.is_valid is True

        # Verify no NaN or Inf
        for val in item.preprocessed.values:
            assert math.isfinite(val)
            assert not math.isnan(val)
            assert not math.isinf(val)


def test_contextual_diversity_exercised():
    """Verify context-aware features (destination diversity, port diversity, port entropy) vary across batch."""
    svc = DemoService(default_seed=50)
    # Generate batch with 100% SCANNING_LIKE flows
    scanning_mix = {"SCANNING_LIKE": 1.0}
    results = svc.generate_batch(count=10, profile_mix=scanning_mix)

    # Since all 10 flows originate from scanner IP 10.24.8.44 targeting multiple ports,
    # the contextual features should reflect high port diversity and non-zero entropy
    scanner_item = results[0]
    assert scanner_item.features.unique_destination_port_count > 1
    assert scanner_item.features.port_diversity > 0.0
    assert scanner_item.features.destination_port_entropy > 0.0
