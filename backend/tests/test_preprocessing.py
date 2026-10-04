"""
Unit Tests for FeaturePreprocessor
Verifies stable feature ordering, finite numerics, and extreme value clipping.
"""

import math
import pytest
from backend.app.core.flow_processor import DirectionalFlowProcessor
from backend.app.core.feature_engine import FeatureEngine
from backend.app.core.preprocessing import FeaturePreprocessor, FEATURE_NAMES, FEATURE_MAX_BOUNDS
from backend.app.schemas.traffic import FeatureVector


def test_preprocessing_canonical_order():
    """Verify preprocessed vector matches FEATURE_NAMES order exactly."""
    flow = DirectionalFlowProcessor.create_flow(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=1234,
        destination_port=80,
        protocol="TCP",
        duration=1.0,
        packet_count=10,
        byte_count=1000,
        packet_sizes=[100] * 10,
        packet_timestamps=[float(i) for i in range(10)],
    )

    raw_features = FeatureEngine.extract_features(flow)
    preprocessed = FeaturePreprocessor.preprocess(raw_features)

    assert preprocessed.is_valid is True
    assert len(preprocessed.feature_names) == 16
    assert preprocessed.feature_names == FEATURE_NAMES
    assert len(preprocessed.values) == 16

    # Verify each value is finite
    for val in preprocessed.values:
        assert math.isfinite(val)
        assert not math.isnan(val)
        assert not math.isinf(val)


def test_preprocessing_extreme_values_clamping():
    """Verify extreme/astronomical values are clamped safely to maximum bounds."""
    extreme_vector = FeatureVector(
        flow_duration=1_000_000.0,       # Exceeds 86400 max
        packet_count=500_000_000,        # Exceeds 100M max
        byte_count=999_999_999_999,
        packets_per_second=50_000_000.0,
        bytes_per_second=90_000_000_000.0,
        average_packet_size=100_000.0,
        packet_size_std=100_000.0,
        unique_destination_count=5_000_000,
        unique_destination_port_count=100_000,
        destination_port_entropy=30.0,
        packet_size_entropy=30.0,
        burst_score=5.0,
        source_activity_rate=5_000_000.0,
        destination_diversity=2.5,
        port_diversity=3.0,
        protocol_indicator=50.0,
    )

    preprocessed = FeaturePreprocessor.preprocess(extreme_vector)
    val_map = dict(zip(preprocessed.feature_names, preprocessed.values))

    assert val_map["flow_duration"] <= FEATURE_MAX_BOUNDS["flow_duration"]
    assert val_map["packet_count"] <= FEATURE_MAX_BOUNDS["packet_count"]
    assert val_map["burst_score"] <= 1.0
    assert val_map["destination_diversity"] <= 1.0
    assert val_map["port_diversity"] <= 1.0


def test_sanitize_float_nan_inf():
    """Verify sanitize_float handles NaN, positive infinity, and negative infinity gracefully."""
    assert FeaturePreprocessor.sanitize_float(float("nan"), default=0.0) == 0.0
    assert FeaturePreprocessor.sanitize_float(float("inf"), default=0.0) == 0.0
    assert FeaturePreprocessor.sanitize_float(float("-inf"), default=0.0) == 0.0
    assert FeaturePreprocessor.sanitize_float(-50.0, default=0.0) == 0.0  # Guard negative
    assert FeaturePreprocessor.sanitize_float(42.5, max_bound=100.0) == 42.5
    assert FeaturePreprocessor.sanitize_float(200.0, max_bound=100.0) == 100.0


def test_to_flat_list():
    """Verify to_flat_list returns a 16-element float array."""
    flow = DirectionalFlowProcessor.create_flow("1.1.1.1", "2.2.2.2", 80, 80, "TCP")
    feats = FeatureEngine.extract_features(flow)
    flat = FeaturePreprocessor.to_flat_list(feats)

    assert isinstance(flat, list)
    assert len(flat) == 16
    assert all(isinstance(x, (float, int)) for x in flat)
