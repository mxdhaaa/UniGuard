"""
Tests for unified inference engine.

Tests cover:
- DirectionalFlowRecord -> FeatureEngine -> Preprocessor -> RF -> IsolationForest -> UnifiedMLResult
- UnifiedMLResult contains all required fields
- class_probabilities sum to approximately 1.0
- threat_type is one of the six known classes
- Exactly 16 feature importances matching FEATURE_NAMES
- No IP/profile/timestamp/flow_id leakage into X
- No external API or network calls
- NOT_TRAINED raises RuntimeError (no retry loop)
- Deterministic with same models and same flow
"""

import math
import pytest

from backend.app.schemas.traffic import DirectionalFlowRecord
from backend.app.schemas.ml import ModelReadinessState, UnifiedMLResult
from backend.app.core.preprocessing import FEATURE_NAMES

KNOWN_CLASSES = {
    "NORMAL", "SCANNING_LIKE", "DOS_LIKE",
    "BOTNET_LIKE", "EXFILTRATION_LIKE", "OTHER_SUSPICIOUS"
}


# ---------------------------------------------------------------------------
# Helper: build a minimal synthetic flow
# ---------------------------------------------------------------------------

def _make_flow(
    protocol: str = "TCP",
    packet_count: int = 10,
    byte_count: int = 1500,
    duration: float = 1.0,
) -> DirectionalFlowRecord:
    return DirectionalFlowRecord(
        flow_id="test-inference-001",
        timestamp="2026-01-01T00:00:00Z",
        source_ip="192.168.1.10",
        source_port=54321,
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol=protocol,
        duration=duration,
        packet_count=packet_count,
        byte_count=byte_count,
        packet_sizes=[150] * packet_count,
        packet_timestamps=[float(i) * (duration / packet_count) for i in range(packet_count)],
        inter_arrival_times=[(duration / packet_count)] * (packet_count - 1),
    )


# ---------------------------------------------------------------------------
# Fixture: trained models available via isolated model dir
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def trained_models(tmp_path_factory):
    """
    Train models once for the module and redirect model_manager paths.
    Uses tiny samples_per_class for speed.
    """
    import backend.app.ml.model_manager as mm

    tmp = tmp_path_factory.mktemp("models")
    mm.MODEL_DIR = tmp
    mm.CLASSIFIER_MODEL_FILE = tmp / "classifier.joblib"
    mm.ANOMALY_MODEL_FILE = tmp / "anomaly_detector.joblib"
    mm.METADATA_FILE = tmp / "metadata.json"

    from backend.app.ml.train import train_models
    meta = train_models(seed=42, samples_per_class=60)
    return meta, tmp


# ---------------------------------------------------------------------------
# NOT_TRAINED state tests (isolated from trained_models fixture)
# ---------------------------------------------------------------------------

def test_inference_not_trained_raises(tmp_path, monkeypatch):
    """run_inference() must raise RuntimeError when models not trained — no retry."""
    import backend.app.ml.model_manager as mm
    monkeypatch.setattr(mm, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(mm, "CLASSIFIER_MODEL_FILE", tmp_path / "classifier.joblib")
    monkeypatch.setattr(mm, "ANOMALY_MODEL_FILE", tmp_path / "anomaly_detector.joblib")
    monkeypatch.setattr(mm, "METADATA_FILE", tmp_path / "metadata.json")

    from backend.app.ml.inference import run_inference
    flow = _make_flow()
    with pytest.raises(RuntimeError, match="not ready"):
        run_inference(flow)


# ---------------------------------------------------------------------------
# Inference correctness tests (requires trained models)
# ---------------------------------------------------------------------------

def test_inference_returns_unified_result(trained_models):
    """run_inference() must return a UnifiedMLResult."""
    from backend.app.ml.inference import run_inference
    flow = _make_flow()
    result = run_inference(flow)
    assert isinstance(result, UnifiedMLResult)


def test_inference_threat_type_is_known_class(trained_models):
    """threat_type must be one of the six known classes."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert result.threat_type in KNOWN_CLASSES


def test_inference_probabilities_sum_to_one(trained_models):
    """class_probabilities must sum to approximately 1.0."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    prob_sum = sum(result.class_probabilities.values())
    assert abs(prob_sum - 1.0) < 1e-4, f"Probabilities sum to {prob_sum}, expected ~1.0"


def test_inference_probabilities_six_classes(trained_models):
    """class_probabilities must have exactly 6 entries."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert len(result.class_probabilities) == 6


def test_inference_probabilities_cover_known_classes(trained_models):
    """class_probabilities keys must match the six known classes."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert set(result.class_probabilities.keys()) == KNOWN_CLASSES


def test_inference_confidence_in_unit_interval(trained_models):
    """classifier_confidence must be in [0.0, 1.0]."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert 0.0 <= result.classifier_confidence <= 1.0


def test_inference_anomaly_score_in_unit_interval(trained_models):
    """anomaly_score must be in [0.0, 1.0]."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert 0.0 <= result.anomaly_score <= 1.0


def test_inference_anomaly_score_finite(trained_models):
    """anomaly_score must be a finite float."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert math.isfinite(result.anomaly_score)


def test_inference_is_anomaly_is_bool(trained_models):
    """is_anomaly must be a bool."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert isinstance(result.is_anomaly, bool)


def test_inference_model_version_is_string(trained_models):
    """model_version must be a non-empty string."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert isinstance(result.model_version, str)
    assert len(result.model_version) > 0


def test_inference_feature_importances_has_16_entries(trained_models):
    """feature_importances must contain exactly 16 entries."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert len(result.feature_importances) == 16


def test_inference_feature_importances_keys_are_canonical(trained_models):
    """feature_importances keys must exactly match FEATURE_NAMES."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert set(result.feature_importances.keys()) == set(FEATURE_NAMES)


def test_inference_feature_importances_no_ip_leakage(trained_models):
    """feature_importances must NOT contain IP, flow_id, timestamp, or profile keys."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    forbidden = {"source_ip", "destination_ip", "flow_id", "timestamp", "simulated_profile"}
    for key in forbidden:
        assert key not in result.feature_importances, f"Forbidden key found in importances: {key}"


def test_inference_feature_importances_are_finite(trained_models):
    """All feature importance values must be finite floats."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    for name, val in result.feature_importances.items():
        assert math.isfinite(val), f"Feature importance for '{name}' is not finite: {val}"


def test_inference_deterministic_same_flow(trained_models):
    """Same flow input must produce identical results on consecutive calls."""
    from backend.app.ml.inference import run_inference
    flow = _make_flow()
    r1 = run_inference(flow)
    r2 = run_inference(flow)
    assert r1.threat_type == r2.threat_type
    assert r1.classifier_confidence == r2.classifier_confidence
    assert r1.anomaly_score == r2.anomaly_score


def test_inference_no_external_calls(trained_models, monkeypatch):
    """
    Inference must not make any external network calls.
    We verify this by monkeypatching socket.connect to raise if called.
    """
    import socket as sock_module

    def _no_connect(*args, **kwargs):
        raise AssertionError("Inference made an external network call — forbidden!")

    monkeypatch.setattr(sock_module, "create_connection", _no_connect)

    from backend.app.ml.inference import run_inference
    # This must complete without hitting create_connection
    result = run_inference(_make_flow())
    assert result is not None


def test_inference_different_protocols_produce_valid_results(trained_models):
    """Inference must work for different protocol types."""
    from backend.app.ml.inference import run_inference
    for proto in ["TCP", "UDP", "ICMP", "DNS"]:
        flow = _make_flow(protocol=proto)
        result = run_inference(flow)
        assert result.threat_type in KNOWN_CLASSES
        assert 0.0 <= result.anomaly_score <= 1.0


def test_inference_all_fields_present(trained_models):
    """UnifiedMLResult must contain all seven required fields."""
    from backend.app.ml.inference import run_inference
    result = run_inference(_make_flow())
    assert hasattr(result, "threat_type")
    assert hasattr(result, "class_probabilities")
    assert hasattr(result, "classifier_confidence")
    assert hasattr(result, "anomaly_score")
    assert hasattr(result, "is_anomaly")
    assert hasattr(result, "feature_importances")
    assert hasattr(result, "model_version")
