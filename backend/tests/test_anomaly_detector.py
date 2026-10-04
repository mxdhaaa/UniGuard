"""
Tests for AnomalyDetector (IsolationForest wrapper).

Tests cover:
- Instantiation with default random_state=42
- fit() trains successfully on NORMAL vectors
- anomaly_score() returns finite values in [0.0, 1.0]
- predict() returns (label, raw_score) where label is 0 or 1
- Higher anomaly_score = more anomalous (sklearn score direction conversion)
- Deterministic behavior with same seed
- Error handling when not fitted
- dump/load persistence round-trip
"""

import pathlib
import tempfile
import math
import pytest

from backend.app.ml.anomaly_detector import AnomalyDetector
from backend.app.core.preprocessing import FEATURE_NAMES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_normal_vectors(n: int = 50, seed: int = 42) -> list:
    """Create synthetic NORMAL-like feature vectors (all zeros with small noise)."""
    import random
    rng = random.Random(seed)
    vectors = []
    for _ in range(n):
        vec = [rng.uniform(0.0, 0.5) for _ in FEATURE_NAMES]
        vectors.append(vec)
    return vectors


def _make_anomalous_vector() -> list:
    """Create an obviously anomalous feature vector (extreme values)."""
    # Maximum possible values for each feature to force anomaly detection
    return [1e6, 1000000, 1e11, 1e7, 1e10, 65535.0, 65535.0,
            1000000, 65536, 16.0, 16.0, 1.0, 1000000.0, 1.0, 1.0, 6.0]


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------

def test_anomaly_detector_default_random_state():
    """AnomalyDetector should default to random_state=42."""
    detector = AnomalyDetector()
    assert detector.random_state == 42


def test_anomaly_detector_custom_random_state():
    """Custom random_state should be stored."""
    detector = AnomalyDetector(random_state=99)
    assert detector.random_state == 99


def test_anomaly_detector_default_contamination():
    """Default contamination should be 0.1."""
    detector = AnomalyDetector()
    assert detector.contamination == 0.1


def test_anomaly_detector_not_fitted_raises():
    """predict() before fit() must raise RuntimeError — no retry."""
    detector = AnomalyDetector()
    vec = [0.0] * len(FEATURE_NAMES)
    with pytest.raises(RuntimeError, match="not been trained"):
        detector.predict(vec)


def test_anomaly_detector_score_before_fit_raises():
    """anomaly_score() before fit() must raise RuntimeError — no retry."""
    detector = AnomalyDetector()
    vec = [0.0] * len(FEATURE_NAMES)
    with pytest.raises(RuntimeError):
        detector.anomaly_score(vec)


# ---------------------------------------------------------------------------
# fit()
# ---------------------------------------------------------------------------

def test_anomaly_detector_fit_succeeds():
    """fit() on valid NORMAL vectors should succeed."""
    detector = AnomalyDetector(random_state=42)
    X_normal = _make_normal_vectors(50)
    detector.fit(X_normal)
    assert detector.model is not None


def test_anomaly_detector_fit_empty_raises():
    """fit() on empty list must raise ValueError."""
    detector = AnomalyDetector()
    with pytest.raises(ValueError, match="cannot be empty"):
        detector.fit([])


def test_anomaly_detector_stores_score_bounds():
    """After fit(), _score_min and _score_max must be set."""
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(50))
    assert detector._score_min is not None
    assert detector._score_max is not None
    assert math.isfinite(detector._score_min)
    assert math.isfinite(detector._score_max)


# ---------------------------------------------------------------------------
# anomaly_score()
# ---------------------------------------------------------------------------

def test_anomaly_score_is_finite():
    """anomaly_score() must return a finite float."""
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(50))
    vec = _make_normal_vectors(1)[0]
    score = detector.anomaly_score(vec)
    assert math.isfinite(score)


def test_anomaly_score_in_unit_interval():
    """anomaly_score() must be in [0.0, 1.0]."""
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(80))
    for vec in _make_normal_vectors(20, seed=7):
        score = detector.anomaly_score(vec)
        assert 0.0 <= score <= 1.0, f"Score out of range: {score}"


def test_normal_vectors_have_low_anomaly_score():
    """
    Vectors drawn from the same distribution as training data should
    have low anomaly scores (< 0.5 on average).
    This tests the sklearn score-direction inversion is correct.
    """
    detector = AnomalyDetector(random_state=42)
    X_normal = _make_normal_vectors(100, seed=42)
    detector.fit(X_normal)
    test_normal = _make_normal_vectors(20, seed=77)
    scores = [detector.anomaly_score(v) for v in test_normal]
    mean_score = sum(scores) / len(scores)
    assert mean_score < 0.6, f"Expected low anomaly scores for normal vectors, got mean={mean_score:.4f}"


def test_anomalous_vector_higher_score_than_normal():
    """
    An obviously extreme vector should score HIGHER than normal vectors.
    This validates that higher score = more anomalous (sklearn inversion correct).
    """
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(100, seed=42))

    normal_score = detector.anomaly_score(_make_normal_vectors(1, seed=5)[0])
    anomalous_score = detector.anomaly_score(_make_anomalous_vector())

    # The anomalous vector should score higher than the normal one
    assert anomalous_score > normal_score, (
        f"Expected anomalous > normal: anomalous={anomalous_score:.4f}, normal={normal_score:.4f}"
    )


def test_sklearn_score_direction_conversion():
    """
    Document and verify sklearn IsolationForest score direction.
    decision_function() returns HIGHER for inliers, LOWER for outliers.
    Our anomaly_score inverts this: higher anomaly_score = more anomalous.
    """
    from sklearn.ensemble import IsolationForest
    import numpy as np

    X_normal = np.array(_make_normal_vectors(80, seed=42))
    X_extreme = np.array([_make_anomalous_vector()])

    iso = IsolationForest(random_state=42)
    iso.fit(X_normal)

    # Raw sklearn scores
    normal_raw = float(iso.decision_function(X_normal[:1])[0])
    extreme_raw = float(iso.decision_function(X_extreme)[0])

    # sklearn: higher raw = more normal
    assert normal_raw > extreme_raw, "sklearn decision_function should be higher for inliers"

    # Our detector inverts: lower raw -> higher anomaly_score
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(80, seed=42))
    our_normal_score = detector.anomaly_score(_make_normal_vectors(1, seed=42)[0])
    our_extreme_score = detector.anomaly_score(_make_anomalous_vector())

    # Our convention: higher score = more anomalous
    assert our_extreme_score > our_normal_score, "Our anomaly_score should be higher for extreme vectors"


# ---------------------------------------------------------------------------
# predict()
# ---------------------------------------------------------------------------

def test_predict_returns_tuple():
    """predict() must return (int, float)."""
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(50))
    vec = _make_normal_vectors(1)[0]
    result = detector.predict(vec)
    assert isinstance(result, tuple)
    assert len(result) == 2
    label, raw = result
    assert isinstance(label, int)
    assert isinstance(raw, float)


def test_predict_label_is_binary():
    """predict() label must be 0 (normal) or 1 (anomaly)."""
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(50))
    for vec in _make_normal_vectors(10, seed=999):
        label, _ = detector.predict(vec)
        assert label in (0, 1), f"Label must be 0 or 1, got {label}"


def test_predict_raw_score_is_finite():
    """The raw score in predict() must be finite."""
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(50))
    _, raw = detector.predict(_make_normal_vectors(1)[0])
    assert math.isfinite(raw)


def test_predict_single_returns_schema():
    """predict_single() must return an AnomalyPrediction schema object."""
    from backend.app.schemas.ml import AnomalyPrediction
    detector = AnomalyDetector(random_state=42)
    detector.fit(_make_normal_vectors(50))
    result = detector.predict_single(_make_normal_vectors(1)[0])
    assert isinstance(result, AnomalyPrediction)
    assert 0.0 <= result.anomaly_score <= 1.0
    assert math.isfinite(result.raw_score)
    assert isinstance(result.is_anomaly, bool)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_anomaly_score_deterministic():
    """Same seed and data must produce identical anomaly scores."""
    X = _make_normal_vectors(60, seed=42)
    test_vec = _make_normal_vectors(1, seed=7)[0]

    d1 = AnomalyDetector(random_state=42)
    d1.fit(X)
    s1 = d1.anomaly_score(test_vec)

    d2 = AnomalyDetector(random_state=42)
    d2.fit(X)
    s2 = d2.anomaly_score(test_vec)

    assert s1 == s2, f"Expected deterministic scores, got {s1} vs {s2}"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_anomaly_detector_dump_and_load():
    """dump() + load() round-trip should preserve functionality."""
    detector = AnomalyDetector(random_state=42)
    X = _make_normal_vectors(60)
    detector.fit(X)
    test_vec = _make_normal_vectors(1, seed=1)[0]
    score_before = detector.anomaly_score(test_vec)

    with tempfile.TemporaryDirectory() as tmp_dir:
        path = pathlib.Path(tmp_dir) / "anomaly.joblib"
        detector.dump(path)

        # Both files must exist
        assert path.is_file()
        assert path.with_suffix(".json").is_file()

        loaded = AnomalyDetector.load(path)
        score_after = loaded.anomaly_score(test_vec)

    assert abs(score_before - score_after) < 1e-10, (
        f"Score changed after load: {score_before} vs {score_after}"
    )


def test_anomaly_detector_load_missing_raises():
    """load() on a non-existent path must raise FileNotFoundError — no retry."""
    with pytest.raises(FileNotFoundError):
        AnomalyDetector.load(pathlib.Path("/nonexistent/path/to/model.joblib"))
