"""
Tests for ModelManager — persistence, loading, and readiness state.

Tests cover:
- save_classifier / load_classifier round-trip
- save_anomaly_detector / load_anomaly_detector round-trip
- save_metadata / load_metadata round-trip
- Missing artifacts => NOT_TRAINED (no retry)
- All artifacts present => READY
- Metadata schema validates correctly
- Metadata contains exactly 16 feature_names
- Metadata contains required fields per spec
"""

import pathlib
import json
import tempfile
import shutil
import pytest
import datetime

from backend.app.ml.classifier import ThreatClassifier
from backend.app.ml.anomaly_detector import AnomalyDetector
from backend.app.schemas.ml import ModelMetadata, ModelReadinessState
from backend.app.core.preprocessing import FEATURE_NAMES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _trained_classifier() -> ThreatClassifier:
    """Return a fitted ThreatClassifier trained on tiny synthetic data."""
    clf = ThreatClassifier(n_estimators=10, random_state=42)
    classes = ["NORMAL", "SCANNING_LIKE", "DOS_LIKE", "BOTNET_LIKE", "EXFILTRATION_LIKE", "OTHER_SUSPICIOUS"]
    X, y = [], []
    for i, cls in enumerate(classes):
        for j in range(10):
            vec = [float(i * 0.1 + j * 0.01)] * len(FEATURE_NAMES)
            X.append(vec)
            y.append(cls)
    clf.fit(X, y)
    return clf


def _trained_anomaly_detector() -> AnomalyDetector:
    """Return a fitted AnomalyDetector trained on tiny NORMAL vectors."""
    detector = AnomalyDetector(random_state=42)
    X_normal = [[float(j * 0.01)] * len(FEATURE_NAMES) for j in range(50)]
    detector.fit(X_normal)
    return detector


def _sample_metadata() -> ModelMetadata:
    """Return a valid ModelMetadata object."""
    return ModelMetadata(
        model_name="UniGuardML",
        model_version="0.1.0",
        feature_schema_version="1.0",
        feature_names=list(FEATURE_NAMES),
        classes=["NORMAL", "SCANNING_LIKE", "DOS_LIKE", "BOTNET_LIKE", "EXFILTRATION_LIKE", "OTHER_SUSPICIOUS"],
        random_seed=42,
        training_source="synthetic_demo_data",
        training_sample_count=1200,
        class_distribution={"NORMAL": 200, "SCANNING_LIKE": 200, "DOS_LIKE": 200,
                             "BOTNET_LIKE": 200, "EXFILTRATION_LIKE": 200, "OTHER_SUSPICIOUS": 200},
        validation_metrics=None,
        isolation_forest_configuration={"n_estimators": 100, "contamination": 0.1},
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        readiness_state=ModelReadinessState.READY,
    )


# ---------------------------------------------------------------------------
# We need to redirect MODEL_DIR for isolation — use monkeypatch
# ---------------------------------------------------------------------------

@pytest.fixture()
def isolated_model_dir(tmp_path, monkeypatch):
    """Redirect model_manager paths to a temp directory for test isolation."""
    import backend.app.ml.model_manager as mm

    monkeypatch.setattr(mm, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(mm, "CLASSIFIER_MODEL_FILE", tmp_path / "classifier.joblib")
    monkeypatch.setattr(mm, "ANOMALY_MODEL_FILE", tmp_path / "anomaly_detector.joblib")
    monkeypatch.setattr(mm, "METADATA_FILE", tmp_path / "metadata.json")
    return tmp_path


# ---------------------------------------------------------------------------
# get_state — missing artifacts
# ---------------------------------------------------------------------------

def test_state_not_trained_when_no_files(isolated_model_dir):
    """get_state() must return NOT_TRAINED when no model files exist."""
    from backend.app.ml.model_manager import get_state
    assert get_state() == ModelReadinessState.NOT_TRAINED


def test_state_not_trained_when_only_classifier(isolated_model_dir):
    """get_state() must return NOT_TRAINED when only classifier is present."""
    import backend.app.ml.model_manager as mm
    from backend.app.ml.model_manager import get_state, save_classifier
    clf = _trained_classifier()
    meta = _sample_metadata()
    save_classifier(clf, meta)
    # Anomaly detector and metadata were written too by save_classifier internally,
    # but anomaly_detector.joblib was NOT saved — remove it to simulate partial state
    mm.ANOMALY_MODEL_FILE.unlink(missing_ok=True)
    assert get_state() == ModelReadinessState.NOT_TRAINED


def test_state_not_trained_when_no_metadata(isolated_model_dir):
    """get_state() must return NOT_TRAINED when metadata.json is absent."""
    import backend.app.ml.model_manager as mm
    from backend.app.ml.model_manager import get_state, save_classifier, save_anomaly_detector
    clf = _trained_classifier()
    det = _trained_anomaly_detector()
    meta = _sample_metadata()
    save_classifier(clf, meta)
    save_anomaly_detector(det, meta)
    mm.METADATA_FILE.unlink(missing_ok=True)
    assert get_state() == ModelReadinessState.NOT_TRAINED


# ---------------------------------------------------------------------------
# Classifier save / load
# ---------------------------------------------------------------------------

def test_save_and_load_classifier(isolated_model_dir):
    """Classifier survives a save/load round-trip."""
    from backend.app.ml.model_manager import save_classifier, load_classifier
    clf = _trained_classifier()
    meta = _sample_metadata()
    save_classifier(clf, meta)

    loaded = load_classifier()
    assert loaded.is_fitted
    # Verify prediction works
    vec = [0.1] * len(FEATURE_NAMES)
    pred = loaded.predict_single(vec)
    assert pred.threat_type in ["NORMAL", "SCANNING_LIKE", "DOS_LIKE",
                                  "BOTNET_LIKE", "EXFILTRATION_LIKE", "OTHER_SUSPICIOUS"]


def test_load_classifier_missing_raises(isolated_model_dir):
    """load_classifier() must raise FileNotFoundError when file absent — no retry."""
    from backend.app.ml.model_manager import load_classifier
    with pytest.raises(FileNotFoundError):
        load_classifier()


# ---------------------------------------------------------------------------
# Anomaly detector save / load
# ---------------------------------------------------------------------------

def test_save_and_load_anomaly_detector(isolated_model_dir):
    """Anomaly detector survives a save/load round-trip and produces equal scores."""
    from backend.app.ml.model_manager import save_anomaly_detector, load_anomaly_detector
    det = _trained_anomaly_detector()
    meta = _sample_metadata()
    test_vec = [0.05] * len(FEATURE_NAMES)
    score_before = det.anomaly_score(test_vec)

    save_anomaly_detector(det, meta)
    loaded = load_anomaly_detector()
    score_after = loaded.anomaly_score(test_vec)

    assert abs(score_before - score_after) < 1e-10, (
        f"Score diverged after round-trip: {score_before} vs {score_after}"
    )


def test_load_anomaly_detector_missing_raises(isolated_model_dir):
    """load_anomaly_detector() must raise FileNotFoundError when file absent — no retry."""
    from backend.app.ml.model_manager import load_anomaly_detector
    with pytest.raises(FileNotFoundError):
        load_anomaly_detector()


# ---------------------------------------------------------------------------
# Metadata save / load
# ---------------------------------------------------------------------------

def test_save_and_load_metadata(isolated_model_dir):
    """Metadata survives a save/load round-trip."""
    from backend.app.ml.model_manager import save_metadata, load_metadata
    meta = _sample_metadata()
    save_metadata(meta)
    loaded = load_metadata()
    assert loaded is not None
    assert loaded.model_name == "UniGuardML"
    assert loaded.model_version == "0.1.0"


def test_load_metadata_missing_returns_none(isolated_model_dir):
    """load_metadata() must return None when file absent — not raise."""
    from backend.app.ml.model_manager import load_metadata
    result = load_metadata()
    assert result is None


# ---------------------------------------------------------------------------
# Metadata schema validation
# ---------------------------------------------------------------------------

def test_metadata_has_exactly_16_feature_names():
    """ModelMetadata must store exactly 16 feature names."""
    meta = _sample_metadata()
    assert len(meta.feature_names) == 16


def test_metadata_feature_names_match_canonical():
    """Metadata feature_names must match FEATURE_NAMES from preprocessing."""
    meta = _sample_metadata()
    assert meta.feature_names == list(FEATURE_NAMES)


def test_metadata_has_required_fields():
    """Metadata must contain all spec-required fields."""
    meta = _sample_metadata()
    assert meta.model_name
    assert meta.model_version
    assert meta.feature_schema_version
    assert len(meta.feature_names) == 16
    assert len(meta.classes) == 6
    assert isinstance(meta.random_seed, int)
    assert meta.training_source
    assert isinstance(meta.training_sample_count, int)
    assert isinstance(meta.class_distribution, dict)
    assert meta.isolation_forest_configuration is not None
    assert meta.created_at


def test_metadata_six_classes():
    """Metadata classes list must contain all six threat profiles."""
    expected = {"NORMAL", "SCANNING_LIKE", "DOS_LIKE", "BOTNET_LIKE", "EXFILTRATION_LIKE", "OTHER_SUSPICIOUS"}
    meta = _sample_metadata()
    assert set(meta.classes) == expected


def test_metadata_readiness_state_enum():
    """Metadata readiness_state must be a valid ModelReadinessState."""
    meta = _sample_metadata()
    assert meta.readiness_state in list(ModelReadinessState)


def test_metadata_serializes_to_json(isolated_model_dir):
    """Metadata must serialize to valid JSON and round-trip correctly."""
    from backend.app.ml.model_manager import save_metadata, load_metadata
    meta = _sample_metadata()
    save_metadata(meta)

    import backend.app.ml.model_manager as mm
    raw = json.loads(mm.METADATA_FILE.read_text(encoding="utf-8"))

    # All spec-required keys must be present in the JSON
    required_keys = [
        "model_name", "model_version", "feature_schema_version",
        "feature_names", "classes", "random_seed", "training_source",
        "training_sample_count", "class_distribution",
        "isolation_forest_configuration", "created_at",
    ]
    for key in required_keys:
        assert key in raw, f"Required key '{key}' missing from metadata.json"


# ---------------------------------------------------------------------------
# READY state (full set of artifacts)
# ---------------------------------------------------------------------------

def test_state_ready_when_all_artifacts_present(isolated_model_dir):
    """get_state() must return READY when all three artifacts exist and metadata is valid."""
    from backend.app.ml.model_manager import (
        save_classifier, save_anomaly_detector, save_metadata, get_state
    )
    clf = _trained_classifier()
    det = _trained_anomaly_detector()
    meta = _sample_metadata()
    save_classifier(clf, meta)
    save_anomaly_detector(det, meta)
    save_metadata(meta)
    assert get_state() == ModelReadinessState.READY
