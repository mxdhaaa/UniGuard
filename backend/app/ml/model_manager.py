"""
UniGuard Model Manager
Handles persistence and loading of the RandomForest classifier,
IsolationForest anomaly detector, and associated metadata.json.

All paths are internal constants - no user-supplied paths are accepted.
Reports ModelReadinessState without retry loops.
"""

from __future__ import annotations

import json
import pathlib
import datetime
from typing import Optional

import joblib

from backend.app.ml.classifier import ThreatClassifier
from backend.app.ml.anomaly_detector import AnomalyDetector
from backend.app.schemas.ml import ModelMetadata, ModelReadinessState

# ---------------------------------------------------------------------------
# Internal storage paths — constants, not user-configurable
# ---------------------------------------------------------------------------
MODEL_DIR: pathlib.Path = pathlib.Path(__file__).resolve().parent / "models"
CLASSIFIER_MODEL_FILE: pathlib.Path = MODEL_DIR / "classifier.joblib"
ANOMALY_MODEL_FILE: pathlib.Path = MODEL_DIR / "anomaly_detector.joblib"
METADATA_FILE: pathlib.Path = MODEL_DIR / "metadata.json"


def _ensure_dir() -> None:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Classifier persistence
# ---------------------------------------------------------------------------

def save_classifier(classifier: ThreatClassifier, metadata: ModelMetadata) -> None:
    """Persist a trained ThreatClassifier and update metadata on disk."""
    _ensure_dir()
    joblib.dump(classifier.model, CLASSIFIER_MODEL_FILE)
    _write_metadata(metadata)


def load_classifier() -> ThreatClassifier:
    """
    Load the persisted ThreatClassifier.
    Raises FileNotFoundError immediately if the model file is absent — no retry.
    """
    if not CLASSIFIER_MODEL_FILE.is_file():
        raise FileNotFoundError(
            f"Classifier model not found at {CLASSIFIER_MODEL_FILE}. "
            "Run train_models() first."
        )
    raw_model = joblib.load(CLASSIFIER_MODEL_FILE)
    clf = ThreatClassifier()
    clf.model = raw_model
    clf.is_fitted = True
    return clf


# ---------------------------------------------------------------------------
# Anomaly detector persistence
# ---------------------------------------------------------------------------

def save_anomaly_detector(detector: AnomalyDetector, metadata: ModelMetadata) -> None:
    """Persist the IsolationForest detector and update metadata on disk."""
    _ensure_dir()
    detector.dump(ANOMALY_MODEL_FILE)
    _write_metadata(metadata)


def load_anomaly_detector() -> AnomalyDetector:
    """
    Load the persisted AnomalyDetector.
    Raises FileNotFoundError immediately if the model file is absent — no retry.
    """
    if not ANOMALY_MODEL_FILE.is_file():
        raise FileNotFoundError(
            f"Anomaly detector not found at {ANOMALY_MODEL_FILE}. "
            "Run train_models() first."
        )
    return AnomalyDetector.load(ANOMALY_MODEL_FILE)


# ---------------------------------------------------------------------------
# Metadata persistence
# ---------------------------------------------------------------------------

def _write_metadata(metadata: ModelMetadata) -> None:
    """Write metadata to disk, overwriting any existing file."""
    _ensure_dir()
    if not metadata.created_at:
        metadata.created_at = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )
    METADATA_FILE.write_text(json.dumps(metadata.model_dump(), indent=2), encoding="utf-8")


def save_metadata(metadata: ModelMetadata) -> None:
    """Public API for writing metadata."""
    _write_metadata(metadata)


def load_metadata() -> Optional[ModelMetadata]:
    """
    Load metadata from disk.
    Returns None if the file is absent or corrupted — no exception raised.
    """
    if not METADATA_FILE.is_file():
        return None
    try:
        raw = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
        return ModelMetadata(**raw)
    except Exception as exc:
        print(f"[ModelManager] Could not load metadata: {exc}")
        return None


# ---------------------------------------------------------------------------
# Readiness state
# ---------------------------------------------------------------------------

def get_state() -> ModelReadinessState:
    """
    Return the current readiness state.

    NOT_TRAINED: any model file or metadata is missing.
    READY:       both model files and valid metadata are present.
    FAILED:      metadata exists but cannot be parsed (corrupted).

    This function is synchronous and does NOT retry or sleep.
    """
    classifier_ok = CLASSIFIER_MODEL_FILE.is_file()
    anomaly_ok = ANOMALY_MODEL_FILE.is_file()
    metadata_ok = METADATA_FILE.is_file()

    if not (classifier_ok and anomaly_ok and metadata_ok):
        return ModelReadinessState.NOT_TRAINED

    meta = load_metadata()
    if meta is None:
        return ModelReadinessState.FAILED

    return ModelReadinessState.READY
