"""
UniGuard Unified Inference Engine

Takes a DirectionalFlowRecord and runs it through the full ML pipeline:
  DirectionalFlowRecord -> FeatureEngine -> FeaturePreprocessor -> ThreatClassifier + AnomalyDetector -> UnifiedMLResult

IMPORTANT:
- No external services are called.
- No IP addresses, flow_ids, timestamps, or profile labels enter the feature vector.
- Models are loaded from local disk only.
- If models are not trained, raises RuntimeError with a clear message (no retry loop).
"""

from __future__ import annotations

from backend.app.core.feature_engine import FeatureEngine
from backend.app.core.preprocessing import FeaturePreprocessor
from backend.app.schemas.traffic import DirectionalFlowRecord
from backend.app.schemas.ml import UnifiedMLResult, ModelReadinessState
from backend.app.ml.model_manager import (
    load_classifier,
    load_anomaly_detector,
    load_metadata,
    get_state,
)


def run_inference(flow: DirectionalFlowRecord) -> UnifiedMLResult:
    """
    Perform end-to-end ML inference on a single directional flow record.

    Pipeline:
        DirectionalFlowRecord
            -> FeatureEngine.extract_features()      (16 behavioral features)
            -> FeaturePreprocessor.preprocess()       (bounded, finite numeric vector)
            -> ThreatClassifier.predict_single()      (class + probabilities)
            -> AnomalyDetector.anomaly_score()        (normalized 0-1 score)
            -> UnifiedMLResult

    The feature vector contains ONLY the canonical 16 numeric features.
    Source IP, destination IP, flow_id, timestamps, and simulated_profile are
    NEVER included in X.

    Parameters
    ----------
    flow : DirectionalFlowRecord
        A single unidirectional flow record (authorized telemetry or synthetic demo data).

    Returns
    -------
    UnifiedMLResult
        Unified prediction result with threat type, probabilities, anomaly score,
        feature importances, and model version.

    Raises
    ------
    RuntimeError
        If models are not trained (ModelReadinessState.NOT_TRAINED). No retry loop.
    """
    # Check readiness immediately — no retry
    state = get_state()
    if state != ModelReadinessState.READY:
        raise RuntimeError(
            f"ML models are not ready (state={state.value}). "
            "Call train_models() to train and persist models first."
        )

    # Step 1: Feature extraction (no context for single-flow inference)
    raw_features = FeatureEngine.extract_features(flow, context_flows=None)

    # Step 2: Preprocessing — ensures all values are finite and bounded
    preprocessed = FeaturePreprocessor.preprocess(raw_features)
    feature_values = preprocessed.values  # List[float], 16 features

    # Step 3: Load models from local disk
    classifier = load_classifier()
    anomaly_detector = load_anomaly_detector()

    # Step 4: Classifier prediction
    clf_pred = classifier.predict_single(feature_values)

    # Step 5: Anomaly detection (independent signal)
    anomaly_score = anomaly_detector.anomaly_score(feature_values)
    label, _raw = anomaly_detector.predict(feature_values)
    is_anomaly = bool(label)

    # Step 6: Retrieve model version from metadata
    meta = load_metadata()
    model_version = meta.model_version if meta else "unknown"

    return UnifiedMLResult(
        threat_type=clf_pred.threat_type,
        class_probabilities=clf_pred.class_probabilities,
        classifier_confidence=clf_pred.confidence,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        model_version=model_version,
        feature_importances=clf_pred.feature_importances,
    )
