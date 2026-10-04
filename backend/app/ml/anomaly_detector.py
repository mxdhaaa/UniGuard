"""
UniGuard Anomaly Detector
Wraps sklearn IsolationForest to provide deterministic, normalized anomaly scoring.

Score direction convention (sklearn IsolationForest):
  decision_function() returns HIGHER values for INLIERS (normal traffic)
                         and LOWER values for OUTLIERS (anomalous traffic).

We invert this so that our normalized anomaly_score follows the intuitive convention:
  0.0 = most normal (inlier)
  1.0 = most anomalous (outlier)

Normalization uses min-max scaling derived from training data scores:
  raw_inverted = -raw_score
  normalized   = (raw_inverted - min_inverted) / (max_inverted - min_inverted)
  where min_inverted = -score_max_train, max_inverted = -score_min_train

IMPORTANT: Trained only on NORMAL class feature vectors.
The anomaly score is an independent signal - it is NOT a probability of maliciousness.
"""

from __future__ import annotations

import json
import pathlib
from typing import List, Tuple, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from backend.app.schemas.ml import AnomalyPrediction


class AnomalyDetector:
    """
    Deterministic IsolationForest-based anomaly detector.

    Trains ONLY on feature vectors from the NORMAL simulated profile.
    All other profiles are considered potentially anomalous relative to that baseline.
    The normalized anomaly score (0.0-1.0) is an independent signal from the classifier.
    """

    def __init__(self, random_state: int = 42, contamination: float = 0.1) -> None:
        self.random_state = random_state
        self.contamination = contamination
        self.model: Optional[IsolationForest] = None
        self._score_min: Optional[float] = None  # min raw decision_function score on training set
        self._score_max: Optional[float] = None  # max raw decision_function score on training set

    def fit(self, X: List[List[float]]) -> None:
        """
        Train the IsolationForest on NORMAL feature vectors only.

        Parameters
        ----------
        X : List[List[float]]
            Pre-processed feature vectors (canonical 16-feature order from FeaturePreprocessor).
            ONLY NORMAL class vectors should be supplied.
        """
        if not X:
            raise ValueError("Training data for AnomalyDetector cannot be empty")

        X_arr = np.asarray(X, dtype=float)
        self.model = IsolationForest(
            n_estimators=100,
            max_samples="auto",
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(X_arr)

        # Capture raw decision_function range from training data for normalization.
        # Higher raw score = more normal (sklearn convention).
        raw_scores = self.model.decision_function(X_arr)
        self._score_min = float(np.min(raw_scores))
        self._score_max = float(np.max(raw_scores))

        # Guard degenerate case (all scores identical)
        if self._score_max == self._score_min:
            self._score_max = self._score_min + 1e-12

    def _raw_score(self, vector: List[float]) -> float:
        """Return the raw decision_function score for a single feature vector."""
        if self.model is None:
            raise RuntimeError("AnomalyDetector has not been trained. Call fit() first.")
        arr = np.asarray([vector], dtype=float)
        return float(self.model.decision_function(arr)[0])

    def anomaly_score(self, vector: List[float]) -> float:
        """
        Return a normalized anomaly score in [0.0, 1.0].

        Inversion rationale:
          sklearn decision_function returns higher scores for inliers.
          We negate the raw score so that higher anomaly_score = more anomalous.
          We then apply min-max scaling using training data bounds to constrain to [0,1].
        """
        if self._score_min is None or self._score_max is None:
            raise RuntimeError("AnomalyDetector score bounds undefined. Call fit() first.")

        raw = self._raw_score(vector)
        # Invert: lower raw -> higher anomaly
        inverted = -raw
        min_inverted = -self._score_max
        max_inverted = -self._score_min

        if max_inverted == min_inverted:
            return 0.0

        normalized = (inverted - min_inverted) / (max_inverted - min_inverted)
        # Clip to [0,1] to guard against numerical noise
        return float(max(0.0, min(1.0, normalized)))

    def predict(self, vector: List[float]) -> Tuple[int, float]:
        """
        Predict whether a vector is an anomaly (1) or normal (0).

        Returns
        -------
        Tuple[int, float]
            (label, raw_score) where label=1 means anomaly, 0 means normal.
            Note: sklearn predict returns 1 for outliers, -1 for inliers.
            We convert: sklearn 1 -> our 1 (anomaly), sklearn -1 -> our 0 (normal).
        """
        if self.model is None:
            raise RuntimeError("AnomalyDetector has not been trained. Call fit() first.")

        raw = self._raw_score(vector)
        sk_label = int(self.model.predict(np.asarray([vector], dtype=float))[0])
        # Convert sklearn label: 1=outlier->1=anomaly, -1=inlier->0=normal
        our_label = 1 if sk_label == 1 else 0
        return our_label, raw

    def predict_single(self, vector: List[float]) -> AnomalyPrediction:
        """
        Full single-vector prediction returning an AnomalyPrediction schema object.
        """
        label, raw = self.predict(vector)
        score = self.anomaly_score(vector)
        return AnomalyPrediction(
            anomaly_score=score,
            raw_score=raw,
            is_anomaly=bool(label),
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def dump(self, path: pathlib.Path) -> None:
        """
        Serialize the trained model and scaling metadata.

        path: path to .joblib file.
        A companion .json file is written to store score bounds and config.
        """
        if self.model is None:
            raise RuntimeError("Cannot serialize an untrained AnomalyDetector.")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)
        scaling_meta = {
            "score_min": self._score_min,
            "score_max": self._score_max,
            "random_state": self.random_state,
            "contamination": self.contamination,
        }
        path.with_suffix(".json").write_text(json.dumps(scaling_meta, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: pathlib.Path) -> "AnomalyDetector":
        """Load a persisted detector from a .joblib file."""
        if not path.is_file():
            raise FileNotFoundError(f"AnomalyDetector model not found: {path}")
        meta_path = path.with_suffix(".json")
        if not meta_path.is_file():
            raise FileNotFoundError(f"AnomalyDetector scaling metadata not found: {meta_path}")

        model = joblib.load(path)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        detector = cls(
            random_state=meta.get("random_state", 42),
            contamination=meta.get("contamination", 0.1),
        )
        detector.model = model
        detector._score_min = meta.get("score_min")
        detector._score_max = meta.get("score_max")
        return detector
