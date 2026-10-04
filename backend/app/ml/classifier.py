"""
Supervised Random Forest Threat Classifier
Classifies unidirectional flow feature vectors into 6 behavioral threat categories.
Consumes ONLY the canonical 16 numeric features; strictly excludes IP addresses, timestamps, and identifiers.
"""

from typing import List, Dict, Optional, Union
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from backend.app.core.preprocessing import FEATURE_NAMES
from backend.app.schemas.ml import ClassifierPrediction, EvaluationMetrics

TARGET_CLASSES: List[str] = [
    "NORMAL",
    "SCANNING_LIKE",
    "DOS_LIKE",
    "BOTNET_LIKE",
    "EXFILTRATION_LIKE",
    "OTHER_SUSPICIOUS",
]


class ThreatClassifier:
    """
    Random Forest multi-class threat classifier for directional network flows.

    Accepts ONLY the canonical 16 numeric features from FeaturePreprocessor.
    IP addresses, timestamps, flow IDs, and profile labels are NEVER used as features.
    """

    def __init__(
        self,
        n_estimators: int = 200,
        random_state: int = 42,
        class_weight: str = "balanced",
        n_jobs: int = -1,
    ) -> None:
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.class_weight = class_weight
        self.n_jobs = n_jobs
        self.classes: List[str] = list(TARGET_CLASSES)
        self.feature_names: List[str] = list(FEATURE_NAMES)

        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            class_weight=self.class_weight,
            n_jobs=self.n_jobs,
        )
        self.is_fitted: bool = False

    def fit(self, X: Union[np.ndarray, List[List[float]]], y: Union[np.ndarray, List[str]]) -> "ThreatClassifier":
        """
        Trains the Random Forest model on feature matrix X and target labels y.

        Parameters
        ----------
        X : array-like of shape (n_samples, 16)
            Feature matrix. Must contain exactly 16 features per row.
        y : array-like of shape (n_samples,)
            Class labels (strings from TARGET_CLASSES).
        """
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y, dtype=str)

        if X_arr.ndim != 2 or X_arr.shape[1] != len(self.feature_names):
            raise ValueError(
                f"Feature dimension mismatch: expected {len(self.feature_names)} features, got {X_arr.shape[1] if X_arr.ndim == 2 else 'non-2D'}"
            )

        self.model.fit(X_arr, y_arr)
        # Update class list to match sklearn's ordering
        self.classes = list(self.model.classes_)
        self.is_fitted = True
        return self

    def predict_single(self, feature_values: List[float]) -> ClassifierPrediction:
        """
        Infers class prediction and probability distribution for a single 16-feature vector.

        The feature_values must be in canonical FEATURE_NAMES order (from FeaturePreprocessor).
        """
        if not self.is_fitted:
            raise RuntimeError("ThreatClassifier must be fitted before running inference.")

        if len(feature_values) != len(self.feature_names):
            raise ValueError(f"Expected {len(self.feature_names)} features, got {len(feature_values)}")

        X_input = np.asarray([feature_values], dtype=np.float64)
        probs = self.model.predict_proba(X_input)[0]

        class_probs: Dict[str, float] = {
            cls_name: round(float(probs[idx]), 6)
            for idx, cls_name in enumerate(self.model.classes_)
        }

        best_idx = int(np.argmax(probs))
        predicted_class = str(self.model.classes_[best_idx])
        confidence = round(float(probs[best_idx]), 6)

        return ClassifierPrediction(
            threat_type=predicted_class,
            class_probabilities=class_probs,
            confidence=confidence,
            feature_importances=self.get_feature_importances(),
        )

    def evaluate(
        self,
        X_val: Union[np.ndarray, List[List[float]]],
        y_val: Union[np.ndarray, List[str]],
        train_samples_count: int = 0,
        samples_per_class: Optional[Dict[str, int]] = None,
    ) -> EvaluationMetrics:
        """
        Evaluates model performance against a held-out validation dataset.
        Computes accuracy, macro/weighted precision, recall, F1, and confusion matrix.

        NOTE: These metrics are computed on synthetic data. High scores reflect
        synthetic class separability and do NOT demonstrate real-world performance.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before evaluation.")

        X_arr = np.asarray(X_val, dtype=np.float64)
        y_arr = np.asarray(y_val, dtype=str)

        y_pred = self.model.predict(X_arr)

        acc = float(accuracy_score(y_arr, y_pred))
        macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(
            y_arr, y_pred, average="macro", zero_division=0
        )
        weighted_prec, weighted_rec, weighted_f1, _ = precision_recall_fscore_support(
            y_arr, y_pred, average="weighted", zero_division=0
        )

        # Per-class metrics
        p_class, r_class, f_class, _ = precision_recall_fscore_support(
            y_arr, y_pred, labels=self.classes, average=None, zero_division=0
        )
        per_class: Dict[str, Dict[str, float]] = {}
        for i, cls_name in enumerate(self.classes):
            per_class[cls_name] = {
                "precision": round(float(p_class[i]), 4),
                "recall": round(float(r_class[i]), 4),
                "f1": round(float(f_class[i]), 4),
            }

        cm = confusion_matrix(y_arr, y_pred, labels=self.classes).tolist()

        return EvaluationMetrics(
            accuracy=round(acc, 4),
            macro_precision=round(float(macro_prec), 4),
            macro_recall=round(float(macro_rec), 4),
            macro_f1=round(float(macro_f1), 4),
            weighted_precision=round(float(weighted_prec), 4),
            weighted_recall=round(float(weighted_rec), 4),
            weighted_f1=round(float(weighted_f1), 4),
            confusion_matrix=cm,
            per_class_metrics=per_class,
            train_samples=train_samples_count,
            val_samples=len(y_arr),
            samples_per_class=samples_per_class or {},
        )

    def get_feature_importances(self) -> Dict[str, float]:
        """
        Returns global feature importance dictionary (Gini impurity reduction across all trees).
        Always returns exactly 16 entries matching FEATURE_NAMES.
        Note: This is a global model-level importance, not a local per-prediction explanation.
        """
        if not self.is_fitted:
            return {name: 0.0 for name in self.feature_names}

        importances = self.model.feature_importances_
        return {
            name: round(float(importances[idx]), 6)
            for idx, name in enumerate(self.feature_names)
        }
