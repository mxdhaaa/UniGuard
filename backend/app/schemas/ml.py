"""
Pydantic Schemas for Machine Learning Intelligence Layer
Includes schemas for threat classification, anomaly detection, evaluation, and model metadata.
"""

from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field


class ModelReadinessState(str, Enum):
    NOT_TRAINED = "NOT_TRAINED"
    TRAINING = "TRAINING"
    READY = "READY"
    FAILED = "FAILED"


class ClassifierPrediction(BaseModel):
    threat_type: str = Field(..., description="Predicted behavioral threat class")
    class_probabilities: Dict[str, float] = Field(..., description="Probability distribution across all 6 classes")
    confidence: float = Field(..., description="Confidence score (highest class probability) in [0.0, 1.0]")
    feature_importances: Dict[str, float] = Field(default_factory=dict, description="Global model feature importance weights")


class AnomalyPrediction(BaseModel):
    anomaly_score: float = Field(..., description="Normalized anomaly score in [0.0, 1.0] where 1.0 = highly anomalous")
    raw_score: float = Field(..., description="Raw decision function output from Isolation Forest (higher=more normal in sklearn convention)")
    is_anomaly: bool = Field(..., description="True if observation is flagged as an outlier/anomaly")


class UnifiedMLResult(BaseModel):
    threat_type: str = Field(..., description="Predicted behavioral threat class")
    class_probabilities: Dict[str, float] = Field(..., description="Class probability distribution")
    classifier_confidence: float = Field(..., description="Classifier confidence in [0.0, 1.0]")
    anomaly_score: float = Field(..., description="Normalized anomaly score in [0.0, 1.0]")
    is_anomaly: bool = Field(..., description="Outlier indicator from Isolation Forest")
    model_version: str = Field(..., description="Active model release version")
    feature_importances: Dict[str, float] = Field(default_factory=dict, description="Feature importance attribution for explainability")


class ModelMetadata(BaseModel):
    model_name: str = Field(..., description="Model identifier")
    model_version: str = Field(default="0.1.0", description="Semantic model version")
    feature_schema_version: str = Field(default="1.0", description="Version of the feature vector contract")
    feature_names: List[str] = Field(default_factory=list, description="Canonical ordered list of 16 feature names")
    classes: List[str] = Field(..., description="List of recognized threat classes")
    random_seed: int = Field(default=42, description="PRNG seed used during training")
    training_source: str = Field(default="synthetic_demo_data", description="Dataset description")
    training_sample_count: int = Field(default=0, description="Total training instances")
    class_distribution: Dict[str, int] = Field(default_factory=dict, description="Training samples per class")
    validation_metrics: Optional[Dict[str, Any]] = Field(default=None, description="Validation evaluation metrics")
    isolation_forest_configuration: Optional[Dict[str, Any]] = Field(default=None, description="IsolationForest hyper-parameters")
    created_at: str = Field(..., description="ISO 8601 training timestamp")
    readiness_state: ModelReadinessState = Field(default=ModelReadinessState.READY, description="Operational state")


class EvaluationMetrics(BaseModel):
    accuracy: float = Field(..., description="Overall classification accuracy")
    macro_precision: float = Field(..., description="Macro-averaged precision")
    macro_recall: float = Field(..., description="Macro-averaged recall")
    macro_f1: float = Field(..., description="Macro-averaged F1 score")
    weighted_precision: float = Field(default=0.0, description="Sample-weighted precision")
    weighted_recall: float = Field(default=0.0, description="Sample-weighted recall")
    weighted_f1: float = Field(..., description="Sample-weighted F1 score")
    confusion_matrix: List[List[int]] = Field(..., description="Confusion matrix (rows=true, cols=pred)")
    per_class_metrics: Dict[str, Dict[str, float]] = Field(..., description="Precision, recall, F1 per class")
    train_samples: int = Field(..., description="Total training instances")
    val_samples: int = Field(..., description="Total validation instances")
    samples_per_class: Dict[str, int] = Field(..., description="Sample distribution across classes")
