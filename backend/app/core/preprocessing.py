"""
UniGuard Feature Preprocessing & Vector Normalization
Ensures deterministic ordering, finite numerics, and bounds safety for ML model inputs.
"""

from typing import List, Dict
import math
from backend.app.schemas.traffic import FeatureVector, PreprocessedFeatureVector

# Canonical, strictly ordered list of feature names consumed by downstream ML models
FEATURE_NAMES: List[str] = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "packet_size_std",
    "unique_destination_count",
    "unique_destination_port_count",
    "destination_port_entropy",
    "packet_size_entropy",
    "burst_score",
    "source_activity_rate",
    "destination_diversity",
    "port_diversity",
    "protocol_indicator",
]

# Reasonable upper bounds for extreme value clipping to prevent numeric overflows
FEATURE_MAX_BOUNDS: Dict[str, float] = {
    "flow_duration": 86400.0,       # 24 hours max flow window
    "packet_count": 100_000_000.0,
    "byte_count": 100_000_000_000.0, # 100 GB max
    "packets_per_second": 10_000_000.0,
    "bytes_per_second": 10_000_000_000.0,
    "average_packet_size": 65535.0,  # Max IP packet size
    "packet_size_std": 65535.0,
    "unique_destination_count": 1_000_000.0,
    "unique_destination_port_count": 65536.0,
    "destination_port_entropy": 16.0, # Log2(65536) = 16 bits max
    "packet_size_entropy": 16.0,
    "burst_score": 1.0,
    "source_activity_rate": 1_000_000.0,
    "destination_diversity": 1.0,
    "port_diversity": 1.0,
    "protocol_indicator": 10.0,
}


class FeaturePreprocessor:
    """
    Transforms raw FeatureVector instances into sanitized, ordered numerical vectors.
    Guarantees no NaN, Inf, or out-of-range values.
    """

    @staticmethod
    def sanitize_float(val: float, max_bound: float = 1e12, default: float = 0.0) -> float:
        """
        Sanitizes a float against NaN, Inf, negative infinity, and excessive magnitude.
        """
        if val is None or math.isnan(val) or math.isinf(val):
            return default
        # Guard non-negative lower bound
        clamped = max(0.0, float(val))
        return min(clamped, max_bound)

    @classmethod
    def preprocess(cls, vector: FeatureVector) -> PreprocessedFeatureVector:
        """
        Processes a FeatureVector into an ordered, validated PreprocessedFeatureVector.
        """
        vector_dict = vector.model_dump()
        ordered_values: List[float] = []

        is_valid = True
        for name in FEATURE_NAMES:
            raw_val = vector_dict.get(name, 0.0)
            max_bound = FEATURE_MAX_BOUNDS.get(name, 1e12)

            sanitized = cls.sanitize_float(raw_val, max_bound=max_bound)
            if raw_val is None or math.isnan(raw_val) or math.isinf(raw_val):
                is_valid = False

            ordered_values.append(round(sanitized, 6))

        return PreprocessedFeatureVector(
            feature_names=list(FEATURE_NAMES),
            values=ordered_values,
            is_valid=is_valid,
        )

    @classmethod
    def to_flat_list(cls, vector: FeatureVector) -> List[float]:
        """Convenience method returning raw flat float array in canonical order."""
        return cls.preprocess(vector).values
