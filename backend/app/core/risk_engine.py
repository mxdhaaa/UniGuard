"""
UniGuard Deterministic Risk Engine (Milestone 6)

Converts a UnifiedMLResult from the Milestone 5 ML pipeline into a structured,
explainable RiskAssessment.

===========================================================================
FORMULA
===========================================================================

risk_score = clamp(
    threat_signal + anomaly_signal + confidence_modifier,
    0, 100
)

Where:

  threat_signal      = THREAT_BASE_WEIGHTS[threat_type] * THREAT_WEIGHT_SCALE
  anomaly_signal     = anomaly_score * ANOMALY_WEIGHT
  confidence_modifier= confidence_delta * CONFIDENCE_WEIGHT

  confidence_delta   = classifier_confidence - 0.5
    (positive = above-baseline confidence amplifies threat signal)
    (negative = below-baseline confidence dampens threat signal)

===========================================================================
COMPONENT WEIGHTS  (sum of max possible = 100)
===========================================================================

THREAT_BASE_WEIGHTS — baseline risk level per threat class (0–1 scale):
  NORMAL            0.00   (no intrinsic threat contribution)
  OTHER_SUSPICIOUS  0.40   (unknown pattern, moderate concern)
  SCANNING_LIKE     0.55   (reconnaissance, precursor to attack)
  EXFILTRATION_LIKE 0.70   (data exfiltration, high impact)
  BOTNET_LIKE       0.75   (command-and-control, high impact)
  DOS_LIKE          0.80   (availability attack, high impact)

THREAT_WEIGHT_SCALE = 60.0
  → max threat_signal = 0.80 * 60 = 48 points

ANOMALY_WEIGHT = 30.0
  → max anomaly_signal = 1.0 * 30 = 30 points
  → anomaly_score direction: higher = more anomalous (Milestone 5 contract)

CONFIDENCE_WEIGHT = 10.0
  → confidence_delta range: [-0.5, +0.5]
  → modifier range: [-5, +5] points
  → Net max (all components at max): 48 + 30 + 5 = 83 base
    (A CRITICAL score requires both high threat_type and high anomaly_score)

NOTE: These weights were chosen so that:
  - A pure NORMAL flow with zero anomaly and 50% confidence → 0 risk
  - A BOTNET_LIKE flow at full confidence and full anomaly → 30+45+5 = 80 (CRITICAL)
  - An anomalous NORMAL flow (anomaly_score=1.0) can still reach 35 (MEDIUM)

===========================================================================
SEVERITY THRESHOLDS
===========================================================================
  0  – 24   LOW
  25 – 49   MEDIUM
  50 – 74   HIGH
  75 – 100  CRITICAL

===========================================================================
SAFETY NOTES
===========================================================================
- No external APIs, network calls, or LLMs are used.
- The formula is fully deterministic: same input → same output.
- UnifiedMLResult is read-only; this engine never modifies it.
- Recommended actions are advisory only; no automated blocking occurs.
"""

from __future__ import annotations

from typing import List

from backend.app.schemas.ml import UnifiedMLResult
from backend.app.schemas.risk import RiskAssessment, RiskFactor, Severity

# ---------------------------------------------------------------------------
# Threat-type baseline weights (0.0 – 1.0)
# ---------------------------------------------------------------------------
THREAT_BASE_WEIGHTS: dict[str, float] = {
    "NORMAL": 0.00,
    "OTHER_SUSPICIOUS": 0.40,
    "SCANNING_LIKE": 0.55,
    "EXFILTRATION_LIKE": 0.70,
    "BOTNET_LIKE": 0.75,
    "DOS_LIKE": 0.80,
}

# Scale factors
THREAT_WEIGHT_SCALE: float = 60.0   # max threat contribution = 0.80 * 60 = 48 pts
ANOMALY_WEIGHT: float = 30.0         # max anomaly contribution = 1.0  * 30 = 30 pts
CONFIDENCE_WEIGHT: float = 10.0      # modifier range = ±5 pts (confidence_delta ∈ [-0.5, +0.5])

# Severity thresholds (inclusive lower bound)
SEVERITY_THRESHOLDS: list[tuple[float, Severity]] = [
    (75.0, Severity.CRITICAL),
    (50.0, Severity.HIGH),
    (25.0, Severity.MEDIUM),
    (0.0,  Severity.LOW),
]

# SOC recommended actions per severity
RECOMMENDED_ACTIONS: dict[Severity, str] = {
    Severity.LOW: (
        "Monitor traffic. No immediate action required."
    ),
    Severity.MEDIUM: (
        "Review flow behavior and continue monitoring. "
        "Correlate with related flows from the same source."
    ),
    Severity.HIGH: (
        "Investigate source activity and correlate related flows. "
        "Escalate to Tier-2 analyst if pattern persists."
    ),
    Severity.CRITICAL: (
        "Prioritize investigation. Correlate all flows from this source. "
        "Consider containment of the source after analyst confirmation."
    ),
}


class RiskEngine:
    """
    Deterministic risk engine that converts a UnifiedMLResult into a RiskAssessment.

    The engine is stateless and produces the same output for the same input.
    It does not make external calls, load models, or use any probabilistic sampling.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess(self, ml_result: UnifiedMLResult) -> RiskAssessment:
        """
        Compute a RiskAssessment from a UnifiedMLResult.

        Parameters
        ----------
        ml_result : UnifiedMLResult
            Output from the Milestone 5 ML inference pipeline.
            This object is not modified.

        Returns
        -------
        RiskAssessment
            Fully populated risk assessment with score, severity, factors, and explanation.
        """
        factors: List[RiskFactor] = []

        # ------------------------------------------------------------------
        # A. Threat signal
        # ------------------------------------------------------------------
        base_weight = THREAT_BASE_WEIGHTS.get(ml_result.threat_type, 0.40)
        threat_signal = base_weight * THREAT_WEIGHT_SCALE
        factors.append(RiskFactor(
            factor="threat_classification",
            contribution=round(threat_signal, 2),
            description=(
                f"ML classifier predicted '{ml_result.threat_type}' "
                f"(baseline weight={base_weight:.2f}). "
                f"Contributes {threat_signal:.1f} points."
            ),
        ))

        # ------------------------------------------------------------------
        # B. Anomaly signal
        # ------------------------------------------------------------------
        # anomaly_score contract (Milestone 5): 0.0 = normal, 1.0 = highly anomalous
        anomaly_signal = ml_result.anomaly_score * ANOMALY_WEIGHT
        factors.append(RiskFactor(
            factor="anomaly_score",
            contribution=round(anomaly_signal, 2),
            description=(
                f"IsolationForest anomaly score={ml_result.anomaly_score:.4f} "
                f"(0=normal, 1=anomalous). "
                f"Contributes {anomaly_signal:.1f} points."
            ),
        ))

        # ------------------------------------------------------------------
        # C. Confidence modifier
        # ------------------------------------------------------------------
        # confidence_delta > 0 → classifier is more certain → amplify threat signal
        # confidence_delta < 0 → classifier is uncertain → dampen threat signal
        confidence_delta = ml_result.classifier_confidence - 0.5
        confidence_modifier = confidence_delta * CONFIDENCE_WEIGHT
        factors.append(RiskFactor(
            factor="confidence_modifier",
            contribution=round(confidence_modifier, 2),
            description=(
                f"Classifier confidence={ml_result.classifier_confidence:.4f}. "
                f"Delta from baseline 0.5: {confidence_delta:+.4f}. "
                f"Modifier: {confidence_modifier:+.2f} points."
            ),
        ))

        # ------------------------------------------------------------------
        # D. Anomaly flag bonus
        # ------------------------------------------------------------------
        anomaly_flag_bonus = 5.0 if ml_result.is_anomaly else 0.0
        if ml_result.is_anomaly:
            factors.append(RiskFactor(
                factor="anomaly_flag",
                contribution=anomaly_flag_bonus,
                description=(
                    "IsolationForest flagged this flow as a statistical outlier "
                    "relative to the NORMAL training baseline (+5 points)."
                ),
            ))

        # ------------------------------------------------------------------
        # E. Compute raw risk and clamp to [0, 100]
        # ------------------------------------------------------------------
        raw_risk = threat_signal + anomaly_signal + confidence_modifier + anomaly_flag_bonus
        risk_score = max(0.0, min(100.0, raw_risk))

        # ------------------------------------------------------------------
        # F. Derive severity
        # ------------------------------------------------------------------
        severity = self._score_to_severity(risk_score)

        # ------------------------------------------------------------------
        # G. Explanation
        # ------------------------------------------------------------------
        explanation = self._build_explanation(
            ml_result, risk_score, severity, anomaly_signal, confidence_modifier
        )

        # ------------------------------------------------------------------
        # H. Recommended action
        # ------------------------------------------------------------------
        recommended_action = RECOMMENDED_ACTIONS[severity]

        return RiskAssessment(
            risk_score=round(risk_score, 2),
            severity=severity,
            threat_type=ml_result.threat_type,
            confidence=ml_result.classifier_confidence,
            anomaly_score=ml_result.anomaly_score,
            is_anomaly=ml_result.is_anomaly,
            risk_factors=factors,
            explanation=explanation,
            recommended_action=recommended_action,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_severity(risk_score: float) -> Severity:
        """Map a numeric risk_score to its Severity band. Always deterministic."""
        for threshold, sev in SEVERITY_THRESHOLDS:
            if risk_score >= threshold:
                return sev
        return Severity.LOW

    @staticmethod
    def _build_explanation(
        ml_result: UnifiedMLResult,
        risk_score: float,
        severity: Severity,
        anomaly_signal: float,
        confidence_modifier: float,
    ) -> str:
        """
        Construct a deterministic human-readable explanation string.
        No LLM is used. Every sentence corresponds to an actual input value.
        """
        parts = [
            f"Traffic was classified as '{ml_result.threat_type}' "
            f"with classifier confidence {ml_result.classifier_confidence:.1%}."
        ]

        if ml_result.anomaly_score >= 0.7:
            parts.append(
                f"The IsolationForest anomaly score ({ml_result.anomaly_score:.4f}) "
                "is elevated, indicating the flow deviates significantly from the NORMAL baseline."
            )
        elif ml_result.anomaly_score >= 0.4:
            parts.append(
                f"The IsolationForest anomaly score ({ml_result.anomaly_score:.4f}) "
                "is moderately elevated."
            )
        else:
            parts.append(
                f"The IsolationForest anomaly score ({ml_result.anomaly_score:.4f}) "
                "is low; the flow is behaviorally close to the NORMAL baseline."
            )

        if ml_result.is_anomaly:
            parts.append("The flow was additionally flagged as a statistical outlier by IsolationForest.")

        if confidence_modifier > 0:
            parts.append(
                f"High classifier confidence amplifies the threat signal by {confidence_modifier:+.1f} points."
            )
        elif confidence_modifier < 0:
            parts.append(
                f"Low classifier confidence dampens the threat signal by {confidence_modifier:+.1f} points."
            )

        parts.append(
            f"Final risk score: {risk_score:.1f}/100 — {severity.value} severity."
        )

        return " ".join(parts)


# ---------------------------------------------------------------------------
# Module-level singleton for convenience import
# ---------------------------------------------------------------------------
risk_engine = RiskEngine()
