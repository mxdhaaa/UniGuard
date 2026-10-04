"""
UniGuard Deterministic Evidence Engine (Milestone 7)

Generates structured, typed SOC evidence explaining WHY a flow received its
classification and risk assessment. The engine consumes existing inputs and
produces deterministic evidence without any external AI, LLMs, or network calls.
"""

from __future__ import annotations

import hashlib
from typing import List, Dict

from backend.app.schemas.traffic import DirectionalFlowRecord, FeatureVector
from backend.app.schemas.ml import UnifiedMLResult
from backend.app.schemas.risk import RiskAssessment, Severity
from backend.app.schemas.evidence import (
    EvidenceAssessment,
    EvidenceItem,
    EvidenceCategory,
    TopFeature,
)
from backend.app.core.feature_engine import FeatureEngine
from backend.app.core.preprocessing import FEATURE_NAMES


class EvidenceEngine:
    """
    Deterministic Evidence Engine mapping flow features and ML outputs to
    explainable, SOC-friendly structured evidence.
    """

    def __init__(self):
        self.feature_engine = FeatureEngine()

    def assess(
        self,
        flow: DirectionalFlowRecord,
        ml_result: UnifiedMLResult,
        risk_assessment: RiskAssessment,
    ) -> EvidenceAssessment:
        """
        Produce a deterministic EvidenceAssessment from the provided inputs.
        Does not mutate any inputs.
        """
        # Re-extract the unscaled raw feature vector for readable threshold analysis
        features = self.feature_engine.extract_features(flow, context_flows=None)

        evidence_items: List[EvidenceItem] = []
        supporting_signals: List[str] = []
        contradictory_signals: List[str] = []

        # ------------------------------------------------------------------
        # 1. Classification Evidence
        # ------------------------------------------------------------------
        evidence_items.append(
            EvidenceItem(
                evidence_id=self._hash(f"{flow.flow_id}-class"),
                category=EvidenceCategory.THREAT_CLASSIFICATION,
                title=f"Classification: {ml_result.threat_type}",
                description=f"Random Forest classified this flow as {ml_result.threat_type} with {ml_result.classifier_confidence:.2%} confidence.",
                value=ml_result.threat_type,
                strength=ml_result.classifier_confidence,
                source="RandomForest",
                severity=risk_assessment.severity,
            )
        )
        supporting_signals.append(f"Predicted class is {ml_result.threat_type}")

        if ml_result.classifier_confidence > 0.8:
            evidence_items.append(
                EvidenceItem(
                    evidence_id=self._hash(f"{flow.flow_id}-conf"),
                    category=EvidenceCategory.MODEL_CONFIDENCE,
                    title="High Classifier Confidence",
                    description="The classifier model demonstrates high confidence in its prediction.",
                    value=ml_result.classifier_confidence,
                    strength=ml_result.classifier_confidence,
                    source="RandomForest",
                    severity=Severity.MEDIUM,
                )
            )

        # ------------------------------------------------------------------
        # 2. Anomaly Evidence
        # ------------------------------------------------------------------
        if ml_result.is_anomaly:
            evidence_items.append(
                EvidenceItem(
                    evidence_id=self._hash(f"{flow.flow_id}-anom-flag"),
                    category=EvidenceCategory.ANOMALY_SIGNAL,
                    title="Statistical Outlier",
                    description="IsolationForest explicitly flagged this flow as an outlier compared to the NORMAL baseline.",
                    value=ml_result.anomaly_score,
                    strength=ml_result.anomaly_score,
                    source="IsolationForest",
                    severity=Severity.HIGH,
                )
            )
            if ml_result.threat_type == "NORMAL":
                contradictory_signals.append(
                    "Signal tension: Flow classified as NORMAL but flagged as a statistical outlier."
                )
            else:
                supporting_signals.append("Anomaly detector corroborates suspicious classification.")
        else:
            if ml_result.anomaly_score > 0.6:
                # High score, but flag is false
                evidence_items.append(
                    EvidenceItem(
                        evidence_id=self._hash(f"{flow.flow_id}-anom-high-noflag"),
                        category=EvidenceCategory.ANOMALY_SIGNAL,
                        title="Elevated Anomaly Score (No Outlier Flag)",
                        description="IsolationForest produced an elevated anomaly score, although the configured anomaly decision threshold did not classify the flow as a strict outlier.",
                        value=ml_result.anomaly_score,
                        strength=ml_result.anomaly_score,
                        source="IsolationForest",
                        severity=Severity.MEDIUM,
                    )
                )
                if ml_result.threat_type != "NORMAL":
                    supporting_signals.append("Elevated anomaly score provides weak support for suspicious classification.")
            else:
                # Low score, no flag
                if ml_result.threat_type != "NORMAL":
                    contradictory_signals.append(
                        "Signal tension: Flow classified as suspicious but anomaly score indicates it is close to the NORMAL baseline."
                    )

        # ------------------------------------------------------------------
        # 3. Risk Assessment Evidence
        # ------------------------------------------------------------------
        evidence_items.append(
            EvidenceItem(
                evidence_id=self._hash(f"{flow.flow_id}-risk"),
                category=EvidenceCategory.RISK_ASSESSMENT,
                title=f"Risk Engine: {risk_assessment.severity.value}",
                description=risk_assessment.explanation,
                value=risk_assessment.risk_score,
                strength=risk_assessment.risk_score / 100.0,
                source="RiskEngine",
                severity=risk_assessment.severity,
            )
        )

        # ------------------------------------------------------------------
        # 4. Feature-Based Evidence (Deterministic Thresholds)
        # ------------------------------------------------------------------
        self._evaluate_features(flow, features, evidence_items, supporting_signals)

        # ------------------------------------------------------------------
        # 5. Top Feature Importances
        # ------------------------------------------------------------------
        top_features: List[TopFeature] = []
        if ml_result.feature_importances:
            sorted_feats = sorted(
                ml_result.feature_importances.items(),
                key=lambda item: item[1],
                reverse=True
            )
            # Pick up to top 3 non-zero
            for fname, imp in sorted_feats:
                if imp > 0 and len(top_features) < 3:
                    top_features.append(TopFeature(feature_name=fname, importance=round(imp, 6)))

        # ------------------------------------------------------------------
        # 6. Summary Generation
        # ------------------------------------------------------------------
        summary = self._build_summary(
            ml_result.threat_type,
            ml_result.classifier_confidence,
            risk_assessment.severity,
            len(contradictory_signals) > 0,
        )

        # ------------------------------------------------------------------
        # 7. Limitations
        # ------------------------------------------------------------------
        limitations = [
            "Single-flow analysis only; no temporal correlation across multiple flows.",
            "Synthetic traffic evaluation; ML outputs are not proof of actual compromise.",
            "No packet payload inspection was performed (Layer 3/4 metadata only).",
            "No external reputation or Threat Intelligence feeds were consulted.",
            "Evidence strength indicates deterministic signal presence, not a probability of compromise."
        ]
        if not top_features:
            limitations.append("Feature importances were all zero or unavailable from the ML model.")

        return EvidenceAssessment(
            evidence_id=self._hash(f"{flow.flow_id}-assessment"),
            flow_id=flow.flow_id,
            threat_type=ml_result.threat_type,
            risk_score=risk_assessment.risk_score,
            severity=risk_assessment.severity,
            summary=summary,
            evidence_items=evidence_items,
            top_features=top_features,
            supporting_signals=supporting_signals,
            contradictory_signals=contradictory_signals,
            limitations=limitations,
        )

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _hash(self, text: str) -> str:
        """Create a short deterministic ID."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]

    def _evaluate_features(
        self,
        flow: DirectionalFlowRecord,
        features: FeatureVector,
        evidence_items: List[EvidenceItem],
        supporting_signals: List[str]
    ) -> None:
        """Evaluate raw feature vector against explainable SOC thresholds."""

        # Rate behavior
        if features.packets_per_second > 500:
            evidence_items.append(
                EvidenceItem(
                    evidence_id=self._hash(f"{flow.flow_id}-rate"),
                    category=EvidenceCategory.RATE_BEHAVIOR,
                    title="High Packet Rate",
                    description=f"Flow observed {features.packets_per_second:.2f} packets per second, indicating rapid transmission.",
                    value=features.packets_per_second,
                    strength=min(1.0, features.packets_per_second / 2000.0),
                    source="FeatureEngine",
                    severity=Severity.HIGH,
                    feature_name="packets_per_second",
                )
            )
            supporting_signals.append("High packet transmission rate observed.")

        # Diversity & Scanning behavior
        if features.unique_destination_count > 5:
            evidence_items.append(
                EvidenceItem(
                    evidence_id=self._hash(f"{flow.flow_id}-dest-div"),
                    category=EvidenceCategory.DESTINATION_DIVERSITY,
                    title="High Destination Diversity",
                    description=f"Flow targeted {features.unique_destination_count} unique internal destinations, characteristic of sweeping behavior.",
                    value=features.unique_destination_count,
                    strength=min(1.0, features.unique_destination_count / 20.0),
                    source="FeatureEngine",
                    severity=Severity.HIGH,
                    feature_name="unique_destination_count",
                )
            )
            supporting_signals.append("Multiple unique destinations targeted.")

        if features.port_diversity > 0.8:
            evidence_items.append(
                EvidenceItem(
                    evidence_id=self._hash(f"{flow.flow_id}-port-div"),
                    category=EvidenceCategory.PORT_BEHAVIOR,
                    title="High Port Diversity",
                    description=f"Port diversity metric is {features.port_diversity:.4f}, indicating traffic spanning many different ports.",
                    value=features.port_diversity,
                    strength=features.port_diversity,
                    source="FeatureEngine",
                    severity=Severity.MEDIUM,
                    feature_name="port_diversity",
                )
            )
            supporting_signals.append("High port diversity indicates possible port scanning.")

        # Burst behavior
        if features.burst_score > 0.6:
            evidence_items.append(
                EvidenceItem(
                    evidence_id=self._hash(f"{flow.flow_id}-burst"),
                    category=EvidenceCategory.TRAFFIC_BEHAVIOR,
                    title="High Burst Behavior",
                    description=f"Inter-arrival times show significant clustering (burst_score={features.burst_score:.4f}), common in beaconing or automated exfiltration.",
                    value=features.burst_score,
                    strength=features.burst_score,
                    source="FeatureEngine",
                    severity=Severity.MEDIUM,
                    feature_name="burst_score",
                )
            )
            supporting_signals.append("Traffic exhibits highly bursty/clustered transmission intervals.")

    def _build_summary(
        self,
        threat_type: str,
        confidence: float,
        severity: Severity,
        has_tension: bool
    ) -> str:
        """Construct a deterministic summary string."""
        conf_str = "high" if confidence >= 0.8 else "moderate" if confidence >= 0.5 else "low"
        
        parts = [
            f"Flow was classified as {threat_type} with {conf_str} classifier confidence."
        ]
        
        if has_tension:
            parts.append("There is signal tension between the ML classifier and the anomaly detector.")
        else:
            parts.append("Supporting behavioral signals generally corroborate the ML outputs.")
            
        parts.append(f"The risk engine assigned {severity.value} severity.")
        
        return " ".join(parts)


# Singleton
evidence_engine = EvidenceEngine()
