"""
Tests for the Milestone 6 Risk Engine.

Tests cover all 20 required scenarios plus the end-to-end integration test.
No external services are called. UnifiedMLResult objects are constructed inline.
"""

from __future__ import annotations

import math
import pytest

from backend.app.schemas.ml import UnifiedMLResult
from backend.app.schemas.risk import RiskAssessment, RiskFactor, Severity
from backend.app.core.risk_engine import (
    RiskEngine,
    THREAT_BASE_WEIGHTS,
    THREAT_WEIGHT_SCALE,
    ANOMALY_WEIGHT,
    CONFIDENCE_WEIGHT,
    SEVERITY_THRESHOLDS,
    RECOMMENDED_ACTIONS,
)

KNOWN_CLASSES = [
    "NORMAL", "SCANNING_LIKE", "DOS_LIKE",
    "BOTNET_LIKE", "EXFILTRATION_LIKE", "OTHER_SUSPICIOUS",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ml_result(
    threat_type: str = "NORMAL",
    classifier_confidence: float = 0.80,
    anomaly_score: float = 0.10,
    is_anomaly: bool = False,
) -> UnifiedMLResult:
    """Build a synthetic UnifiedMLResult without calling any ML model."""
    probs = {c: (classifier_confidence if c == threat_type else (1 - classifier_confidence) / 5)
             for c in KNOWN_CLASSES}
    importances = {
        "flow_duration": 0.05, "packet_count": 0.08, "byte_count": 0.07,
        "packets_per_second": 0.09, "bytes_per_second": 0.08,
        "average_packet_size": 0.06, "packet_size_std": 0.05,
        "unique_destination_count": 0.07, "unique_destination_port_count": 0.07,
        "destination_port_entropy": 0.07, "packet_size_entropy": 0.06,
        "burst_score": 0.06, "source_activity_rate": 0.06,
        "destination_diversity": 0.05, "port_diversity": 0.05,
        "protocol_indicator": 0.03,
    }
    return UnifiedMLResult(
        threat_type=threat_type,
        class_probabilities=probs,
        classifier_confidence=classifier_confidence,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        model_version="0.1.0",
        feature_importances=importances,
    )


engine = RiskEngine()


# ---------------------------------------------------------------------------
# 1. NORMAL low-risk input
# ---------------------------------------------------------------------------

def test_normal_low_risk():
    """NORMAL classification + low anomaly should produce LOW severity."""
    result = _make_ml_result("NORMAL", classifier_confidence=0.90, anomaly_score=0.05)
    assessment = engine.assess(result)
    assert assessment.risk_score < 25.0, f"Expected LOW risk, got {assessment.risk_score}"
    assert assessment.severity == Severity.LOW


# ---------------------------------------------------------------------------
# 2. High-confidence SCANNING_LIKE
# ---------------------------------------------------------------------------

def test_scanning_like_high_confidence():
    """High-confidence SCANNING_LIKE should produce >= MEDIUM severity."""
    result = _make_ml_result("SCANNING_LIKE", classifier_confidence=0.95, anomaly_score=0.60)
    assessment = engine.assess(result)
    assert assessment.risk_score >= 25.0
    assert assessment.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# 3. DOS_LIKE
# ---------------------------------------------------------------------------

def test_dos_like_elevated_risk():
    """DOS_LIKE has one of the highest baseline weights — should be HIGH or CRITICAL."""
    result = _make_ml_result("DOS_LIKE", classifier_confidence=0.85, anomaly_score=0.70)
    assessment = engine.assess(result)
    assert assessment.risk_score >= 50.0
    assert assessment.severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# 4. BOTNET_LIKE
# ---------------------------------------------------------------------------

def test_botnet_like_elevated_risk():
    """BOTNET_LIKE should produce >= HIGH severity at reasonable confidence."""
    result = _make_ml_result("BOTNET_LIKE", classifier_confidence=0.80, anomaly_score=0.65)
    assessment = engine.assess(result)
    assert assessment.risk_score >= 50.0


# ---------------------------------------------------------------------------
# 5. EXFILTRATION_LIKE
# ---------------------------------------------------------------------------

def test_exfiltration_like_elevated_risk():
    """EXFILTRATION_LIKE should produce >= HIGH severity at reasonable confidence."""
    result = _make_ml_result("EXFILTRATION_LIKE", classifier_confidence=0.85, anomaly_score=0.70)
    assessment = engine.assess(result)
    assert assessment.risk_score >= 50.0


# ---------------------------------------------------------------------------
# 6. OTHER_SUSPICIOUS
# ---------------------------------------------------------------------------

def test_other_suspicious_medium_risk():
    """OTHER_SUSPICIOUS should produce at least MEDIUM severity."""
    result = _make_ml_result("OTHER_SUSPICIOUS", classifier_confidence=0.75, anomaly_score=0.50)
    assessment = engine.assess(result)
    assert assessment.risk_score >= 25.0


# ---------------------------------------------------------------------------
# 7. High anomaly score
# ---------------------------------------------------------------------------

def test_high_anomaly_score_elevates_risk():
    """Even a NORMAL classification with very high anomaly_score should elevate risk."""
    low_anomaly = engine.assess(_make_ml_result("NORMAL", anomaly_score=0.05))
    high_anomaly = engine.assess(_make_ml_result("NORMAL", anomaly_score=1.0))
    assert high_anomaly.risk_score > low_anomaly.risk_score
    # A NORMAL + full anomaly can reach MEDIUM territory
    assert high_anomaly.risk_score >= 25.0


# ---------------------------------------------------------------------------
# 8. Low anomaly score
# ---------------------------------------------------------------------------

def test_low_anomaly_score_keeps_risk_low():
    """NORMAL + very low anomaly_score should remain LOW."""
    result = _make_ml_result("NORMAL", classifier_confidence=0.95, anomaly_score=0.01)
    assessment = engine.assess(result)
    assert assessment.severity == Severity.LOW


# ---------------------------------------------------------------------------
# 9. High classifier confidence amplifies risk
# ---------------------------------------------------------------------------

def test_high_confidence_amplifies_risk():
    """Higher confidence should produce a higher risk score for the same threat type."""
    low_conf = engine.assess(_make_ml_result("SCANNING_LIKE", classifier_confidence=0.51))
    high_conf = engine.assess(_make_ml_result("SCANNING_LIKE", classifier_confidence=1.0))
    assert high_conf.risk_score > low_conf.risk_score


# ---------------------------------------------------------------------------
# 10. Low classifier confidence dampens risk
# ---------------------------------------------------------------------------

def test_low_confidence_dampens_risk():
    """Very low classifier confidence should reduce the risk score relative to high confidence."""
    low_conf = engine.assess(_make_ml_result("DOS_LIKE", classifier_confidence=0.01, anomaly_score=0.0))
    high_conf = engine.assess(_make_ml_result("DOS_LIKE", classifier_confidence=1.0, anomaly_score=0.0))
    assert high_conf.risk_score > low_conf.risk_score


# ---------------------------------------------------------------------------
# 11. Score always in [0, 100]
# ---------------------------------------------------------------------------

def test_score_always_in_unit_range():
    """risk_score must stay in [0, 100] for all six threat types at extremes."""
    for cls in KNOWN_CLASSES:
        for conf in (0.0, 0.5, 1.0):
            for anom in (0.0, 0.5, 1.0):
                result = _make_ml_result(cls, classifier_confidence=conf, anomaly_score=anom)
                assessment = engine.assess(result)
                assert 0.0 <= assessment.risk_score <= 100.0, (
                    f"Out-of-range score {assessment.risk_score} for "
                    f"cls={cls}, conf={conf}, anom={anom}"
                )


# ---------------------------------------------------------------------------
# 12. Deterministic output
# ---------------------------------------------------------------------------

def test_deterministic_output():
    """Same input must produce identical output on every call."""
    result = _make_ml_result("BOTNET_LIKE", classifier_confidence=0.82, anomaly_score=0.74)
    a1 = engine.assess(result)
    a2 = engine.assess(result)
    assert a1.risk_score == a2.risk_score
    assert a1.severity == a2.severity
    assert a1.explanation == a2.explanation


# ---------------------------------------------------------------------------
# 13. Severity boundaries
# ---------------------------------------------------------------------------

def test_severity_boundary_low_to_medium():
    """risk_score of 25.0 must be MEDIUM."""
    assert RiskEngine._score_to_severity(25.0) == Severity.MEDIUM


def test_severity_boundary_medium_to_high():
    """risk_score of 50.0 must be HIGH."""
    assert RiskEngine._score_to_severity(50.0) == Severity.HIGH


def test_severity_boundary_high_to_critical():
    """risk_score of 75.0 must be CRITICAL."""
    assert RiskEngine._score_to_severity(75.0) == Severity.CRITICAL


def test_severity_boundary_just_below_medium():
    """risk_score of 24.99 must be LOW."""
    assert RiskEngine._score_to_severity(24.99) == Severity.LOW


def test_severity_boundary_just_below_high():
    """risk_score of 49.99 must be MEDIUM."""
    assert RiskEngine._score_to_severity(49.99) == Severity.MEDIUM


def test_severity_boundary_zero():
    """risk_score of 0.0 must be LOW."""
    assert RiskEngine._score_to_severity(0.0) == Severity.LOW


def test_severity_boundary_hundred():
    """risk_score of 100.0 must be CRITICAL."""
    assert RiskEngine._score_to_severity(100.0) == Severity.CRITICAL


# ---------------------------------------------------------------------------
# 14. Risk factors exist
# ---------------------------------------------------------------------------

def test_risk_factors_present():
    """RiskAssessment must always contain at least one risk factor."""
    assessment = engine.assess(_make_ml_result("BOTNET_LIKE"))
    assert len(assessment.risk_factors) >= 1


def test_risk_factors_are_typed():
    """Every risk factor must be a RiskFactor instance."""
    assessment = engine.assess(_make_ml_result("DOS_LIKE"))
    for rf in assessment.risk_factors:
        assert isinstance(rf, RiskFactor)


# ---------------------------------------------------------------------------
# 15. Risk factor contributions are numeric
# ---------------------------------------------------------------------------

def test_risk_factor_contributions_are_finite():
    """All risk factor contributions must be finite floats."""
    assessment = engine.assess(_make_ml_result("EXFILTRATION_LIKE", anomaly_score=0.8))
    for rf in assessment.risk_factors:
        assert isinstance(rf.contribution, (int, float))
        assert math.isfinite(rf.contribution)


def test_risk_factors_sum_near_raw_score():
    """
    The sum of risk_factor contributions should approximate the risk_score.
    (They may not be exactly equal because of clamping at the extremes.)
    """
    result = _make_ml_result("SCANNING_LIKE", classifier_confidence=0.75, anomaly_score=0.40)
    assessment = engine.assess(result)
    total_factors = sum(rf.contribution for rf in assessment.risk_factors)
    # If no clamping occurred, total_factors == risk_score; with clamping, score may be lower
    assert total_factors >= assessment.risk_score - 0.1


# ---------------------------------------------------------------------------
# 16. Explanation is deterministic
# ---------------------------------------------------------------------------

def test_explanation_is_string():
    """Explanation must be a non-empty string."""
    assessment = engine.assess(_make_ml_result("BOTNET_LIKE"))
    assert isinstance(assessment.explanation, str)
    assert len(assessment.explanation) > 0


def test_explanation_contains_threat_type():
    """Explanation must reference the predicted threat type."""
    for cls in KNOWN_CLASSES:
        result = _make_ml_result(cls)
        assessment = engine.assess(result)
        assert cls in assessment.explanation, (
            f"Explanation missing threat type '{cls}': {assessment.explanation}"
        )


def test_explanation_contains_severity():
    """Explanation must state the severity level."""
    result = _make_ml_result("DOS_LIKE", classifier_confidence=0.9, anomaly_score=0.8)
    assessment = engine.assess(result)
    assert assessment.severity.value in assessment.explanation


def test_explanation_deterministic():
    """Same input must produce the same explanation string."""
    result = _make_ml_result("EXFILTRATION_LIKE", classifier_confidence=0.88)
    e1 = engine.assess(result).explanation
    e2 = engine.assess(result).explanation
    assert e1 == e2


# ---------------------------------------------------------------------------
# 17. Recommended action matches severity
# ---------------------------------------------------------------------------

def test_recommended_action_matches_severity():
    """recommended_action must be the canonical action for the assessed severity."""
    for cls in KNOWN_CLASSES:
        result = _make_ml_result(cls)
        assessment = engine.assess(result)
        expected = RECOMMENDED_ACTIONS[assessment.severity]
        assert assessment.recommended_action == expected


def test_all_severities_have_recommended_actions():
    """Every Severity enum value must have a corresponding recommended action."""
    for sev in Severity:
        assert sev in RECOMMENDED_ACTIONS
        assert len(RECOMMENDED_ACTIONS[sev]) > 0


# ---------------------------------------------------------------------------
# 18. No external service / network dependency
# ---------------------------------------------------------------------------

def test_no_external_calls(monkeypatch):
    """RiskEngine.assess() must not make any external network calls."""
    import socket as sock_module

    def _no_connect(*args, **kwargs):
        raise AssertionError("RiskEngine made an external network call — forbidden!")

    monkeypatch.setattr(sock_module, "create_connection", _no_connect)
    # Must complete without hitting create_connection
    result = _make_ml_result("SCANNING_LIKE")
    assessment = engine.assess(result)
    assert assessment is not None


# ---------------------------------------------------------------------------
# 19. No mutation of UnifiedMLResult
# ---------------------------------------------------------------------------

def test_no_mutation_of_ml_result():
    """engine.assess() must not modify the input UnifiedMLResult."""
    result = _make_ml_result("BOTNET_LIKE", classifier_confidence=0.9, anomaly_score=0.7)
    original_threat = result.threat_type
    original_conf = result.classifier_confidence
    original_anom = result.anomaly_score

    engine.assess(result)

    assert result.threat_type == original_threat
    assert result.classifier_confidence == original_conf
    assert result.anomaly_score == original_anom


# ---------------------------------------------------------------------------
# 20. Edge values: anomaly_score and confidence at 0.0 and 1.0
# ---------------------------------------------------------------------------

def test_edge_values_zero():
    """All zero inputs should produce a valid (LOW) assessment without error."""
    result = _make_ml_result("NORMAL", classifier_confidence=0.0, anomaly_score=0.0)
    assessment = engine.assess(result)
    assert 0.0 <= assessment.risk_score <= 100.0
    assert assessment.severity == Severity.LOW


def test_edge_values_one():
    """Maximum inputs should produce a valid CRITICAL assessment without error."""
    result = _make_ml_result("DOS_LIKE", classifier_confidence=1.0, anomaly_score=1.0, is_anomaly=True)
    assessment = engine.assess(result)
    assert 0.0 <= assessment.risk_score <= 100.0
    assert assessment.severity == Severity.CRITICAL


def test_edge_confidence_zero_reduces_score():
    """confidence=0.0 means confidence_delta=-0.5; should reduce score vs confidence=0.5."""
    r_zero = engine.assess(_make_ml_result("DOS_LIKE", classifier_confidence=0.0, anomaly_score=0.5))
    r_base = engine.assess(_make_ml_result("DOS_LIKE", classifier_confidence=0.5, anomaly_score=0.5))
    assert r_zero.risk_score < r_base.risk_score


# ---------------------------------------------------------------------------
# 21. Anomalous NORMAL can exceed pure non-anomalous NORMAL
# ---------------------------------------------------------------------------

def test_anomalous_normal_exceeds_non_anomalous():
    """An anomalous NORMAL flow must score higher than a purely normal NORMAL flow."""
    normal = engine.assess(_make_ml_result("NORMAL", anomaly_score=0.0, is_anomaly=False))
    anomalous_normal = engine.assess(_make_ml_result("NORMAL", anomaly_score=1.0, is_anomaly=True))
    assert anomalous_normal.risk_score > normal.risk_score


# ---------------------------------------------------------------------------
# 22. NORMAL has lowest baseline vs. threat classes
# ---------------------------------------------------------------------------

def test_normal_has_lowest_baseline():
    """NORMAL must have a lower base weight than all other threat types."""
    normal_weight = THREAT_BASE_WEIGHTS["NORMAL"]
    for cls, w in THREAT_BASE_WEIGHTS.items():
        if cls != "NORMAL":
            assert normal_weight < w, f"NORMAL weight ({normal_weight}) not < {cls} weight ({w})"


# ---------------------------------------------------------------------------
# 23. Threat type preserved in assessment
# ---------------------------------------------------------------------------

def test_threat_type_preserved():
    """assessment.threat_type must match the input threat_type."""
    for cls in KNOWN_CLASSES:
        result = _make_ml_result(cls)
        assessment = engine.assess(result)
        assert assessment.threat_type == cls


# ---------------------------------------------------------------------------
# 24. Confidence and anomaly_score preserved in assessment
# ---------------------------------------------------------------------------

def test_confidence_and_anomaly_preserved():
    """confidence and anomaly_score in assessment must match ML result."""
    result = _make_ml_result("BOTNET_LIKE", classifier_confidence=0.77, anomaly_score=0.63)
    assessment = engine.assess(result)
    assert assessment.confidence == pytest.approx(0.77)
    assert assessment.anomaly_score == pytest.approx(0.63)


# ---------------------------------------------------------------------------
# 25. Risk API: status endpoint (no ML required)
# ---------------------------------------------------------------------------

def test_risk_api_status_endpoint():
    """GET /api/risk/status must return a valid JSON response."""
    from fastapi.testclient import TestClient
    from backend.app.main import app
    client = TestClient(app)
    response = client.get("/api/risk/status")
    assert response.status_code == 200
    data = response.json()
    assert "ml_model_state" in data
    assert "risk_engine" in data


# ---------------------------------------------------------------------------
# 26. Integration test: DirectionalFlowRecord -> ML -> Risk -> RiskAssessment
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def _ensure_models():
    """Ensure persisted models from Milestone 5 are available."""
    from backend.app.ml.model_manager import get_state, MODEL_DIR
    from backend.app.schemas.ml import ModelReadinessState
    if get_state() != ModelReadinessState.READY:
        from backend.app.ml.train import train_models
        train_models(seed=42, samples_per_class=60)
    return True


def test_end_to_end_flow_to_risk_assessment(_ensure_models):
    """
    Full pipeline integration test:
    DirectionalFlowRecord -> FeatureEngine -> ML -> RiskEngine -> RiskAssessment
    Uses persisted Milestone 5 models — no retraining inside the test.
    """
    from backend.app.schemas.traffic import DirectionalFlowRecord
    from backend.app.ml.inference import run_inference

    flow = DirectionalFlowRecord(
        flow_id="m6-integration-test-001",
        timestamp="2026-01-01T12:00:00Z",
        source_ip="10.0.0.100",
        source_port=49152,
        destination_ip="192.168.1.1",
        destination_port=443,
        protocol="TCP",
        duration=3.0,
        packet_count=15,
        byte_count=12000,
        packet_sizes=[800] * 15,
        packet_timestamps=[i * 0.2 for i in range(15)],
        inter_arrival_times=[0.2] * 14,
    )

    ml_result = run_inference(flow)
    assessment = engine.assess(ml_result)

    # Structural checks
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.risk_score <= 100.0
    assert assessment.severity in list(Severity)
    assert assessment.threat_type in KNOWN_CLASSES
    assert len(assessment.risk_factors) >= 1
    assert len(assessment.explanation) > 0
    assert len(assessment.recommended_action) > 0
    assert assessment.confidence == pytest.approx(ml_result.classifier_confidence)
    assert assessment.anomaly_score == pytest.approx(ml_result.anomaly_score)


def test_risk_api_assess_endpoint(_ensure_models):
    """
    POST /api/risk/assess with a valid DirectionalFlowRecord should return a RiskAssessment.
    Uses persisted Milestone 5 models.
    """
    from fastapi.testclient import TestClient
    from backend.app.main import app
    client = TestClient(app)

    payload = {
        "flow_id": "api-test-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "source_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_ip": "192.168.1.1",
        "destination_port": 80,
        "protocol": "TCP",
        "duration": 1.5,
        "packet_count": 10,
        "byte_count": 7500,
        "packet_sizes": [750] * 10,
        "packet_timestamps": [i * 0.15 for i in range(10)],
        "inter_arrival_times": [0.15] * 9,
    }
    response = client.post("/api/risk/assess", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "severity" in data
    assert "threat_type" in data
    assert "explanation" in data
    assert "recommended_action" in data
    assert 0.0 <= data["risk_score"] <= 100.0
