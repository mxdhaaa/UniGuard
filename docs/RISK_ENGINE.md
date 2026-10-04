# UniGuard Risk Engine

## Purpose

The Risk Engine converts the ML inference output (`UnifiedMLResult`) from Milestone 5 into a structured, explainable SOC risk assessment (`RiskAssessment`). It is entirely deterministic — the same input always produces the same output — and requires no external APIs, network calls, or LLMs.

> **Important:** The risk score is a deterministic heuristic aggregation of ML outputs. It is NOT itself a machine-learned probability of compromise.

> **Synthetic-data limitation:** The Milestone 5 ML models were trained and validated on synthetic data with distinct per-class behavioral distributions. The 100% validation accuracy reflects synthetic class separability and does NOT establish real-world threat detection performance on actual network traffic.

---

## Inputs

| Field | Type | Source |
|---|---|---|
| `threat_type` | `str` | RandomForest predicted class |
| `classifier_confidence` | `float [0,1]` | Max class probability |
| `anomaly_score` | `float [0,1]` | Normalized IsolationForest score |
| `is_anomaly` | `bool` | IsolationForest outlier flag |
| `class_probabilities` | `Dict[str, float]` | Full probability distribution |
| `feature_importances` | `Dict[str, float]` | RF global feature importances |

---

## Outputs (`RiskAssessment`)

| Field | Type | Description |
|---|---|---|
| `risk_score` | `float [0,100]` | Deterministic aggregate risk score |
| `severity` | `Severity` | SOC severity band |
| `threat_type` | `str` | Preserved from ML result |
| `confidence` | `float` | Preserved from ML result |
| `anomaly_score` | `float` | Preserved from ML result |
| `is_anomaly` | `bool` | Preserved from ML result |
| `risk_factors` | `List[RiskFactor]` | Traceable contributors to score |
| `explanation` | `str` | Deterministic human-readable summary |
| `recommended_action` | `str` | SOC advisory for this severity |

---

## Formula

```
risk_score = clamp(
    threat_signal + anomaly_signal + confidence_modifier + anomaly_flag_bonus,
    0, 100
)
```

### Component Definitions

| Component | Formula | Max Value |
|---|---|---|
| `threat_signal` | `THREAT_BASE_WEIGHTS[threat_type] × 60` | 48 pts |
| `anomaly_signal` | `anomaly_score × 30` | 30 pts |
| `confidence_modifier` | `(classifier_confidence − 0.5) × 10` | ±5 pts |
| `anomaly_flag_bonus` | `5.0 if is_anomaly else 0.0` | 5 pts |

**Maximum possible raw score:** 48 + 30 + 5 + 5 = **88 pts** (CRITICAL)

A CRITICAL score requires both a high-risk threat type AND a high anomaly score.

---

## Threat-Type Baseline Weights

| Threat Class | Base Weight | Max Threat Signal |
|---|---|---|
| `NORMAL` | **0.00** | 0 pts |
| `OTHER_SUSPICIOUS` | 0.40 | 24 pts |
| `SCANNING_LIKE` | 0.55 | 33 pts |
| `EXFILTRATION_LIKE` | 0.70 | 42 pts |
| `BOTNET_LIKE` | 0.75 | 45 pts |
| `DOS_LIKE` | **0.80** | 48 pts |

**Design rationale:**
- `NORMAL` contributes zero threat signal; risk can still be elevated by anomaly components.
- `DOS_LIKE` is highest because availability attacks have immediate operational impact.
- `BOTNET_LIKE` and `EXFILTRATION_LIKE` are high due to persistence and data-loss impact.
- `SCANNING_LIKE` is moderate — reconnaissance is a precursor but not yet an active attack.
- `OTHER_SUSPICIOUS` is conservative — unknown pattern warrants concern but not certainty.

---

## Anomaly Contribution

- Uses `anomaly_score` from Milestone 5's IsolationForest wrapper.
- **Score direction (Milestone 5 contract):** `0.0 = normal, 1.0 = highly anomalous`.
- Weight: **30 points** at `anomaly_score = 1.0`.
- This means an anomalous `NORMAL` classification can still reach **MEDIUM** severity (score ≈ 30).
- An anomalous `DOS_LIKE` with full anomaly can reach ≈ 83 points (CRITICAL).

---

## Confidence Contribution

- `confidence_delta = classifier_confidence − 0.5`
- A classifier at exactly 50% confidence contributes **zero modifier**.
- High confidence (e.g., 1.0) adds `+5 points` — amplifies the threat signal.
- Low confidence (e.g., 0.0) subtracts `−5 points` — dampens the threat signal.
- This ensures uncertain classifications are not treated as definitive.

---

## Anomaly Flag Bonus

- `+5 points` if `is_anomaly = True` (IsolationForest hard outlier flag).
- This is an independent signal from the continuous `anomaly_score`.

---

## Severity Thresholds

| Risk Score | Severity |
|---|---|
| 0 – 24 | **LOW** |
| 25 – 49 | **MEDIUM** |
| 50 – 74 | **HIGH** |
| 75 – 100 | **CRITICAL** |

The same score always produces the same severity. Thresholds are fixed constants.

---

## Score Clamping

`risk_score` is always clamped to `[0, 100]` after summation. Pydantic also enforces `ge=0, le=100` at the schema level as a second guard.

---

## Risk Factor Generation

Every `RiskFactor` object corresponds to an actual input value or deterministic calculation:

| Factor | When Present | Contribution |
|---|---|---|
| `threat_classification` | Always | `THREAT_BASE_WEIGHTS[threat_type] × 60` |
| `anomaly_score` | Always | `anomaly_score × 30` |
| `confidence_modifier` | Always | `(confidence − 0.5) × 10` |
| `anomaly_flag` | Only if `is_anomaly=True` | `+5.0` |

No hallucinated or LLM-generated factors are created.

---

## Severity → Recommended Action

| Severity | Action |
|---|---|
| LOW | Monitor traffic. No immediate action required. |
| MEDIUM | Review flow behavior and continue monitoring. Correlate related flows. |
| HIGH | Investigate source activity and correlate related flows. Escalate to Tier-2 if pattern persists. |
| CRITICAL | Prioritize investigation. Consider containment after analyst confirmation. |

These are **advisory recommendations only**. No automated blocking or containment is implemented.

---

## Limitations

1. **Synthetic training data.** The underlying ML models were trained on synthetic flows. The risk scores reflect synthetic class separability.
2. **Single-flow context.** Each assessment evaluates one flow in isolation. Temporal correlation across flows is not yet implemented.
3. **No live traffic.** The pipeline processes supplied flow records only; live packet capture belongs to a later milestone.
4. **Fixed weights.** The formula weights are heuristic constants. They have not been tuned on real threat intelligence data.
5. **Feature-level explainability.** The `feature_importances` from the RandomForest are global (Gini-based), not per-flow local explanations.
6. **No authentication.** The `/api/risk/assess` endpoint is unauthenticated. Production deployment requires authentication (later milestone).
