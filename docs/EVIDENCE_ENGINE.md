# UniGuard Evidence Engine

## Purpose

The Evidence Engine (Milestone 7) provides the explainability layer for the UniGuard platform. It consumes the deterministic outputs from the traffic feature extraction, ML inference, and risk assessment engines, and translates them into a structured, human-readable SOC `EvidenceAssessment`. 

> **Important Limitation:** The Evidence Engine explains deterministic observations already produced by the traffic feature, ML, and risk layers. It does not independently prove malicious activity.

> **Evidence Strength Semantics:** Evidence strength indicates how strongly the available deterministic signal supports the described observation. It is NOT a probability of compromise.

---

## Architecture

The Evidence Engine sits at the end of the deterministic analysis pipeline:

`DirectionalFlowRecord` → `FeatureEngine` → `ML Inference` → `RiskEngine` → **`EvidenceEngine`** → `EvidenceAssessment`

The engine does not mutate any of its inputs. It strictly consumes them to generate evidence items.

---

## Input Contracts

The `EvidenceEngine.assess()` method requires:
1. `flow: DirectionalFlowRecord`: The raw flow metadata.
2. `ml_result: UnifiedMLResult`: The output from the Milestone 5 ML pipeline.
3. `risk_assessment: RiskAssessment`: The output from the Milestone 6 Risk Engine.

---

## Output Contracts (`EvidenceAssessment`)

The resulting assessment contains:
- **`summary`**: A generated deterministic human-readable summary.
- **`evidence_items`**: A list of `EvidenceItem` objects mapping directly to specific features or ML outcomes.
- **`top_features`**: Up to the top 3 contributing canonical features from the RandomForest feature importances.
- **`supporting_signals`**: Signals that strongly corroborate the primary threat classification.
- **`contradictory_signals`**: Signals exhibiting tension (e.g., NORMAL classification but high anomaly score).
- **`limitations`**: Relevant analytical limitations for the SOC analyst to consider.

---

## Evidence Categories

All generated evidence belongs to a deterministic category:
- `THREAT_CLASSIFICATION`: Extracted from RandomForest prediction.
- `ANOMALY_SIGNAL`: Extracted from IsolationForest score and outlier flag.
- `TRAFFIC_BEHAVIOR`: Based on inter-arrival times and burst scores.
- `DESTINATION_DIVERSITY`: Based on unique destination counts.
- `PORT_BEHAVIOR`: Based on port entropy and diversity.
- `PACKET_BEHAVIOR`: Based on packet sizes and variance.
- `RATE_BEHAVIOR`: Based on packets/bytes per second.
- `MODEL_CONFIDENCE`: Extracted from classification probability distributions.
- `RISK_ASSESSMENT`: Extracted from the RiskEngine severity and score.

---

## Feature Evidence Generation

Evidence items are generated conditionally when specific thresholds are breached. These thresholds are defined deterministically in code. 

**Examples:**
- *High Packet Rate*: `packets_per_second > 500`
- *High Destination Diversity*: `unique_destination_count > 5`
- *High Port Diversity*: `port_diversity > 0.8`
- *High Burst Behavior*: `burst_score > 0.6`

If a threshold is not breached, no evidence item is fabricated.

---

## Model Evidence Logic

- **Classification**: Generates an evidence item detailing the predicted threat type and the model's confidence. High confidence (>0.8) yields an additional supporting evidence item.
- **Anomaly**: Converts the `anomaly_score` and `is_anomaly` flag into evidence. The contract is strictly adhered to: `higher score = more anomalous`. 
- **Risk**: Consumes the final `risk_score` and `severity` without recalculating them.

---

## Supporting vs Signal-Tension Logic

The engine explicitly separates signals into supporting vs contradictory buckets to assist analysts.

- **Supporting Signals**: Examples include high confidence aligning with a suspicious classification, or an anomaly flag corroborating a known threat pattern.
- **Signal Tension**: Occurs when signals conflict, such as a flow classified as `NORMAL` being flagged as a statistical outlier by the anomaly detector, or a flow classified as suspicious having a very low anomaly score.

---

## Limitations

Every assessment carries standard deterministic limitations to ensure analysts do not over-rely on the heuristic output:
1. Single-flow analysis only; no temporal correlation across multiple flows.
2. Synthetic traffic evaluation; ML outputs are not proof of actual compromise.
3. No packet payload inspection was performed (Layer 3/4 metadata only).
4. No external reputation or Threat Intelligence feeds were consulted.
5. Evidence strength indicates deterministic signal presence, not a probability of compromise.
