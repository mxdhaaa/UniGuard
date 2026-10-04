# UniGuard Reports REST APIs (Milestone 13)

This document describes the structured JSON reporting REST API endpoints for UniGuard.

> **Deterministic Report Generation & Integrity Guarantees:**
>
> 1. **Structured JSON Format**: All reports are output as strictly typed, validated JSON documents (`application/json`). In Milestone 13, reports are generated directly from persisted database state without generating PDF, DOCX, or CSV files.
> 2. **Strictly Read-Only**: Report endpoints do not mutate, create, or delete underlying database records.
> 3. **No New Model Inference**: Reports reflect previously persisted ML predictions, risk calculations, and evidence items. No inference, risk scoring, or evidence engines are re-executed.
> 4. **No External Lookups or LLMs**: Executive summaries and findings are compiled deterministically using deterministic string formatting from verified database fields; no external AI, LLMs, or network lookups are employed.

---

## Base URL
* Prefix: `/api/reports`
* Full Base URL (local): `http://127.0.0.1:8000/api/reports`

---

## 1. Flow Investigation Report

### `GET /api/reports/flows/{flow_id}`
Generates a formal SOC investigation report for a specific unidirectional traffic flow.

* **Method**: `GET`
* **Path Parameters**:
  * `flow_id` (string): Unique identifier of the traffic flow.
* **Error States**:
  * `404 Not Found`: If `flow_id` is not present in the database.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
  "report_id": "rep-7f893e2b-5c8e-4a92-b43d-1e4a3b8d9f10",
  "report_type": "FLOW_INVESTIGATION",
  "generated_at": "2026-10-04T12:30:00.123456+00:00",
  "subject": {
    "investigation_id": "inv-flow_1234567890",
    "flow_id": "flow_1234567890",
    "alert_id": "alert_9876543210"
  },
  "executive_summary": "Flow flow_1234567890 was classified as DOS_LIKE with a risk score of 68.5 and severity HIGH. Classifier confidence was 0.94. The anomaly detector flagged the flow as an outlier with an anomaly score of 0.78. Observed 5-tuple: 192.168.1.100:49152 -> 10.0.0.1:80 (TCP), transmitting 250 packets (150000 bytes) over 1.25s.",
  "classification": {
    "flow_id": "flow_1234567890",
    "threat_type": "DOS_LIKE",
    "classifier_confidence": 0.94,
    "anomaly_score": 0.78,
    "is_anomaly": true,
    "model_version": "1.0.0",
    "class_probabilities": { "NORMAL": 0.06, "DOS_LIKE": 0.94 },
    "feature_importances": { "packets_per_second": 0.35, "bytes_per_second": 0.25 }
  },
  "risk": {
    "flow_id": "flow_1234567890",
    "risk_score": 68.5,
    "severity": "HIGH",
    "threat_type": "DOS_LIKE",
    "confidence": 0.94,
    "anomaly_score": 0.78,
    "is_anomaly": true,
    "explanation": "Flow exhibits characteristics consistent with high-rate denial of service.",
    "recommended_action": "Apply rate-limiting or firewall drop rule for source IP 192.168.1.100.",
    "risk_factors": []
  },
  "anomaly": {
    "is_anomaly": true,
    "anomaly_score": 0.78,
    "model_version": "1.0.0"
  },
  "evidence": [
    {
      "evidence_id": "ev_001",
      "flow_id": "flow_1234567890",
      "category": "THREAT_CLASSIFICATION",
      "title": "RandomForest Threat Classification",
      "description": "Classified as DOS_LIKE with 94.0% confidence.",
      "value": "DOS_LIKE",
      "strength": 0.94,
      "source": "RandomForest",
      "severity": "HIGH",
      "feature_name": "packets_per_second"
    }
  ],
  "findings": [
    {
      "finding_id": "finding-cls-flow_1234567890",
      "category": "CLASSIFICATION",
      "title": "Threat Classification: DOS_LIKE",
      "description": "Model classified traffic flow as DOS_LIKE with confidence 0.94.",
      "severity": "HIGH",
      "source": "ThreatClassifier (1.0.0)"
    }
  ],
  "recommended_action": "Apply rate-limiting or firewall drop rule for source IP 192.168.1.100.",
  "limitations": [
    "Analysis is based on unidirectional flow telemetry.",
    "No packet payload contents are persisted or inspected by the investigation layer.",
    "Threat classification reflects the persisted model result and is not recomputed during investigation.",
    "Risk assessment reflects the persisted deterministic risk result.",
    "Evidence reflects the persisted evidence assessment.",
    "No external threat-intelligence enrichment is performed."
  ]
}
```

---

## 2. Alert Investigation Report

### `GET /api/reports/alerts/{alert_id}`
Generates a formal SOC investigation report for a specific security alert, joining the parent flow and all associated analytical records.

* **Method**: `GET`
* **Path Parameters**:
  * `alert_id` (string): Unique identifier of the alert.
* **Error States**:
  * `404 Not Found`: If `alert_id` is not present in the database.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
  Same structure as Flow Report, with `report_type` set to `"ALERT_INVESTIGATION"`, `subject.investigation_id` set to `inv-alert-{alert_id}`, and `subject.alert_id` set to the queried alert ID.
