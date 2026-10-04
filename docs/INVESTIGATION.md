# UniGuard Investigation REST APIs (Milestone 13)

This document describes the read-only SOC Investigation REST API endpoints for UniGuard.

> **Deterministic Architecture & Inference Isolation:**
>
> 1. **Strictly Read-Only**: The endpoints under `/api/investigations/*` query existing persisted M8 records. They do not create, modify, or delete any database rows.
> 2. **No Dynamic Inference**: These APIs **do not** rerun ML classification, anomaly scoring, the Risk Engine, or the Evidence Engine.
> 3. **No External Dependencies**: No LLMs, external threat-intelligence services, WHOIS lookups, or external AI APIs are invoked.
> 4. **No Packet Payload Inspection**: Only persisted 5-tuple flow metadata and statistical features are inspected; raw packet payloads are never stored or exposed.

---

## Base URL
* Prefix: `/api/investigations`
* Full Base URL (local): `http://127.0.0.1:8000/api/investigations`

---

## 1. Flow Investigation

### `GET /api/investigations/flows/{flow_id}`
Retrieves a complete investigation package for a specific traffic flow, assembling the flow telemetry, 16 canonical features, persisted ML classification, risk assessment, explainability evidence, deterministic findings, chronological evidence timeline, factual summary, and SOC limitations.

* **Method**: `GET`
* **Path Parameters**:
  * `flow_id` (string): Unique identifier of the traffic flow to investigate.
* **Error States**:
  * `404 Not Found`: Returned if `flow_id` does not exist in the database.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
  "subject": {
    "investigation_id": "inv-flow_1234567890",
    "flow_id": "flow_1234567890",
    "alert_id": "alert_9876543210"
  },
  "flow": {
    "flow_id": "flow_1234567890",
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.1",
    "source_port": 49152,
    "destination_port": 80,
    "protocol": "TCP",
    "duration": 1.25,
    "packet_count": 250,
    "byte_count": 150000,
    "feature_schema_version": "1.0",
    "timestamp": "2026-10-04T12:00:00Z",
    "created_at": "2026-10-04T12:00:05.123456+00:00"
  },
  "features": {
    "flow_duration": 1.25,
    "packet_count": 250.0,
    "byte_count": 150000.0,
    "packets_per_second": 200.0,
    "bytes_per_second": 120000.0,
    "average_packet_size": 600.0,
    "packet_size_std": 45.2,
    "unique_destination_count": 1.0,
    "unique_destination_port_count": 1.0,
    "destination_port_entropy": 0.0,
    "packet_size_entropy": 0.5,
    "burst_score": 0.8,
    "source_activity_rate": 200.0,
    "destination_diversity": 0.0,
    "port_diversity": 0.0,
    "protocol_indicator": 1.0,
    "feature_schema_version": "1.0"
  },
  "ml_assessment": {
    "flow_id": "flow_1234567890",
    "threat_type": "DOS_LIKE",
    "classifier_confidence": 0.94,
    "anomaly_score": 0.78,
    "is_anomaly": true,
    "model_version": "1.0.0",
    "class_probabilities": { "NORMAL": 0.06, "DOS_LIKE": 0.94 },
    "feature_importances": { "packets_per_second": 0.35, "bytes_per_second": 0.25 }
  },
  "risk_assessment": {
    "flow_id": "flow_1234567890",
    "risk_score": 68.5,
    "severity": "HIGH",
    "threat_type": "DOS_LIKE",
    "confidence": 0.94,
    "anomaly_score": 0.78,
    "is_anomaly": true,
    "explanation": "Flow exhibits characteristics consistent with high-rate denial of service.",
    "recommended_action": "Apply rate-limiting or firewall drop rule for source IP 192.168.1.100.",
    "risk_factors": [
      {
        "factor": "HIGH_PACKET_RATE",
        "contribution": 35.0,
        "description": "Flow packet rate exceeds 150 pps baseline."
      }
    ]
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
    },
    {
      "finding_id": "finding-anom-flow_1234567890",
      "category": "ANOMALY",
      "title": "Statistical Anomaly Detected",
      "description": "IsolationForest detector flagged flow as an outlier with anomaly score 0.78.",
      "severity": "HIGH",
      "source": "AnomalyDetector"
    },
    {
      "finding_id": "finding-risk-flow_1234567890",
      "category": "RISK",
      "title": "SOC Risk Assessment: HIGH",
      "description": "Deterministic risk score evaluated at 68.5 (HIGH). Flow exhibits characteristics consistent with high-rate denial of service.",
      "severity": "HIGH",
      "source": "RiskEngine"
    },
    {
      "finding_id": "finding-traffic-flow_1234567890",
      "category": "TRAFFIC_BEHAVIOR",
      "title": "Unidirectional Flow Profile",
      "description": "Flow from 192.168.1.100:49152 to 10.0.0.1:80 (TCP) generated 250 packets and 150000 bytes over 1.25s.",
      "severity": "LOW",
      "source": "FlowProcessor"
    }
  ],
  "timeline": [
    {
      "timestamp": "2026-10-04T12:00:00Z",
      "event_type": "FLOW_OBSERVED",
      "title": "Unidirectional Flow Observed",
      "description": "Traffic flow flow_1234567890 observed from 192.168.1.100:49152 to 10.0.0.1:80 (TCP).",
      "severity": "LOW",
      "source": "FlowCollector"
    },
    {
      "timestamp": "2026-10-04T12:00:05.123456+00:00",
      "event_type": "ALERT_GENERATED",
      "title": "Security Alert Raised: DOS_LIKE",
      "description": "High risk DOS_LIKE traffic detected from 192.168.1.100",
      "severity": "HIGH",
      "source": "AlertManager"
    }
  ],
  "summary": "Flow flow_1234567890 was classified as DOS_LIKE with a risk score of 68.5 and severity HIGH. Classifier confidence was 0.94. The anomaly detector flagged the flow as an outlier with an anomaly score of 0.78. Observed 5-tuple: 192.168.1.100:49152 -> 10.0.0.1:80 (TCP), transmitting 250 packets (150000 bytes) over 1.25s. Security alert alert_9876543210 was generated with status OPEN and severity HIGH.",
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

## 2. Alert Investigation

### `GET /api/investigations/alerts/{alert_id}`
Retrieves a complete investigation package initiated from an existing SOC alert. Looks up the parent flow and aggregates all associated ML, risk, and evidence records.

* **Method**: `GET`
* **Path Parameters**:
  * `alert_id` (string): Unique identifier of the security alert.
* **Error States**:
  * `404 Not Found`: Returned if `alert_id` does not exist in the database.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
  Same structure as Flow Investigation, with `subject.investigation_id` set to `inv-alert-{alert_id}` and `subject.alert_id` set to the queried alert ID.
