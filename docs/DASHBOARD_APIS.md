# UniGuard Dashboard REST APIs (Milestone 12)

This document details the read-only SOC Dashboard REST API endpoints provided by UniGuard.

> **Read-Only Architecture & Inference Isolation:**
> 
> 1. **Strictly Read-Only**: All endpoints under `/api/dashboard/*` perform deterministic, read-only queries against existing persisted data in the repository/database layer. They do not insert, modify, or delete any records.
> 2. **No Dynamic Inference**: These APIs **do not** execute new ML classification, anomaly scoring, risk evaluations, or evidence synthesis. All displayed predictions, risk assessments, and evidence items reflect previously analyzed and persisted flows (Milestones 3–11 pipeline).

---

## Base URL
* Prefix: `/api/dashboard`
* Full Base URL (local): `http://127.0.0.1:8000/api/dashboard`

---

## 1. Overview Statistics

### `GET /api/dashboard/overview`
Retrieves platform-wide overview statistics for SOC operational awareness, including total flow counts, alert metrics, threat distribution, live ingestion state, and ML engine readiness.

* **Method**: `GET`
* **Query Parameters**: None
* **Empty State**:
  * Counts are `0` (`total_flows: 0`, `total_alerts: 0`, `high_alerts: 0`, `critical_alerts: 0`, `anomaly_count: 0`)
  * Distribution dictionaries are `{}`
  * `ingestion_state` reflects the actual state of the ingestion service (`"STOPPED"` or `"RUNNING"`)
  * `ml_readiness` reflects current model readiness (`"READY"`, `"NOT_TRAINED"`, or `"FAILED"`)
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
  "total_flows": 1500,
  "total_alerts": 42,
  "high_alerts": 28,
  "critical_alerts": 14,
  "anomaly_count": 65,
  "threat_type_distribution": {
    "NORMAL": 1350,
    "DOS_LIKE": 85,
    "SCANNING_LIKE": 45,
    "EXFILTRATION": 20
  },
  "severity_distribution": {
    "LOW": 1350,
    "MEDIUM": 108,
    "HIGH": 28,
    "CRITICAL": 14
  },
  "ingestion_state": "RUNNING",
  "ml_readiness": "READY"
}
```

---

## 2. Traffic Flow Exploration

### `GET /api/dashboard/flows`
Lists traffic flows with pagination and multi-parameter filtering. Returns flow metadata along with pre-computed ML classification and risk assessment summaries.

* **Method**: `GET`
* **Query Parameters**:
  | Parameter | Type | Required | Default | Description |
  |---|---|---|---|---|
  | `page` | integer | No | `1` | Page number (1-indexed, minimum: 1). |
  | `page_size` | integer | No | `20` | Items per page (minimum: 1, maximum: 100). |
  | `threat_type` | string | No | `None` | Filter by ML threat type (e.g. `DOS_LIKE`, `SCANNING_LIKE`, `NORMAL`). |
  | `severity` | string | No | `None` | Filter by severity band (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
  | `is_anomaly` | boolean | No | `None` | Filter by IsolationForest outlier flag (`true` or `false`). |
  | `source_ip` | string | No | `None` | Filter by source IP address. |
  | `destination_ip` | string | No | `None` | Filter by destination IP address. |
  | `start_time` | string | No | `None` | ISO8601 timestamp; includes flows at or after this time. |
  | `end_time` | string | No | `None` | ISO8601 timestamp; includes flows at or before this time. |

* **Ordering**: Deterministic secondary ordering: `timestamp DESC, flow_id DESC`.
* **Empty State**: `{"data": [], "meta": {"page": 1, "page_size": 20, "total_items": 0, "total_pages": 0}}`.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
  "data": [
    {
      "flow_id": "flow_1234567890",
      "timestamp": "2026-10-04T12:00:00Z",
      "source_ip": "192.168.1.100",
      "source_port": 49152,
      "destination_ip": "10.0.0.1",
      "destination_port": 80,
      "protocol": "TCP",
      "threat_type": "DOS_LIKE",
      "classifier_confidence": 0.94,
      "anomaly_score": 0.78,
      "is_anomaly": true,
      "risk_score": 68.5,
      "severity": "HIGH"
    }
  ],
  "meta": {
    "page": 1,
    "page_size": 20,
    "total_items": 1,
    "total_pages": 1
  }
}
```

---

### `GET /api/dashboard/flows/{flow_id}`
Retrieves comprehensive details for a single traffic flow, combining the base directional flow record, 16 extracted canonical features, ML inference result, deterministic risk assessment, synthesized evidence items, and associated alert (if triggered).

* **Method**: `GET`
* **Path Parameters**:
  * `flow_id` (string): Unique identifier of the flow.
* **Error States**:
  * `404 Not Found`: If `flow_id` does not exist in the database.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
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
    "flow_id": "flow_1234567890",
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
  "ml_result": {
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
  "alert": {
    "alert_id": "alert_9876543210",
    "flow_id": "flow_1234567890",
    "threat_type": "DOS_LIKE",
    "risk_score": 68.5,
    "severity": "HIGH",
    "status": "OPEN",
    "summary": "High risk DOS_LIKE traffic detected from 192.168.1.100",
    "created_at": "2026-10-04T12:00:05.123456+00:00",
    "updated_at": "2026-10-04T12:00:05.123456+00:00"
  }
}
```

---

## 3. SOC Alert Management

### `GET /api/dashboard/alerts`
Lists security alerts generated for `HIGH` and `CRITICAL` risk flows with pagination and triage filtering.

* **Method**: `GET`
* **Query Parameters**:
  | Parameter | Type | Required | Default | Description |
  |---|---|---|---|---|
  | `page` | integer | No | `1` | Page number (1-indexed, minimum: 1). |
  | `page_size` | integer | No | `20` | Items per page (minimum: 1, maximum: 100). |
  | `severity` | string | No | `None` | Filter by alert severity (`HIGH`, `CRITICAL`). |
  | `status` | string | No | `None` | Filter by workflow status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`). |
  | `threat_type` | string | No | `None` | Filter by predicted threat type. |
  | `start_time` | string | No | `None` | ISO8601 timestamp; includes alerts created at or after this time. |
  | `end_time` | string | No | `None` | ISO8601 timestamp; includes alerts created at or before this time. |

* **Ordering**: Deterministic secondary ordering: `created_at DESC, alert_id DESC`.
* **Empty State**: `{"data": [], "meta": {"page": 1, "page_size": 20, "total_items": 0, "total_pages": 0}}`.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
  "data": [
    {
      "alert_id": "alert_9876543210",
      "flow_id": "flow_1234567890",
      "threat_type": "DOS_LIKE",
      "risk_score": 68.5,
      "severity": "HIGH",
      "status": "OPEN",
      "summary": "High risk DOS_LIKE traffic detected from 192.168.1.100",
      "created_at": "2026-10-04T12:00:05.123456+00:00",
      "updated_at": "2026-10-04T12:00:05.123456+00:00"
    }
  ],
  "meta": {
    "page": 1,
    "page_size": 20,
    "total_items": 1,
    "total_pages": 1
  }
}
```

---

### `GET /api/dashboard/alerts/{alert_id}`
Retrieves complete triage context for a specific alert, joining the alert record with its parent traffic flow, ML predictions, risk assessment, and explainability evidence items.

* **Method**: `GET`
* **Path Parameters**:
  * `alert_id` (string): Unique identifier of the alert.
* **Error States**:
  * `404 Not Found`: If `alert_id` does not exist in the database.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
  "alert": {
    "alert_id": "alert_9876543210",
    "flow_id": "flow_1234567890",
    "threat_type": "DOS_LIKE",
    "risk_score": 68.5,
    "severity": "HIGH",
    "status": "OPEN",
    "summary": "High risk DOS_LIKE traffic detected from 192.168.1.100",
    "created_at": "2026-10-04T12:00:05.123456+00:00",
    "updated_at": "2026-10-04T12:00:05.123456+00:00"
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
  "ml_result": {
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
    "risk_factors": []
  },
  "evidence": []
}
```

---

## 4. Threat Analytics

### `GET /api/dashboard/threats`
Provides aggregated threat classification distributions, severity distributions, and total anomaly count across all persisted flows.

* **Method**: `GET`
* **Query Parameters**: None
* **Empty State**: `{"threat_type_distribution": {}, "severity_distribution": {}, "anomaly_count": 0}`.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
  "threat_type_distribution": {
    "NORMAL": 500,
    "DOS_LIKE": 30,
    "SCANNING_LIKE": 15
  },
  "severity_distribution": {
    "LOW": 500,
    "HIGH": 30,
    "CRITICAL": 15
  },
  "anomaly_count": 45
}
```

---

## 5. Timeline Analytics

### `GET /api/dashboard/timeline`
Produces chronological time-series buckets for SOC timeline visualizations. Supports hourly (`interval=hour`) and daily (`interval=day`) aggregation intervals.

* **Method**: `GET`
* **Query Parameters**:
  | Parameter | Type | Required | Default | Description |
  |---|---|---|---|---|
  | `interval` | string | No | `"hour"` | Aggregation resolution: `"hour"` or `"day"`. |
  | `start_time` | string | No | `None` | Optional ISO8601 start timestamp filter. |
  | `end_time` | string | No | `None` | Optional ISO8601 end timestamp filter. |

* **Bucket Key Formats**:
  * `hour`: `YYYY-MM-DDTHH` (e.g. `"2026-10-04T12"`)
  * `day`: `YYYY-MM-DD` (e.g. `"2026-10-04"`)
* **Ordering**: Chronological ascending (oldest bucket first).
* **Empty State**: `{"interval": "hour", "buckets": []}`.
* **Validation**: Returns `400 Bad Request` if `interval` is neither `"hour"` nor `"day"`.
* **Response Status**: `200 OK`
* **Response Schema (`application/json`)**:
```json
{
  "interval": "hour",
  "buckets": [
    {
      "bucket_time": "2026-10-04T10",
      "flow_count": 120,
      "alert_count": 4,
      "high_alert_count": 3,
      "critical_alert_count": 1,
      "anomaly_count": 5
    },
    {
      "bucket_time": "2026-10-04T11",
      "flow_count": 95,
      "alert_count": 2,
      "high_alert_count": 2,
      "critical_alert_count": 0,
      "anomaly_count": 2
    }
  ]
}
```

---

## Security & Data Integrity

1. **Payload Privacy**: Neither directional flow records nor any dashboard schemas contain packet payload bytes or user content. Only 5-tuple metadata and statistical feature metrics are processed or displayed.
2. **Deterministic Architecture**: All counts, severity distributions, and timeline buckets are computed deterministically from persisted records. No stochastic or synthetic estimates are introduced at the API layer.
3. **Database Dialect Independence**: All queries and aggregations are cross-compatible between SQLite (used for local testing and lightweight deployments) and PostgreSQL (production).
