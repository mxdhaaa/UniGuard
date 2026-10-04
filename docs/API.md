# UniGuard REST API Documentation

This document describes the active REST API endpoints for the UniGuard passive network intelligence backend.

---

## Base URL
* Local Development: `http://127.0.0.1:8000`

---

## 1. System Endpoints

### 1.1 Service Health Check
Retrieves the operational status and semantic version of the backend service.

* **Endpoint**: `/api/health`
* **Method**: `GET`
* **Authentication**: None
* **Response Status**: `200 OK`
* **Response Payload (`application/json`)**:
```json
{
  "status": "ok",
  "service": "uniguard-backend",
  "version": "0.1.0"
}
```

#### Response Fields:
| Field | Type | Description |
|---|---|---|
| `status` | string | Health indicator (`ok`) |
| `service` | string | Name of the service (`uniguard-backend`) |
| `version` | string | Semantic version of the service (`0.1.0`) |

---

### 1.2 Subsystem Operational Status
Retrieves readiness and connectivity states across all core platform subsystems. Unimplemented or unconfigured subsystems are explicitly identified.

* **Endpoint**: `/api/system/status`
* **Method**: `GET`
* **Authentication**: None
* **Response Status**: `200 OK`
* **Response Payload (`application/json`)**:
```json
{
  "backend": "healthy",
  "database": "not_configured",
  "ml_engine": "not_ready",
  "ingestion": "not_ready"
}
```

#### Response Fields:
| Field | Type | Description | Current State (Milestone 2) |
|---|---|---|---|
| `backend` | string | Backend API process state | `healthy` |
| `database` | string | PostgreSQL database connectivity | `not_configured` |
| `ml_engine` | string | Random Forest & Isolation Forest inference engines | `not_ready` |
| `ingestion` | string | Telemetry, PCAP, and live flow ingestion pipeline | `not_ready` |
