# UniGuard Milestone 14: Frontend Integration & SOC Dashboard

## Overview

UniGuard Milestone 14 integrates the React frontend with the complete Python FastAPI backend (Milestones 1–13). The application operates as a full-featured Security Operations Center (SOC) dashboard backed by real persisted traffic flows, machine learning threat assessments, risk scores, evidence explanations, incident alerts, forensic investigations, and printable/exportable incident reports.

---

## Architecture

```
                    +------------------------------------+
                    |        UniGuard React UI           |
                    |  (Vite + React 19 + Tailwind CSS)  |
                    +-----------------+------------------+
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v                                                         v
+-------------------------------+                       +---------------------+
| Centralized REST API Client   |                       | WebSocket Hook      |
| `src/api/client.ts`           |                       | `useAlertSocket.ts` |
+---------------+---------------+                       +----------+----------+
                |                                                  |
                | HTTP GET/POST                                    | wss://
                v                                                  v
+-----------------------------------------------------------------------------+
|                            UniGuard FastAPI SOC                             |
|                                                                             |
|  * /api/health                   * /api/dashboard/overview                  |
|  * /api/system/status            * /api/dashboard/flows [filters/pages]     |
|  * /api/ingestion/status         * /api/dashboard/flows/{flow_id}           |
|  * /api/ingestion/start          * /api/dashboard/alerts [filters/pages]    |
|  * /api/ingestion/stop           * /api/dashboard/alerts/{alert_id}         |
|  * /api/pcap/upload              * /api/dashboard/threats                   |
|  * /api/pcap/status/{job_id}     * /api/dashboard/timeline                  |
|  * /api/investigations/flows/{id}* /api/reports/flows/{flow_id}             |
|  * /api/investigations/alerts/{id}* /api/reports/alerts/{alert_id}          |
|  * /api/ws/alerts (Real-Time WebSocket Stream)                              |
+-----------------------------------------------------------------------------+
```

---

## Centralized Frontend API Client (`src/api/client.ts`)

The typed API layer encapsulates all backend communication:

- **Configurable Base URL**: Reads `import.meta.env.VITE_API_BASE_URL` with automatic fallback to `http://127.0.0.1:8000`.
- **WebSocket URL Resolution**: Automatically maps `http:` -> `ws:` and `https:` -> `wss:` to `/api/ws/alerts`.
- **Query Parameter Serialization**: Encodes filter options, pagination (`page`, `page_size`), timestamps, and search keys.
- **Error Handling**: Captures backend FastAPI JSON error responses (`detail` payload) and formats human-readable error messages.
- **Typed Responses**: TypeScript interfaces strictly aligned with backend Pydantic models:
  - `HealthResponse`, `SystemStatusResponse`
  - `DashboardOverview`, `DashboardTimeline`, `ThreatAnalytics`
  - `DashboardFlowSummary`, `DashboardFlowDetail`, `PaginatedFlowResponse`
  - `DashboardAlertSummary`, `DashboardAlertDetail`, `PaginatedAlertResponse`
  - `InvestigationResponse`, `InvestigationFinding`, `InvestigationTimelineEvent`
  - `ReportResponse`, `InvestigationSubject`
  - `IngestionStatusResponse`, `PcapUploadResponse`, `PcapStatusResponse`

---

## WebSocket Alert Streaming (`src/api/useAlertSocket.ts`)

Subscribes to `/api/ws/alerts` for live push alerts (HIGH and CRITICAL severity):
- **Lifecycle Management**: Mounts clean WebSocket connection with teardown on unmount.
- **Automated Reconnect**: Reconnection loop with exponential backoff (`Math.min(1000 * 2 ** retryCount, 15000)`).
- **State Tracking**: `connecting`, `connected`, `disconnected`, `reconnecting`, `error`.
- **Stream Buffering**: Accumulates recent incoming alerts for live banner display in `AlertsView`.

---

## Frontend Components & Views

### 1. `FlowsView.tsx` (`src/components/views/FlowsView.tsx`)
- Server-side paginated network flow browser backed by `GET /api/dashboard/flows`.
- Multi-parameter filtering:
  - `threat_type` (BENIGN, DOS_DDOS, PORT_SCAN, BOTNET_C2, BRUTE_FORCE, WEB_ATTACK, INFILTRATION)
  - `severity` (LOW, MEDIUM, HIGH, CRITICAL)
  - `is_anomaly` (Anomalous only, Normal only)
  - `source_ip` and `destination_ip`
- Table displays: Timestamp, Flow ID, 5-tuple endpoints, protocol, threat type, confidence, anomaly flag & score, risk score, severity badge.
- Row actions:
  - **Investigate**: Opens `InvestigationModal` for deep-dive forensic analysis.
  - **Report**: Opens `ReportModal` to generate a formal incident report.
- Full loading, empty, and error retry states.

### 2. `AlertsView.tsx` (`src/components/views/AlertsView.tsx`)
- Security incident table backed by `GET /api/dashboard/alerts`.
- Live WebSocket indicator with manual reconnect control.
- Real-time incoming alert banner for instant notification when threats are detected.
- Filter criteria: `threat_type`, `severity`, `status`.
- Actions to open deep-dive investigation or incident report for any alert.

### 3. `IngestionPcapView.tsx` (`src/components/views/IngestionPcapView.tsx`)
- Passive sensor packet capture controls (`/api/ingestion/status`, `/start`, `/stop`).
- Real-time sensor metrics: Active flows, packets captured, flows completed, errors.
- PCAP/PCAPNG upload drop-zone (`/api/pcap/upload`).
- Asynchronous job status tracking (`/api/pcap/status/{job_id}`) with direct shortcut to navigate to extracted flows upon completion.

### 4. `InvestigationModal.tsx` (`src/components/views/InvestigationModal.tsx`)
- Comprehensive SOC forensic investigation drawer for flows (`/api/investigations/flows/{id}`) and alerts (`/api/investigations/alerts/{id}`).
- 5 investigation tabs:
  1. **Overview**: Executive summary, risk score, ML confidence, 5-tuple network details.
  2. **16 Flow Features**: Observed values, baseline references, Z-scores, impact badges.
  3. **Evidence**: Extracted heuristic rules, interpretations, and weight contributions.
  4. **Findings**: Individual finding titles, categories, severities, and descriptions.
  5. **Timeline**: Chronological forensic reconstruction.
- Direct handoff button to open `ReportModal`.

### 5. `ReportModal.tsx` (`src/components/views/ReportModal.tsx`)
- Formal SOC incident report backed by `/api/reports/flows/{id}` and `/api/reports/alerts/{id}`.
- Executive summary, threat classification probabilities, risk assessment breakdown, anomaly detection metrics, evidence table, key findings, recommended operational actions, and analytical limitations.
- "Copy JSON" action with clipboard confirmation for external SIEM/ticketing export.
- Direct handoff button to investigate the underlying incident.

### 6. `OverviewView.tsx` (`src/components/views/OverviewView.tsx`)
- Connects to `/api/dashboard/overview` and displays real persisted flow counts, alert counts, and anomaly metrics.
- Threat distribution chart reflecting real classification distribution.
- Quick navigation shortcuts to `Flows`, `Alerts`, and `Ingestion`.

### 7. Navigation & App Shell (`Sidebar.tsx`, `App.tsx`)
- Added `Network Flows`, `SOC Alerts`, and `PCAP & Ingestion` tabs to the navigation bar.
- Unified modal state management for seamless navigation between table views, investigations, and incident reports.

---

## Configuration

Set the backend API endpoint via environment variable in `.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

If omitted, the frontend automatically defaults to `http://127.0.0.1:8000`.

---

## Running the Application Locally

### 1. Start the UniGuard Backend
```bash
# In project root
py -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Start the Frontend Dev Server
```bash
# In project root
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## Verification & Test Results

### 1. Frontend Native Unit Tests
```bash
npm test
```
```
▶ UniGuard Centralized Frontend API Client (M14)
  ✔ API Base URL and WebSocket URL derivation (1.57ms)
  ✔ uniguardApi exposes all required SOC methods (0.26ms)
  ✔ getFlows builds correct query parameters (0.45ms)
  ✔ getAlerts builds correct query parameters (0.31ms)
  ✔ Investigation and Report endpoints encode identifiers safely (0.37ms)
  ✔ HTTP error responses properly extract error detail (2.38ms)
  ✔ Ingestion controls formulate POST requests (0.51ms)
✔ UniGuard Centralized Frontend API Client (M14) (8.22ms)
ℹ tests 7 | pass 7 | fail 0
```

### 2. Frontend Typecheck & Build
```bash
npx tsc -b
npm run build
```
- TypeScript check passed with **0 errors**.
- Vite production build succeeded with **0 errors**.

### 3. Frontend Linting
```bash
npm run lint
```
- Oxlint finished on 26 files with **0 errors**.

### 4. Backend Regression Test Suite
```bash
py -m pytest
```
- **254 passed, 1 warning in 15.70s (100% green)** across all Milestones 1–13.
