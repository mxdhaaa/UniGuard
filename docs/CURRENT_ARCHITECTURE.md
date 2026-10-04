# UniGuard Architecture Assessment & Migration Plan

## 1. Executive Summary

**UniGuard** is an AI-based passive network intelligence and threat detection prototype designed for **SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**. 

The solution operates on unidirectional traffic flows where return traffic (destination-to-source responses) is unavailable or absent (such as in data diode, TAP, or SPAN port environments). This document provides an audit of the existing codebase, identifies architectural gaps, and details the target architecture and phased migration roadmap.

---

## 2. Existing Architecture Analysis

### 2.1 Existing Frontend (`src/`)
* **Technology Stack**: React 19, TypeScript, Vite 8, Tailwind CSS v4 (`@tailwindcss/vite`), Recharts, Lucide React.
* **Component Structure**:
  * **Main Shell (`App.tsx`)**: Manages navigation state across 8 tabs (`overview`, `traffic`, `threats`, `detection`, `models`, `replay-lab`, `system`, `settings`). Fetches `/api/v1/detections` on initial mount with fallback to local mock data.
  * **Layout (`src/components/layout/`)**:
    * `Sidebar.tsx`: Navigation bar with threat badge counter.
    * `Header.tsx`: Search bar, live toggle, notifications.
  * **Views (`src/components/views/`)**:
    * `OverviewView.tsx`: Metric cards, throughput timeseries chart, threat category distribution bar chart, and recent detection table.
    * `TrafficView.tsx`: Static mock sample flow inspector table and simulated throughput area chart.
    * `ThreatTableView.tsx`: Interactive table of threats with severity badges, confidence, and row selection.
    * `ThreatDetailModal.tsx`: Modal drawer showing explainability metrics, feature variance ($Z$-scores), chronological sequence, and flow telemetry.
    * `ReplayLabView.tsx`: Synthetic scenario simulation runner (client-side timer driving random mock alert logs).
    * `DetectionRulesView.tsx`: Sliders for jitter threshold, alert confidence cutoff, and DNS entropy cutoff (client-side only).
    * `ModelsView.tsx`: Static display cards for "UniGuard Beacon Heuristic", "UniGuard Volumetric Detector", etc., marked as "Pending evaluation".
    * `SystemView.tsx`: Diagnostics cards for CPU, packet drops, and buffer utilization with static placeholders.
    * `SettingsView.tsx`: Client-side configuration placeholders.
  * **Shared Components (`src/components/common/`)**:
    * `MetricCard.tsx`, `SeverityBadge.tsx`, `ExplainabilityBox.tsx`.
* **State Management**: Local component state (`useState`, `useEffect`) without WebSocket connection or state store.
* **Build / Quality Status**:
  * `npm run build` fails with TypeScript strict errors (`TS6133` unused variables in `App.tsx`, `DetectionRulesView.tsx`, `SettingsView.tsx`; `TS2367` type mismatch in `OverviewView.tsx`).

### 2.2 Existing Backend (`backend/`)
* **Technology Stack**: Python 3.13, FastAPI, Pydantic v2.
* **Structure**: Flat module structure inside `backend/`:
  * `main.py`: Entry point with endpoints `GET /api/v1/health`, `GET /api/v1/stats`, `POST /api/v1/ingest/pcap`, `POST /api/v1/detect`, `GET /api/v1/detections`, `GET /api/v1/detections/{id}`.
  * `schemas.py`: Pydantic models `FlowRecord`, `EvidenceItem`, `DetectionResult`, `IngestResponse`, `StatsResponse`.
  * `flow_engine.py`: Scapy-based PCAP parser building directional flows `(src_ip, dst_ip, src_port, dst_port, protocol)` without requiring reverse handshake.
  * `feature_engine.py`: Calculates basic duration, packets/sec, bytes/sec, inter-arrival time mean/std/CV, packet size mean/std/entropy, unique destination counts, destination concentration, and DNS Shannon entropy.
  * `detectors/`:
    * `base.py`: `BaseDetector` abstract base class.
    * `c2_beaconing.py`: Heuristic checking inter-arrival coefficient of variation ($CV < 0.25$) and destination concentration.
    * `ddos.py`: Heuristic checking packets-per-second ($> 500$) or bytes-per-second ($> 1,000,000$).
    * `dns_tunnelling.py`: Heuristic checking DNS domain Shannon entropy ($> 3.8$), query length ($> 35$), and digit ratio ($> 0.25$).
    * `reconnaissance.py`: Heuristic counting unique ports ($> 8$) probed across context flows.
  * `correlation.py`: `RiskCorrelationEngine` combining repeated reconnaissance and boosting confidence for multi-signal sources.
  * `generator.py`: `SyntheticTrafficGenerator` generating synthetic flow records for benign, C2, DDoS, DNS tunnel, and port scan traffic.
  * `tests/test_uniguard.py`: Pytest tests for detectors, flow generation, and schemas.
* **Environment Status**:
  * Scapy and NumPy are not installed in the global Python environment, causing import errors during collection.
  * No database engine (relies on in-memory global list `DETECTIONS_STORE`).

---

## 3. Current Limitations

1. **Absence of Real Machine Learning**:
   * Detection currently relies entirely on static heuristic threshold rules (e.g., hardcoded `cv_iat < 0.25` or `pps > 500`).
   * No supervised ML classifier (Random Forest) trained to classify multi-class threats (`NORMAL`, `SCANNING_LIKE`, `DOS_LIKE`, `BOTNET_LIKE`, `EXFILTRATION_LIKE`, `OTHER_SUSPICIOUS`).
   * No unsupervised anomaly detection engine (Isolation Forest) trained on baseline normal traffic to catch zero-day / previously unseen anomalies.
2. **Missing Risk Scoring Engine**:
   * Severity and confidence are currently derived ad-hoc inside each detector.
   * No centralized, deterministic 0–100 risk score engine combining classification probability, anomaly score, and behavioral indicators.
3. **No Database Persistence**:
   * Detections and flows are kept in a volatile Python in-memory list (`DETECTIONS_STORE`) that resets on restart.
   * Missing PostgreSQL / SQLAlchemy persistence for flows, detections, evidence, analysis jobs, model versions, reports, and system events.
4. **Lack of Real-Time Streaming (WebSockets)**:
   * Frontend only polls or fetches on load; no WebSocket endpoint (`/ws/alerts`) exists on the backend.
   * New detections cannot push live updates to the SOC dashboard.
5. **Feature Engine Incompleteness for Unidirectional IP Traffic**:
   * Lacks port entropy, destination entropy, temporal burst scoring, source activity rate, protocol indicators, and robust zero-duration/zero-packet guards.
6. **Incomplete API Surface**:
   * Missing endpoints mandated for SIH26145: `/api/traffic/flow`, `/api/traffic/batch`, `/api/demo/start`, `/api/analysis/start`, `/api/dashboard/summary`, `/api/dashboard/timeline`, `/api/dashboard/threat-distribution`, `/api/reports`, `/api/models`.
7. **Frontend Disconnection**:
   * Views such as Traffic, Replay Lab, Models, and System Diagnostics rely primarily on static mock constants (`mockData.ts`).
   * Frontend TypeScript compilation errors prevent clean production builds.

---

## 4. Proposed Target Architecture

```
                  +-------------------------------------------------------+
                  |               TRAFFIC INGESTION MODES                 |
                  |  [Mode 1: Demo Engine]  [Mode 2: PCAP]  [Mode 3: Live]|
                  +---------------------------+---------------------------+
                                              |
                                              v
                  +-------------------------------------------------------+
                  |             UNIDIRECTIONAL FLOW PROCESSOR             |
                  |     (Directional 5-Tuple, Packet & Byte Accounting)   |
                  +---------------------------+---------------------------+
                                              |
                                              v
                  +-------------------------------------------------------+
                  |                     FEATURE ENGINE                    |
                  |  (Rates, Entropy, Temporal Bursts, Diversity, Stats)  |
                  +---------------------------+---------------------------+
                                              |
                        +---------------------+---------------------+
                        |                                           |
                        v                                           v
         +-----------------------------+             +-----------------------------+
         |      ML CLASSIFIER          |             |      ANOMALY DETECTOR       |
         |  (Supervised Random Forest) |             |    (Isolation Forest)       |
         +--------------+--------------+             +--------------+--------------+
                        |                                           |
                        +---------------------+---------------------+
                                              |
                                              v
                  +-------------------------------------------------------+
                  |               EXPLAINABLE RISK ENGINE                 |
                  |  0-100 Risk Score, Configurable Severity, Evidence    |
                  +---------------------------+---------------------------+
                                              |
                        +---------------------+---------------------+
                        |                                           |
                        v                                           v
         +-----------------------------+             +-----------------------------+
         |     POSTGRESQL DATABASE     |             |      WEBSOCKET MANAGER      |
         | (Flows, Alerts, Evidence)   |             |       (/ws/alerts)          |
         +-----------------------------+             +--------------+--------------+
                                                                    |
                                                                    v
                                                     +-----------------------------+
                                                     |      REACT SOC DASHBOARD    |
                                                     | (Live Flows, Threat Detail) |
                                                     +-----------------------------+
```

### 4.1 Backend Architecture (`backend/app/`)
* **`api/`**: REST endpoints partitioned cleanly:
  * `traffic.py`: Single flow ingestion, batch ingestion, PCAP upload.
  * `analysis.py`: Async analysis jobs for large captures.
  * `detections.py`: Query, filter, and patch analyst investigation status (`NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
  * `dashboard.py`: Summary statistics, timeseries timeline, threat distribution.
  * `reports.py`: Generation and retrieval of comprehensive analyst reports.
  * `system.py`: Real-time health, resource utilization, latency, and ingestion metrics.
* **`core/`**:
  * `flow_processor.py`: Directional one-way flow aggregation.
  * `feature_engine.py`: Deterministic 16-feature vector extraction (rates, Shannon entropy, burst scores).
  * `preprocessing.py`: Feature scaling, missing/infinite value sanitization.
  * `risk_engine.py`: Deterministic 0–100 risk scoring with configurable thresholds (LOW: 0–24, MEDIUM: 25–49, HIGH: 50–74, CRITICAL: 75–100).
  * `evidence_engine.py`: Fact-based evidence generator explaining exact contributing features.
* **`ml/`**:
  * `classifier.py`: Random Forest multi-class model.
  * `anomaly_detector.py`: Isolation Forest for zero-day/unseen anomaly detection.
  * `inference.py`: Consolidated dual-signal inference pipeline.
  * `model_manager.py`: Model loading, metadata tracking, and fallback handling.
* **`collectors/`**:
  * `pcap_collector.py`: Defensive Scapy-based PCAP/PCAPNG parser.
  * `flow_receiver.py`: JSON flow receiver for telemetry endpoints.
  * `demo_collector.py`: Background continuous synthetic flow generator with START / PAUSE / STOP / CLEAR controls.
* **`db/`**:
  * `database.py`: SQLAlchemy engine, session maker, PostgreSQL connection pooling with SQLite/in-memory fallback for local lightweight development.
  * `models.py`: Declarative ORM models for `Flow`, `Detection`, `Evidence`, `AnalysisJob`, `ModelVersion`, `Report`, `SystemEvent`.
  * `repositories.py`: Data access layers.
* **`websocket/`**:
  * `manager.py`: Connection manager broadcasting detection events, dashboard counter deltas, and live traffic stream.

### 4.2 Upgraded Frontend SOC UI
* Preserve the existing clean Tailwind layout and views while elevating them:
  1. **SOC Overview**: Real-time counter metrics, dynamic Recharts timeseries, threat & risk distributions, and recent detections.
  2. **Live Traffic**: Real-time streaming table showing incoming unidirectional flows with risk and classification.
  3. **Threat Detection**: Filterable incident table with one-click navigation to detailed investigation.
  4. **Detection Details**: Modal and full view displaying 0–100 risk score, confidence, anomaly score, classifier probability, observed features vs baseline, fact-based evidence, and analyst triage status actions.
  5. **Analytics**: Protocol, port, and threat trend visualizations.
  6. **Reports**: Interactive analyst report generator with exportable findings, limitations, and defensive recommendations.
  7. **System Health**: Health check statuses (API, DB, ML, WebSocket), pipeline latency breakdown (ingestion, feature extraction, ML, DB), and uptime.

---

## 5. Phased Migration Plan

| Milestone | Scope | Deliverables & Verification |
|---|---|---|
| **Milestone 1** (Current) | Codebase Inspection & Baseline | `docs/CURRENT_ARCHITECTURE.md`, TS error identification, environment check. |
| **Milestone 2** | Backend Foundation & Health | Modular `backend/app/` layout, configuration (`.env`), health endpoints, FastAPI lifecycle. |
| **Milestone 3** | Directional Flow Model & Feature Engine | Unidirectional flow processor, 16-feature vector engine, unit tests for edge cases (zero duration, extreme values). |
| **Milestone 4** | Demo Traffic Pipeline | Synthetic flow generator for 6 traffic profiles (`NORMAL`, `SCANNING_LIKE`, `DOS_LIKE`, `BOTNET_LIKE`, `EXFILTRATION_LIKE`, `UNKNOWN_ANOMALY`). |
| **Milestone 5** | ML Classifier & Anomaly Detector | Random Forest classifier + Isolation Forest anomaly detector, inference pipeline, model versioning. |
| **Milestone 6** | Deterministic Risk & Evidence Engine | 0–100 risk scoring algorithm, evidence generator from observed feature deltas, unit tests. |
| **Milestone 7** | Database Persistence | SQLAlchemy ORM models, PostgreSQL repository with indexes, migrations/initialization. |
| **Milestone 8** | Live Flow Ingestion & PCAP Upload | REST ingestion endpoints (`/api/traffic/flow`, `/api/traffic/batch`, `/api/traffic/pcap`), background jobs. |
| **Milestone 9** | WebSocket Alert Streaming | WebSocket manager (`/ws/alerts`), real-time event broadcasting on new detections. |
| **Milestone 10** | React SOC Dashboard Integration | Connect React frontend to REST & WebSocket APIs, resolve TypeScript errors, live flow streaming. |
| **Milestone 11** | Reports & Analytics | Analyst report generator, metrics aggregation endpoints, analytics charts. |
| **Milestone 12** | Dockerization & Hardening | `docker-compose.yml`, Dockerfiles, rate limiting, file validation, security hardening. |
| **Milestone 13** | End-to-End Testing & Verification | Comprehensive automated E2E test suite covering flow -> feature -> ML -> risk -> DB -> WebSocket -> UI. |

---

## 6. What Can Be Preserved vs Refactored

* **Preserved & Elevated**:
  * Existing modern UI layout (`Header.tsx`, `Sidebar.tsx`, `OverviewView.tsx`, `ThreatTableView.tsx`, `ThreatDetailModal.tsx`).
  * Existing visual design system (Tailwind colors, clean enterprise SOC aesthetics, Recharts charts).
  * Existing Scapy-based one-way flow parsing logic from `flow_engine.py` (migrating into `backend/app/collectors/pcap_collector.py` and `backend/app/core/flow_processor.py`).
  * Existing synthetic test scenarios (enhancing with full statistical distributions).
* **Refactored / Replaced**:
  * Flat `backend/` directory restructured into the standard enterprise `backend/app/` modular architecture.
  * Static heuristic rule detectors replaced/augmented by the dual-engine ML system (Random Forest + Isolation Forest) and deterministic Risk Engine.
  * In-memory `DETECTIONS_STORE` replaced with PostgreSQL + SQLAlchemy repository layer.
  * Client-side-only Replay Lab replaced with backend-driven Demo mode (`/api/demo/start`, `/api/demo/stop`).
  * Frontend TypeScript compilation bugs resolved.
