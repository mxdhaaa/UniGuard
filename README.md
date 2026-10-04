# UniGuard: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

UniGuard is an enterprise-grade, passive network security operations center (SOC) platform designed for high-assurance network traffic inspection. Operating strictly without deep packet payload inspection, UniGuard aggregates raw directional IP packets into statistical flow records, computes 16 statistical features, applies dual-engine Machine Learning (Random Forest classifier and Isolation Forest anomaly detector), scores risks deterministically, and surfaces forensic incident alerts in real time.

---

## Key Capabilities

- **Passive Directional Flow Inspection**: Aggregates network traffic using Scapy (live capture) or PCAP/PCAPNG offline processing without inspecting packet payloads.
- **Canonical 16-Feature Extraction**: Fast, deterministic extraction of timing, volume, entropy, and flag statistics.
- **Dual-Model ML Threat Engine**:
  - Supervised Random Forest Classifier for multi-class threat attribution (DOS/DDOS, PORT_SCAN, BOTNET_C2, BRUTE_FORCE, WEB_ATTACK, INFILTRATION).
  - Unsupervised Isolation Forest for statistical anomaly and zero-day deviation detection.
- **Explainable Evidence & Risk Engines**: Transparent scoring (0–100) and weighted feature evidence for SOC analyst validation.
- **Real-Time SOC Dashboard**: Vite + React 19 interface with live WebSocket alerts, deep-dive forensic modals, and exportable SOC incident reports.
- **Production Hardened (Milestone 15)**: Secure Docker deployment, PostgreSQL connection pooling, path-traversal protection, security headers, CORS hardening, and comprehensive health/readiness probes.

---

## Architecture Overview

```
                      +-----------------------------+
                      |         Web Client          |
                      |   (Browser / SOC Analyst)   |
                      +--------------+--------------+
                                     |
                                     | HTTP / WSS (Port 80 / 443)
                                     v
                      +-----------------------------+
                      |     Nginx Reverse Proxy     |
                      |    (Frontend Container)     |
                      +--------------+--------------+
                                     |
              +----------------------+----------------------+
              |                                             |
              | /api/ (REST)                                | /api/ws/ (WebSocket)
              v                                             v
+---------------------------------------------------------------------------+
|                          UniGuard FastAPI Backend                         |
|                                                                           |
|   * Liveness & Readiness Checks (/api/health, /api/system/status)         |
|   * Machine Learning Engine (Random Forest & Isolation Forest)            |
|   * 16-Feature Flow Aggregator & Risk / Evidence Engines                  |
|   * Live Ingestion (Scapy) & PCAP Ingestion with Sandbox Isolation        |
|   * Real-Time Alert Broadcast WebSocket Manager                           |
+------------------------------------+--------------------------------------+
                                     |
                                     | SQLAlchemy Engine (Pool Pre-Ping)
                                     v
                      +-----------------------------+
                      |      PostgreSQL 16 DB       |
                      | (Relational SOC Persistence)|
                      +-----------------------------+
```

---

## Quick Start (Local Development)

### 1. Backend Setup
```bash
# Install Python dependencies
pip install -r backend/requirements.txt

# Run backend test suite
py -m pytest

# Start development API server (SQLite fallback by default)
py -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend Setup
```bash
# Install Node dependencies
npm install

# Run frontend tests
npm test

# Typecheck and lint
npx tsc -b
npm run lint

# Start Vite dev server
npm run dev
```

Visit `http://localhost:5173` to access the SOC interface.

---

## Production Deployment (Docker Compose)

UniGuard provides a containerized multi-tier deployment (PostgreSQL + FastAPI + React/Nginx):

```bash
# Build and launch all services in detached mode
docker-compose up -d --build

# Inspect running services
docker-compose ps

# View operational logs
docker-compose logs -f backend
```

Access the production SOC dashboard at `http://localhost:80`.

---

## Documentation Index

- [Architecture & Data Flow](docs/CURRENT_ARCHITECTURE.md)
- [Deployment & Operations Guide](docs/DEPLOYMENT.md)
- [Security Policy & Hardening](docs/SECURITY.md)
- [Feature Extraction Specification](docs/FEATURES.md)
- [Risk Scoring Engine](docs/RISK_ENGINE.md)
- [Evidence Engine](docs/EVIDENCE_ENGINE.md)
- [Database Schema & Persistence](docs/DATABASE.md)
- [WebSocket Alert Stream](docs/WEBSOCKETS.md)
- [Live Ingestion Specification](docs/LIVE_INGESTION.md)
- [PCAP Ingestion Specification](docs/PCAP_INGESTION.md)
- [SOC Dashboard APIs](docs/DASHBOARD_APIS.md)
- [Investigation APIs](docs/INVESTIGATION.md)
- [Incident Reporting APIs](docs/REPORTS.md)
- [Frontend Integration Guide](docs/FRONTEND_INTEGRATION.md)

---

## Testing & Quality Assurance

```bash
# Run 264 backend unit and integration tests
py -m pytest

# Run frontend client unit tests
npm test

# Verify TypeScript type correctness
npx tsc -b

# Run linter
npm run lint

# Build production bundle
npm run build
```

---

## License

Proprietary / Smart India Hackathon (SIH) Confidential.
