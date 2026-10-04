# UniGuard Production Deployment & Operations Guide

## Overview

UniGuard is an AI-based passive network threat detection platform designed for unidirectional IP traffic inspection. This guide covers local development, containerized production deployment with Docker Compose, PostgreSQL database configuration, WebSocket alert streaming, storage isolation, and operational maintenance.

---

## Architecture Summary

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

## 1. Local Development Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.12 / 3.13)
- Node.js 20+ (tested on Node 22 / 24)
- Libpcap / Npcap (only if performing live packet capture)

### Starting the Backend
```bash
# 1. Create and activate virtual environment (optional)
py -m venv venv
venv\Scripts\activate   # Windows PowerShell: .\venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Initialize SQLite database (default local fallback)
py -c "from backend.app.db.init_db import init_db; init_db()"

# 4. Start development server with hot-reload
py -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Starting the Frontend
```bash
# 1. Install frontend dependencies
npm install

# 2. Run unit tests
npm test

# 3. Start Vite dev server
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 2. Environment Variables Configuration

Configure environment variables via `.env` or container runtime flags:

| Variable | Type | Default | Description |
|---|---|---|---|
| `ENVIRONMENT` | string | `development` | `development`, `staging`, or `production`. When set to `production`, stack traces are hidden and wildcard CORS origins (`*`) are disallowed. |
| `API_HOST` | string | `127.0.0.1` | Network interface to bind backend server (`0.0.0.0` in Docker). |
| `API_PORT` | integer | `8000` | Port for the backend API server. |
| `LOG_LEVEL` | string | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. Controls application log output. |
| `ENABLE_DOCS` | boolean | `true` | When `false`, disables `/docs`, `/redoc`, and `/openapi.json` for hardened production environments. |
| `CORS_ORIGINS` | string | `http://localhost:5173,...` | Comma-separated list of allowed HTTP origins. |
| `DATABASE_URL` | string | `""` (SQLite fallback) | PostgreSQL connection URI (`postgresql+psycopg://user:password@host:5432/dbname`). If omitted, falls back to `sqlite:///./uniguard.db`. |
| `CAPTURE_INTERFACE` | string | `""` | Network interface name for live Scapy capture (e.g., `eth0`). If blank, auto-detects. |
| `CAPTURE_FILTER` | string | `ip and (tcp or udp or icmp)` | BPF capture filter for directional IP packets. |
| `FLOW_IDLE_TIMEOUT` | float | `30.0` | Inactivity seconds before an IP flow expires and triggers ML evaluation. |
| `FLOW_MAX_DURATION` | float | `120.0` | Maximum lifetime of an ongoing flow before evaluation. |
| `PCAP_UPLOAD_DIR` | string | `./pcap_uploads` | File storage path for isolated PCAP/PCAPNG uploads. |
| `PCAP_MAX_FILE_SIZE_MB` | integer | `50` | Maximum allowed PCAP file size in megabytes. |
| `VITE_API_BASE_URL` | string | `http://127.0.0.1:8000` | Frontend API client base URL. |

---

## 3. PostgreSQL Database Configuration

PostgreSQL 14+ (recommended PostgreSQL 16) is the production database target.

### Connection String Format
```
DATABASE_URL=postgresql+psycopg://uniguard_user:uniguard_secure_password@postgres-host:5432/uniguard
```

### Connection Pooling Behavior
When connecting to PostgreSQL, UniGuard initializes SQLAlchemy with:
- `pool_pre_ping=True`: Tests connection health before query execution to recover gracefully from network drops.
- `pool_size=10`: Maintains persistent connection pool.
- `max_overflow=20`: Allows burst pool capacity during high flow ingestion.
- `pool_timeout=30`: 30-second timeout before raising pool acquisition error.
- `pool_recycle=1800`: Recycles idle connections every 30 minutes to prevent database connection timeouts.

### Database Initialization
On startup with a clean database, tables are created deterministically via SQLAlchemy metadata. Existing data is preserved; UniGuard never drops tables automatically.

---

## 4. Docker Deployment (Docker Compose)

### Services Topology
1. **`db`**: PostgreSQL 16 Alpine container with persistent named volume `postgres_data`.
2. **`backend`**: Python 3.12-slim container running FastAPI via Uvicorn under an unprivileged user (`uniguard`, UID 1001).
3. **`frontend`**: Nginx Alpine container serving optimized Vite static assets and reverse-proxying `/api/` and `/api/ws/` to `backend:8000`.

### Launching the Stack
```bash
# Start all containers in the background
docker-compose up -d --build

# View operational logs
docker-compose logs -f backend

# Check container health status
docker-compose ps
```

The SOC dashboard is accessible at `http://localhost:80`.

---

## 5. Live Packet Capture Requirements

In containerized Linux environments, passive packet capture via Scapy requires the `CAP_NET_RAW` and `CAP_NET_ADMIN` Linux capabilities rather than running as root:

```yaml
# In docker-compose.yml (only if live physical NIC capture is needed):
services:
  backend:
    cap_add:
      - NET_RAW
      - NET_ADMIN
    network_mode: host  # Required to listen to host interfaces
```

> **Security Note**: Offline PCAP processing, synthetic traffic replay, and all REST/WebSocket APIs operate completely without elevated privileges. Elevated capabilities are never granted by default.

---

## 6. Health & Readiness Probes

### Liveness Probe (`/api/health`)
- Returns `HTTP 200` with `{"status": "ok", "service": "uniguard-backend", "version": "0.1.0"}`.
- Used by Docker/Kubernetes container health checks to verify process liveness.

### Readiness Probe (`/api/system/status`)
- Returns subsystem health:
  ```json
  {
    "backend": "healthy",
    "database": "healthy",
    "ml_engine": "ready",
    "ingestion": "not_ready"
  }
  ```
- If PostgreSQL is unreachable, `database` reports `"unavailable"`.

---

## 7. Logging & Observability

- Centralized logging uses Python's standard `logging` library with configurable `LOG_LEVEL`.
- Log output format: `%(asctime)s [%(levelname)s] %(name)s: %(message)s`.
- Key events logged:
  - Startup initialization and database connectivity status.
  - Active WebSocket client connections and disconnections.
  - PCAP job uploads, completion packet statistics, and processing errors.
  - Live ingestion start, stop, and flow aggregation cycles.
  - Unhandled exceptions with full tracebacks (without returning tracebacks to clients).
- **Security Invariant**: Passwords, connection string credentials, secrets, raw packet payloads, and sensitive payload bytes are strictly prohibited from log output.

---

## 8. Database Backup & Disaster Recovery

### Manual Backup (PostgreSQL)
```bash
docker exec -t uniguard-postgres pg_dump -U uniguard uniguard > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Restoration
```bash
cat backup_20261004.sql | docker exec -i uniguard-postgres psql -U uniguard -d uniguard
```

---

## 9. HTTPS & Reverse Proxy Recommendations

In production, terminate TLS at an outer reverse proxy (e.g., Cloudflare, AWS ALB, Nginx, or Caddy) and forward traffic to the UniGuard Nginx container on port 80:
- Enforce HTTP/2 or HTTP/3.
- Enforce TLS 1.3 with strong cipher suites.
- Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
- Enable WebSocket upgrade headers (`Upgrade: websocket`, `Connection: Upgrade`) on the proxy for `/api/ws/alerts`.

---

## 10. Graceful Shutdown

UniGuard implements FastAPI's modern `lifespan` handler:
1. Stops active live packet capture threads and flushes remaining partial flows.
2. Closes registered WebSocket connections with code 1001 (Server Going Away).
3. Disposes SQLAlchemy connection pool cleanly.
4. Cleanly releases all held file descriptors.

---

## 11. Troubleshooting

| Symptom | Probable Cause | Resolution |
|---|---|---|
| `database: unavailable` in `/api/system/status` | PostgreSQL container is initializing or credentials mismatch | Verify `DATABASE_URL` matches credentials in `docker-compose.yml`. Inspect `docker-compose logs db`. |
| WebSocket disconnection (`code 1006`) | Reverse proxy does not support HTTP upgrade | Ensure Nginx `proxy_set_header Upgrade $http_upgrade` and `Connection "upgrade"` are present. |
| PCAP upload returns `HTTP 413` | Upload exceeds `PCAP_MAX_FILE_SIZE_MB` | Adjust `PCAP_MAX_FILE_SIZE_MB` environment variable (default: 50 MB). |
| Live packet capture fails to start | Insufficient Linux capabilities for Scapy raw sockets | Add `cap_add: [NET_RAW, NET_ADMIN]` and `network_mode: host` to the backend container configuration. |
| CORS errors in browser console | Origin not listed in `CORS_ORIGINS` | Add frontend protocol, host, and port to `CORS_ORIGINS` environment variable. |
