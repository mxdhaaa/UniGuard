# UniGuard Database Documentation (Milestone 8)

## Architecture

The persistence layer bridges the stateless analysis pipeline to future stateful SOC dashboards. It accepts the pure deterministic outputs of the pipeline and safely records them.

`Traffic` → `Feature/ML` → `Risk` → `Evidence` → **`PersistenceService`** → `PostgreSQL`

This design enforces separation of concerns: domain logic happens strictly before persistence. The ORM does not contain feature extraction logic or model inference code.

---

## PostgreSQL Configuration

UniGuard uses **SQLAlchemy 2.x** with the `psycopg` (v3) driver.

By default, the application looks for the `DATABASE_URL` environment variable. A typical PostgreSQL configuration looks like:
```env
DATABASE_URL=postgresql+psycopg://uniguard:password@localhost:5432/uniguard
```

### Health Status Behavior
If `DATABASE_URL` is omitted, the application falls back safely to a local SQLite database (`sqlite:///./uniguard.db`) to prevent crashing the API in unconfigured environments.

The existing `GET /api/system/status` endpoint executes a live `SELECT 1` query to verify database health. If PostgreSQL is down, the system remains up, but the database component will accurately report `unavailable`.

---

## Tables and Relationships

The database schema directly maps to the application's domain models:

1. **`traffic_flows`**: The primary entity. Contains metadata like IPs, ports, duration, and packet counts. (PK: `flow_id`)
2. **`features`**: Contains the exact 16 canonical features. (FK: `flow_id` → `traffic_flows`)
3. **`ml_results`**: Contains classifier confidences, anomaly scores, and model metadata. Probabilities and feature importances are stored natively as JSON/JSONB. (FK: `flow_id` → `traffic_flows`)
4. **`risk_assessments`**: Stores the deterministic risk score, severity band, and explanations. (FK: `flow_id` → `traffic_flows`)
5. **`evidence_items`**: One-to-many relationship with flows. Stores individual explainability items mapped by the Evidence Engine. (FK: `flow_id` → `traffic_flows`)
6. **`alerts`**: High-severity investigation records for the SOC. (FK: `flow_id` → `traffic_flows`)

---

## Repository Design

The repository layer (`backend/app/db/repositories.py`) contains pure CRUD functions. It converts Pydantic domain schemas into SQLAlchemy ORM models and executes the queries. 

Functions include:
- `save_flow`, `get_flow`, `list_flows`
- `save_features`, `save_ml_result`, `save_risk_assessment`, `save_evidence`, `save_alert`
- `get_alert`, `list_alerts` (with severity/threat/status filtering)

---

## Transaction Strategy & `PersistenceService`

The `PersistenceService` (`backend/app/services/persistence_service.py`) orchestrates atomic commits of a complete pipeline execution.

**Transaction Safety:**
- All 5 related records (Flow, Features, ML, Risk, Evidence) are added to a single `Session`.
- `db.commit()` is called exactly once.
- If an `IntegrityError` (such as a duplicate `flow_id`) or any other exception occurs, `db.rollback()` is fired, completely preventing orphaned rows.

---

## Alert Persistence Rule

Alerts are not created for every flow. The `PersistenceService` enforces a strict deterministic threshold for alert generation:
- If `RiskAssessment.severity` is **HIGH** or **CRITICAL**, an alert is automatically generated with `status="OPEN"`.
- If severity is LOW or MEDIUM, no alert is generated.

---

## Test Database Strategy

The test suite completely avoids relying on an external PostgreSQL instance, ensuring zero-friction local development.
- The `db_session` fixture uses an in-memory SQLite database (`sqlite:///:memory:`).
- Tables are generated locally using `Base.metadata.create_all()` per test.
- SQLAlchemy 2.x natively handles translating PostgreSQL `JSONB` mappings to SQLite `JSON` strings safely without breaking domain models.

---

## Initialization

Database tables can be safely initialized locally by running:
```bash
python -m backend.app.db.init_db
```
This leverages `create_all()`, which safely skips existing tables without destroying data. Alembic migrations are intentionally deferred to future milestones when schema drift becomes a factor.

---

## Limitations

- **No Real-Time Subscriptions:** Milestone 8 provides persistence but does not implement WebSockets to push new alerts to frontends.
- **No API Exfiltration:** The current API provides basic retrieval but lacks full SOC dashboard endpoints (filtering, sorting, full-text search).
- **Incident Management:** Alerts can be created, but there are no API routes to transition them from `OPEN` to `RESOLVED` yet.
- **No Live Capture:** The pipeline still relies on programmatic/synthetic injection for processing.
