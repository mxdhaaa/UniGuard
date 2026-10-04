# UniGuard WebSockets (Milestone 9)

## Overview
The WebSocket layer provides real-time, low-latency delivery of UniGuard alerts to SOC dashboards and frontend clients.

## Architecture
- **In-Process Manager:** Active WebSocket connections are tracked in-memory by the `WebSocketManager`. 
- **No External Broker:** For this milestone, no external message brokers (e.g., Redis, Kafka, Celery) are required. The state is maintained within the FastAPI process.

## Endpoint
- **URL:** `ws://<host>:<port>/api/ws/alerts`
- **Authentication:** Currently unauthenticated (authentication hardening is reserved for a future milestone).

## Connection Lifecycle
1. Client connects via a standard WebSocket upgrade request to `/api/ws/alerts`.
2. The endpoint registers the connection in the `WebSocketManager`.
3. The connection remains open and idle.
4. When a new alert is generated, the server broadcasts the event to the client.
5. If the client disconnects or network failure occurs, the server gracefully removes the connection from the manager without disrupting other connected clients.

## Alert Broadcasting Rules
- **HIGH & CRITICAL Only:** Only alerts associated with flows evaluated as `HIGH` or `CRITICAL` severity are broadcast. `LOW` and `MEDIUM` risk assessments do not generate alerts and thus produce no real-time broadcast.
- **Post-Commit Only:** To ensure consistency between real-time events and persistent storage, broadcasts are dispatched *only after* a successful database commit in the `PersistenceService`. A WebSocket failure never causes a database rollback.

## Alert Event Payload
The broadcasted message is a JSON object formatted as follows:

```json
{
  "event": "alert.created",
  "alert": {
    "alert_id": "ALRT-12345678",
    "flow_id": "flow-abc-123",
    "threat_type": "DOS_LIKE",
    "risk_score": 85.0,
    "severity": "CRITICAL",
    "status": "OPEN",
    "summary": "Flow was classified as DOS_LIKE with high classifier confidence..."
  }
}
```

### Fields
- `event`: Always exactly `"alert.created"`.
- `alert`: Contains the core persisted alert data required by the dashboard. Sensitive internal objects (such as SQLAlchemy instances or database strings) are strictly excluded from this payload.
