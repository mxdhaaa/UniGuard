"""
Unit Tests for Demo API Endpoints
Verifies REST controllers for demo status, lifecycle actions, and batch generation.
"""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_demo_status_endpoint():
    """Verify GET /api/demo/status returns valid schema and defensive disclaimer."""
    response = client.get("/api/demo/status")
    assert response.status_code == 200
    data = response.json()
    assert "state" in data
    assert "generated_flows" in data
    assert "disclaimer" in data
    assert "synthetic" in data["disclaimer"].lower()


def test_demo_lifecycle_endpoints():
    """Verify POST /api/demo/start, pause, stop, clear."""
    # Start
    res_start = client.post("/api/demo/start", json={"seed": 100})
    assert res_start.status_code == 200
    assert res_start.json()["state"] == "RUNNING"

    # Pause
    res_pause = client.post("/api/demo/pause")
    assert res_pause.status_code == 200
    assert res_pause.json()["state"] == "PAUSED"

    # Stop
    res_stop = client.post("/api/demo/stop")
    assert res_stop.status_code == 200
    assert res_stop.json()["state"] == "STOPPED"

    # Clear
    res_clear = client.post("/api/demo/clear")
    assert res_clear.status_code == 200
    assert res_clear.json()["generated_flows"] == 0


def test_demo_batch_endpoint():
    """Verify POST /api/demo/batch returns generated flows with features and metadata."""
    payload = {
        "count": 5,
        "seed": 42,
    }
    response = client.post("/api/demo/batch", json=payload)
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 5

    for item in items:
        assert "flow" in item
        assert "features" in item
        assert "preprocessed" in item
        assert "simulated_profile" in item
        assert len(item["preprocessed"]["values"]) == 16


def test_demo_batch_invalid_count():
    """Verify validation error when count <= 0."""
    response = client.post("/api/demo/batch", json={"count": 0})
    assert response.status_code == 422  # Pydantic validation error (ge=1)
