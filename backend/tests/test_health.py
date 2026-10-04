"""
Unit Tests for Health & System Status Endpoints
Milestone 2 Backend Foundation Verification
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_endpoint():
    """Verify GET /api/health returns 200 and matches required contract."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "uniguard-backend"
    assert data["version"] == "0.1.0"


def test_system_status_endpoint():
    """Verify GET /api/system/status returns 200 and reports subsystem readiness accurately."""
    response = client.get("/api/system/status")
    assert response.status_code == 200
    data = response.json()
    assert data["backend"] == "healthy"
    assert data["database"] in {"healthy", "not_configured", "unavailable"}
    assert data["ml_engine"] in {"ready", "not_ready"}
    assert data["ingestion"] == "not_ready"
