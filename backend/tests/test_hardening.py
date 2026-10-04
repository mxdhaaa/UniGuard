"""
UniGuard Milestone 15: Deployment & Hardening Unit Tests
Verifies configuration loading, CORS hardening, security headers,
safe error handling, PCAP path sanitization, and WebSocket lifecycle management.
"""

import os
import pytest
from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import app
from backend.app.services.websocket_manager import WebSocketManager

client = TestClient(app)


def test_configuration_defaults_and_env_loading(monkeypatch):
    """Test that Settings loads safe defaults and environment variables accurately."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setenv("ENABLE_DOCS", "false")
    monkeypatch.setenv("API_PORT", "9000")
    monkeypatch.setenv("CORS_ORIGINS", "https://soc.uniguard.local,https://dashboard.uniguard.local")

    cfg = Settings()
    assert cfg.environment == "production"
    assert cfg.is_production is True
    assert cfg.log_level == "WARNING"
    assert cfg.enable_docs is False
    assert cfg.api_port == 9000
    assert "https://soc.uniguard.local" in cfg.cors_origins
    assert "https://dashboard.uniguard.local" in cfg.cors_origins


def test_cors_origins_parsing():
    """Verify CORS origins parsing strips spaces and ignores empty items."""
    raw = " http://localhost:5173 , http://custom-soc.internal , "
    os.environ["CORS_ORIGINS"] = raw
    try:
        cfg = Settings()
        assert cfg.cors_origins == ["http://localhost:5173", "http://custom-soc.internal"]
    finally:
        del os.environ["CORS_ORIGINS"]


def test_security_headers_present_on_responses():
    """Verify standard security headers are injected into HTTP responses."""
    response = client.get("/api/health")
    assert response.status_code == 200

    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in headers.get("Permissions-Policy", "")


def test_cors_preflight_and_headers():
    """Verify CORS headers behave properly on valid request origins."""
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Preflight should succeed and echo allowed origin
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cors_disallowed_origin():
    """Verify disallowed origins do not receive access-control-allow-origin."""
    response = client.get(
        "/api/health",
        headers={"Origin": "https://malicious-site.attacker.com"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") is None


def test_safe_error_handling_no_stack_traces(monkeypatch):
    """
    Verify that unhandled internal exceptions return a controlled response
    without exposing Python stack traces or filesystem paths.
    """
    from backend.app.config import settings
    monkeypatch.setattr(settings, "environment", "production")

    from fastapi import APIRouter
    test_router = APIRouter()

    @test_router.get("/test/broken-route")
    def broken_route():
        raise RuntimeError("SensitiveDatabaseException: connection to /var/secrets/db failed")

    app.include_router(test_router, prefix="/api")

    # Use raise_server_exceptions=False so the TestClient allows FastAPI's 500 handler to return
    safe_client = TestClient(app, raise_server_exceptions=False)
    response = safe_client.get("/api/test/broken-route")
    assert response.status_code == 500
    data = response.json()
    assert data["detail"] == "Internal server error occurred."
    assert "SensitiveDatabaseException" not in response.text
    assert "/var/secrets/db" not in response.text


def test_pcap_path_traversal_protection():
    """Verify that uploading with path traversal filenames is safely sanitized."""
    traversal_name = "../../etc/passwd.pcap"
    response = client.post(
        "/api/pcap/upload",
        files={"file": (traversal_name, b"dummy pcap content", "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 200
    data = response.json()
    job_id = data["job_id"]

    status_resp = client.get(f"/api/pcap/status/{job_id}")
    status_data = status_resp.json()
    assert ".." not in status_data["filename"]
    assert "/" not in status_data["filename"]
    assert "\\" not in status_data["filename"]
    assert status_data["filename"] == "passwd.pcap"


def test_pcap_null_byte_rejection():
    """Verify null byte filenames are sanitized."""
    null_name = "exploit\x00test.pcap"
    response = client.post(
        "/api/pcap/upload",
        files={"file": (null_name, b"dummy pcap", "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 200
    data = response.json()
    job_id = data["job_id"]

    status_resp = client.get(f"/api/pcap/status/{job_id}")
    status_data = status_resp.json()
    assert "\x00" not in status_data["filename"]


def test_pcap_size_limit_enforcement(monkeypatch):
    """Verify that uploads exceeding configured PCAP_MAX_FILE_SIZE_MB return 413."""
    from backend.app.config import settings
    # Set limit to 0 MB (forcing any non-empty upload to fail)
    monkeypatch.setattr(settings, "pcap_max_file_size_mb", 0)

    response = client.post(
        "/api/pcap/upload",
        files={"file": ("large.pcap", b"A" * 1024, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 413
    assert "exceeds maximum allowed size" in response.json()["detail"]


@pytest.mark.anyio
async def test_websocket_manager_lifecycle():
    """Verify WebSocketManager connection registration, tracking, and clean disposal."""
    wm = WebSocketManager()
    assert wm.connection_count == 0

    class MockWebSocket:
        def __init__(self):
            self.accepted = False
            self.closed = False
            self.sent_messages = []

        async def accept(self):
            self.accepted = True

        async def send_json(self, data):
            self.sent_messages.append(data)

        async def close(self, code=1000, reason=""):
            self.closed = True

    ws1 = MockWebSocket()
    ws2 = MockWebSocket()

    await wm.connect(ws1)
    await wm.connect(ws2)
    assert wm.connection_count == 2
    assert ws1.accepted is True

    # Broadcast message
    await wm.broadcast({"type": "ALERT", "id": "123"})
    assert len(ws1.sent_messages) == 1
    assert len(ws2.sent_messages) == 1

    # Disconnect single
    wm.disconnect(ws1)
    assert wm.connection_count == 1

    # Close all on shutdown
    await wm.close_all()
    assert wm.connection_count == 0
    assert ws2.closed is True
