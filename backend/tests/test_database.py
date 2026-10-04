"""
Tests for database connectivity and initialization.
"""

from backend.app.db.database import check_db_health, engine
from backend.app.db.init_db import init_db
from backend.app.db.models import Base

def test_check_db_health_succeeds_with_sqlite():
    """SQLite in-memory or file should pass health check."""
    assert check_db_health() is True

def test_init_db_creates_tables():
    """Verify init_db doesn't raise errors and creates metadata."""
    init_db()
    # Check that a table exists
    assert "traffic_flows" in Base.metadata.tables.keys()

def test_check_db_health_fails_when_unreachable(monkeypatch):
    """Simulate a broken database connection."""
    def broken_connect(*args, **kwargs):
        raise Exception("Connection failed")
    
    # Monkeypatch the engine's connect method
    monkeypatch.setattr(engine, "connect", broken_connect)
    
    assert check_db_health() is False
