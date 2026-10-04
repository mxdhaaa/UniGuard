"""
Tests for WebSocket alert notifications (Milestone 9).
"""

import asyncio
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.websocket_manager import WebSocketManager, websocket_manager

client = TestClient(app)

def test_websocket_accepts_connection():
    """Test that the endpoint accepts connections and stays open."""
    initial_count = websocket_manager.connection_count
    
    with client.websocket_connect("/api/ws/alerts") as websocket:
        assert websocket_manager.connection_count == initial_count + 1
        
    # Should disconnect cleanly
    assert websocket_manager.connection_count == initial_count


def test_websocket_disconnects_cleanly():
    """Test that connection count decreases upon disconnect."""
    initial_count = websocket_manager.connection_count
    
    with client.websocket_connect("/api/ws/alerts") as websocket:
        assert websocket_manager.connection_count == initial_count + 1
        
    assert websocket_manager.connection_count == initial_count


def test_manager_registration_and_disconnection():
    """Test WebSocketManager directly for connect/disconnect logic."""
    manager = WebSocketManager()
    
    class MockWebSocket:
        def __init__(self):
            self.accepted = False
        async def accept(self):
            self.accepted = True

    ws = MockWebSocket()
    asyncio.run(manager.connect(ws)) # type: ignore
    assert ws.accepted
    assert manager.connection_count == 1
    
    manager.disconnect(ws) # type: ignore
    assert manager.connection_count == 0
    # Safe to disconnect again
    manager.disconnect(ws) # type: ignore


def test_manager_broadcast_handles_failure():
    """Test that a failed client does not block others from receiving broadcasts."""
    manager = WebSocketManager()
    
    class FailingWebSocket:
        def __init__(self):
            self.accepted = True
        async def send_json(self, message):
            raise Exception("Network failure")
            
    class SuccessWebSocket:
        def __init__(self):
            self.accepted = True
            self.messages = []
        async def send_json(self, message):
            self.messages.append(message)
            
    ws_fail = FailingWebSocket()
    ws_success = SuccessWebSocket()
    
    manager._connections = [ws_fail, ws_success] # type: ignore
    assert manager.connection_count == 2
    
    asyncio.run(manager.broadcast({"event": "alert.created"}))

    
    # Success client should have received it
    assert len(ws_success.messages) == 1
    assert ws_success.messages[0]["event"] == "alert.created"
    
    # Failed client should be removed, success client remains
    assert manager.connection_count == 1
    assert ws_success in manager._connections # type: ignore
    assert ws_fail not in manager._connections # type: ignore


def test_broadcast_via_testclient():
    """Test sending an actual broadcast while connected."""
    
    # Run the broadcast within the active connection context
    with client.websocket_connect("/api/ws/alerts") as websocket:
        msg = {"event": "alert.created", "alert": {"alert_id": "ALRT-123"}}
        asyncio.run(websocket_manager.broadcast(msg))
        
        data = websocket.receive_json()
        assert data["event"] == "alert.created"
        assert data["alert"]["alert_id"] == "ALRT-123"
