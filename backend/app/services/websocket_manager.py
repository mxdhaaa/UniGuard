"""
UniGuard WebSocket Connection Manager (Milestone 9, Hardened in Milestone 15)

Maintains in-process WebSocket connections and broadcasts
real-time alert events to connected SOC/dashboard clients.
Includes clean lifecycle logging and graceful shutdown cleanup.
"""

import logging
from typing import List

from fastapi import WebSocket

logger = logging.getLogger("uniguard.websocket")


class WebSocketManager:
    """Manage active WebSocket connections for real-time alerts."""

    def __init__(self) -> None:
        self._connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a WebSocket connection."""
        await websocket.accept()
        self._connections.append(websocket)
        logger.info(
            "WebSocket client connected. Active connections: %d",
            len(self._connections)
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection if it is currently registered."""
        if websocket in self._connections:
            self._connections.remove(websocket)
            logger.info(
                "WebSocket client disconnected. Remaining connections: %d",
                len(self._connections)
            )

    @property
    def connection_count(self) -> int:
        """Return the number of currently registered connections."""
        return len(self._connections)

    async def broadcast(self, message: dict) -> None:
        """
        Broadcast a JSON-serializable message to all connected clients.

        A failed/disconnected client is removed without preventing
        delivery to the remaining clients.
        """
        disconnected: List[WebSocket] = []

        for websocket in list(self._connections):
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.warning("Failed to deliver alert to client, marking disconnected: %s", e)
                disconnected.append(websocket)

        for websocket in disconnected:
            self.disconnect(websocket)

    async def close_all(self, code: int = 1001, reason: str = "Server shutting down") -> None:
        """
        Close all registered WebSocket connections cleanly during application shutdown.
        """
        total = len(self._connections)
        if total > 0:
            logger.info("Closing %d active WebSocket connection(s) on shutdown...", total)
            for websocket in list(self._connections):
                try:
                    await websocket.close(code=code, reason=reason)
                except Exception:
                    pass
            self._connections.clear()
            logger.info("All WebSocket connections closed.")


websocket_manager = WebSocketManager()