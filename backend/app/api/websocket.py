"""
UniGuard WebSocket API (Milestone 9)

Real-time WebSocket endpoint for SOC alert notifications.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.services.websocket_manager import websocket_manager


router = APIRouter()


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket) -> None:
    """
    Maintain a real-time connection for alert notifications.

    Clients remain connected until they disconnect. Alert broadcasts
    are initiated by the persistence layer after successful commits.
    """
    await websocket_manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
    except Exception:
        websocket_manager.disconnect(websocket)