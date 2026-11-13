"""
WebSocket Router & Manager for Real-Time SOC Push Notifications
"""

import json
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        dead_connections = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead_connections.add(connection)
        for dc in dead_connections:
            self.active_connections.discard(dc)

manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial handshake confirmation
        await websocket.send_text(json.dumps({
            "type": "CONNECTED",
            "message": "DiodeGuard SOC Real-time Feed Connected",
        }))
        while True:
            # Keep-alive or handle client incoming messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "PONG"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


async def broadcast_alert(alert_dict: dict):
    """Utility to broadcast a newly detected alert to all connected analysts."""
    await manager.broadcast({
        "type": "NEW_ALERT",
        "data": alert_dict,
    })


async def broadcast_flow(flow_dict: dict):
    """Utility to broadcast flow ingress telemetry."""
    await manager.broadcast({
        "type": "NEW_FLOW",
        "data": flow_dict,
    })
