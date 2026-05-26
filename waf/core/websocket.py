import asyncio
import json
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.incident_queue: asyncio.Queue = asyncio.Queue()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_incident(self, incident: dict[str, Any]):
        data = json.dumps(incident)
        for connection in self.active_connections[:]:
            try:
                await connection.send_text(data)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


async def broadcast_incident(incident: dict[str, Any]):
    await manager.broadcast_incident(incident)
