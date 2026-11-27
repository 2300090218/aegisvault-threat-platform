"""WebSocket endpoint and connection manager for sub-second live alert & metric streaming."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.config import Settings
from app.core.security import AuthenticationError, decode_access_token
from app.streaming.broker import StreamBroker

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ws"])


class ConnectionManager:
    """Tracks active authenticated WebSocket clients and broadcasts JSON events."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        async with self._lock:
            targets = list(self._connections)
        stale: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)
        if stale:
            async with self._lock:
                for ws in stale:
                    self._connections.discard(ws)


ws_manager = ConnectionManager()


async def broadcast_listener_loop(broker: StreamBroker, manager: ConnectionManager) -> None:
    """Subscribe to Redis Pub/Sub (or in-memory broker) and push updates to WebSocket clients."""
    while True:
        try:
            async for kind, payload in broker.subscribe_broadcasts():
                await manager.broadcast({"type": kind, "data": payload})
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("WebSocket broadcast listener error; reconnecting in 1s")
            await asyncio.sleep(1.0)


@router.websocket("/ws/alerts")
async def alerts_websocket(
    websocket: WebSocket,
    token: str | None = Query(default=None),
) -> None:
    settings: Settings = websocket.app.state.settings
    if not token:
        await websocket.close(code=4401, reason="Missing token")
        return
    try:
        user_claims = decode_access_token(token, settings)
    except AuthenticationError:
        await websocket.close(code=4401, reason="Invalid or expired token")
        return

    await ws_manager.connect(websocket)
    await websocket.send_json(
        {
            "type": "connected",
            "data": {"username": user_claims.sub, "role": user_claims.role.value},
        }
    )
    try:
        while True:
            # Keep socket alive and consume ping/heartbeat messages from clients
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong", "data": {}})
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)
