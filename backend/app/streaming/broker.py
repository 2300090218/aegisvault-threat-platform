"""Stream and Pub/Sub broker supporting Redis Streams and in-memory transport."""

from __future__ import annotations

import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import AsyncIterator
from typing import Any

import redis.asyncio as aioredis

from app.core.config import Settings


class StreamBroker(ABC):
    """Abstract interface over Redis Streams + Pub/Sub for multi-process or in-memory execution."""

    @abstractmethod
    async def ensure_group(self) -> None:
        """Create the consumer group on the stream if it does not exist."""

    @abstractmethod
    async def publish_raw_event(self, payload: dict[str, Any]) -> str:
        """Append a raw security event payload to the stream and return its stream ID."""

    @abstractmethod
    async def read_events(
        self, consumer_name: str, *, count: int = 20, block_ms: int = 250
    ) -> list[tuple[str, dict[str, Any]]]:
        """Read unacknowledged messages for the consumer group."""

    @abstractmethod
    async def ack_events(self, entry_ids: list[str]) -> int:
        """Acknowledge processed stream messages."""

    @abstractmethod
    async def broadcast_alert(self, alert_payload: dict[str, Any]) -> None:
        """Publish a detected alert to real-time WebSocket subscribers."""

    @abstractmethod
    async def broadcast_metrics(self, metrics_payload: dict[str, Any]) -> None:
        """Publish live ingestion/detection throughput metrics."""

    @abstractmethod
    def subscribe_broadcasts(self) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        """Yield (event_kind, payload) tuples for WebSocket fanout."""

    @abstractmethod
    async def close(self) -> None:
        """Release underlying connections."""


class RedisStreamBroker(StreamBroker):
    """Production Redis Streams + Redis Pub/Sub broker."""

    def __init__(
        self,
        *,
        redis_url: str,
        stream_key: str,
        consumer_group: str,
        alert_channel: str,
        metrics_channel: str,
        client: aioredis.Redis | None = None,
    ) -> None:
        self.stream_key = stream_key
        self.consumer_group = consumer_group
        self.alert_channel = alert_channel
        self.metrics_channel = metrics_channel
        self.client: aioredis.Redis = client or aioredis.from_url(redis_url, decode_responses=True)

    async def ensure_group(self) -> None:
        try:
            await self.client.xgroup_create(
                name=self.stream_key,
                groupname=self.consumer_group,
                id="0",
                mkstream=True,
            )
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def publish_raw_event(self, payload: dict[str, Any]) -> str:
        entry_id = await self.client.xadd(
            self.stream_key,
            {"payload": json.dumps(payload, default=str)},
            maxlen=50_000,
            approximate=True,
        )
        return str(entry_id)

    async def read_events(
        self, consumer_name: str, *, count: int = 20, block_ms: int = 250
    ) -> list[tuple[str, dict[str, Any]]]:
        await self.ensure_group()
        rows = await self.client.xreadgroup(
            groupname=self.consumer_group,
            consumername=consumer_name,
            streams={self.stream_key: ">"},
            count=count,
            block=block_ms,
        )
        parsed: list[tuple[str, dict[str, Any]]] = []
        for _stream, entries in rows or []:
            for entry_id, fields in entries:
                raw_json = fields.get("payload") or fields.get(b"payload")
                if isinstance(raw_json, bytes):
                    raw_json = raw_json.decode("utf-8")
                if raw_json:
                    eid = entry_id.decode("utf-8") if isinstance(entry_id, bytes) else str(entry_id)
                    parsed.append((eid, json.loads(raw_json)))
        return parsed

    async def ack_events(self, entry_ids: list[str]) -> int:
        if not entry_ids:
            return 0
        return int(await self.client.xack(self.stream_key, self.consumer_group, *entry_ids))

    async def broadcast_alert(self, alert_payload: dict[str, Any]) -> None:
        await self.client.publish(self.alert_channel, json.dumps(alert_payload, default=str))

    async def broadcast_metrics(self, metrics_payload: dict[str, Any]) -> None:
        await self.client.publish(self.metrics_channel, json.dumps(metrics_payload, default=str))

    async def subscribe_broadcasts(self) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        pubsub = self.client.pubsub()
        await pubsub.subscribe(self.alert_channel, self.metrics_channel)
        try:
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                channel = msg.get("channel")
                if isinstance(channel, bytes):
                    channel = channel.decode("utf-8")
                data = msg.get("data")
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                kind = "alert" if channel == self.alert_channel else "metrics"
                yield kind, json.loads(data)
        finally:
            await pubsub.unsubscribe(self.alert_channel, self.metrics_channel)
            await pubsub.aclose()

    async def close(self) -> None:
        await self.client.aclose()


class MemoryStreamBroker(StreamBroker):
    """In-memory async StreamBroker for unit tests and single-process embedded execution."""

    def __init__(self) -> None:
        self._queue: deque[tuple[str, dict[str, Any]]] = deque()
        self._notify: asyncio.Event | None = None
        self._notify_loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: set[asyncio.Queue[tuple[str, dict[str, Any]]]] = set()
        self._seq = 0

    def _get_notify(self) -> asyncio.Event:
        loop = asyncio.get_running_loop()
        if self._notify is None or self._notify_loop is not loop:
            self._notify = asyncio.Event()
            self._notify_loop = loop
        return self._notify

    async def ensure_group(self) -> None:
        return None

    async def publish_raw_event(self, payload: dict[str, Any]) -> str:
        self._seq += 1
        entry_id = f"{self._seq}-0"
        self._queue.append((entry_id, payload))
        self._get_notify().set()
        return entry_id

    async def read_events(
        self, consumer_name: str, *, count: int = 20, block_ms: int = 250
    ) -> list[tuple[str, dict[str, Any]]]:
        notify = self._get_notify()
        if not self._queue:
            notify.clear()
            try:
                await asyncio.wait_for(notify.wait(), timeout=block_ms / 1000.0)
            except TimeoutError:
                return []
        batch: list[tuple[str, dict[str, Any]]] = []
        while self._queue and len(batch) < count:
            batch.append(self._queue.popleft())
        if not self._queue:
            notify.clear()
        return batch

    async def ack_events(self, entry_ids: list[str]) -> int:
        return len(entry_ids)

    async def _fanout(self, kind: str, payload: dict[str, Any]) -> None:
        for q in list(self._subscribers):
            await q.put((kind, payload))

    async def broadcast_alert(self, alert_payload: dict[str, Any]) -> None:
        await self._fanout("alert", alert_payload)

    async def broadcast_metrics(self, metrics_payload: dict[str, Any]) -> None:
        await self._fanout("metrics", metrics_payload)

    async def subscribe_broadcasts(self) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        q: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()
        self._subscribers.add(q)
        try:
            while True:
                item = await q.get()
                yield item
        finally:
            self._subscribers.discard(q)

    async def close(self) -> None:
        self._subscribers.clear()
        self._notify = None
        self._notify_loop = None
        global _memory_broker
        if _memory_broker is self:
            _memory_broker = None


class InlineStreamBroker(StreamBroker):
    """Serverless-compatible no-op broker when events are processed inline per request."""

    def __init__(self) -> None:
        self._seq = 0

    async def ensure_group(self) -> None:
        return None

    async def publish_raw_event(self, payload: dict[str, Any]) -> str:
        self._seq += 1
        return f"inline-{self._seq}"

    async def read_events(
        self, consumer_name: str, *, count: int = 20, block_ms: int = 250
    ) -> list[tuple[str, dict[str, Any]]]:
        return []

    async def ack_events(self, entry_ids: list[str]) -> int:
        return len(entry_ids)

    async def broadcast_alert(self, alert_payload: dict[str, Any]) -> None:
        return None

    async def broadcast_metrics(self, metrics_payload: dict[str, Any]) -> None:
        return None

    async def subscribe_broadcasts(self) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        if False:  # pragma: no cover
            yield ("alert", {})

    async def close(self) -> None:
        return None


_memory_broker: MemoryStreamBroker | None = None


def create_broker(settings: Settings) -> StreamBroker:
    """Create a configured StreamBroker from Settings."""
    if settings.stream_mode == "inline":
        return InlineStreamBroker()
    if settings.stream_mode == "memory":
        global _memory_broker
        if _memory_broker is None:
            _memory_broker = MemoryStreamBroker()
        return _memory_broker

    return RedisStreamBroker(
        redis_url=settings.redis_url,
        stream_key=settings.redis_stream_key,
        consumer_group=settings.redis_consumer_group,
        alert_channel=settings.redis_alert_channel,
        metrics_channel=settings.redis_metrics_channel,
    )


def new_consumer_name() -> str:
    return f"detector-{uuid.uuid4().hex[:8]}"
