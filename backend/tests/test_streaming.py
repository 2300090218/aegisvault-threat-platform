"""Tests for streaming pipeline (Redis Streams via FakeRedis + MemoryStreamBroker + Consumer + Generator)."""

from __future__ import annotations

import time

import fakeredis.aioredis
import pytest
from sqlalchemy import select

from app.models.db import Alert, PiiVaultEntry, SecurityEvent, ThreatIntelHash
from app.streaming.broker import MemoryStreamBroker, RedisStreamBroker
from app.streaming.consumer import StreamConsumerWorker
from app.streaming.generator import (
    KNOWN_MALICIOUS_SAMPLE_HASH,
    build_normal_event,
    enqueue_scenario,
    run_demo_burst,
)


@pytest.mark.asyncio
async def test_memory_broker_and_consumer_subsecond_pipeline(db_session_factory, test_settings) -> None:
    with db_session_factory() as db:
        db.add(
            ThreatIntelHash(
                sha256_hash=KNOWN_MALICIOUS_SAMPLE_HASH,
                malware_family="EmotetLoader",
                severity="critical",
                source="unit-test",
            )
        )
        db.commit()

    broker = MemoryStreamBroker()
    worker = StreamConsumerWorker(
        settings=test_settings,
        broker=broker,
        session_factory=db_session_factory,
    )

    received_alerts: list[dict] = []

    async def _collect() -> None:
        async for kind, payload in broker.subscribe_broadcasts():
            if kind == "alert":
                received_alerts.append(payload)

    import asyncio

    sub_task = asyncio.create_task(_collect())
    await asyncio.sleep(0.02)

    await run_demo_burst(broker)
    t0 = time.perf_counter()
    total_events = 0
    total_alerts = 0
    for _ in range(5):
        ev_cnt, al_cnt = await worker.process_once(count=50, block_ms=50)
        total_events += ev_cnt
        total_alerts += al_cnt
        if ev_cnt == 0:
            break
    elapsed_sec = time.perf_counter() - t0
    await asyncio.sleep(0.02)
    sub_task.cancel()

    assert elapsed_sec < 1.0
    assert total_events >= 20
    assert total_alerts >= 5
    assert len(received_alerts) == total_alerts

    rule_ids = {a["rule_id"] for a in received_alerts}
    assert {
        "RULE_BRUTE_FORCE",
        "RULE_IMPOSSIBLE_TRAVEL",
        "RULE_DATA_EXFILTRATION",
        "RULE_PORT_SCAN",
        "RULE_THREAT_INTEL_HASH",
    }.issubset(rule_ids)

    with db_session_factory() as db:
        events = db.execute(select(SecurityEvent)).scalars().all()
        alerts = db.execute(select(Alert)).scalars().all()
        vault = db.execute(select(PiiVaultEntry)).scalars().all()
        assert len(events) == total_events
        assert len(alerts) == total_alerts
        assert len(vault) > 0
        # Confirm no raw usernames/IPs stored on events
        for ev in events:
            if ev.username_token:
                assert ev.username_token.startswith("usr_")
            if ev.source_ip_token:
                assert ev.source_ip_token.startswith("ip_")

    await broker.close()


@pytest.mark.asyncio
async def test_redis_stream_broker_with_fakeredis(db_session_factory, test_settings) -> None:
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    broker = RedisStreamBroker(
        redis_url="redis://unused",
        stream_key="events:raw",
        consumer_group="threat-detectors",
        alert_channel="alerts:broadcast",
        metrics_channel="metrics:broadcast",
        client=fake_redis,
    )
    worker = StreamConsumerWorker(
        settings=test_settings,
        broker=broker,
        session_factory=db_session_factory,
    )

    sids = await enqueue_scenario(broker, scenario="data_exfiltration", count=1, region="eu-west")
    assert len(sids) == 1
    sid_norm = await broker.publish_raw_event(build_normal_event())
    assert sid_norm

    ev_cnt, al_cnt = await worker.process_once(count=10, block_ms=50)
    assert ev_cnt == 2
    assert al_cnt == 1

    with db_session_factory() as db:
        alerts = db.execute(select(Alert)).scalars().all()
        assert len(alerts) == 1
        assert alerts[0].mitre_technique_id == "T1041"

    await broker.close()
