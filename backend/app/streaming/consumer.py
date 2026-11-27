"""Real-time stream consumer: pseudonymize -> detect -> persist -> WebSocket broadcast."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.database import init_db_globals, session_scope
from app.detection.engine import ThreatDetectionEngine
from app.detection.rules import PseudonymizedEventInput
from app.models.db import Alert, PrivacySetting, SecurityEvent, ThreatIntelHash
from app.models.schemas import AlertOut, RawSecurityEventIn
from app.privacy.pseudonymizer import Pseudonymizer
from app.streaming.broker import StreamBroker, create_broker, new_consumer_name

logger = logging.getLogger(__name__)


def load_known_bad_hashes(db: Session) -> dict[str, tuple[str, str]]:
    """Load threat-intelligence SHA-256 hashes indexed for O(1) detection lookup."""
    rows = db.execute(select(ThreatIntelHash)).scalars().all()
    return {row.sha256_hash.lower(): (row.malware_family, row.severity) for row in rows}


def process_raw_event(
    db: Session,
    *,
    settings: Settings,
    pseudonymizer: Pseudonymizer,
    detector: ThreatDetectionEngine,
    raw_payload: dict,
    known_bad_hashes: dict[str, tuple[str, str]] | None = None,
) -> tuple[SecurityEvent, list[AlertOut]]:
    """Pseudonymize an inbound event, run rules + ML detection, and persist results."""
    raw_event = RawSecurityEventIn(**raw_payload)
    ev_ts = raw_event.timestamp or datetime.now(UTC)
    if ev_ts.tzinfo is None:
        ev_ts = ev_ts.replace(tzinfo=UTC)

    privacy_cfg = db.execute(select(PrivacySetting).where(PrivacySetting.id == 1)).scalar_one_or_none()
    rot_hours = privacy_cfg.hmac_rotation_hours if privacy_cfg else settings.hmac_rotation_hours
    ret_days = privacy_cfg.retention_days if privacy_cfg else settings.default_retention_days

    tokens_map, _ = pseudonymizer.pseudonymize_event(
        db,
        raw_event,
        rotation_hours=rot_hours,
        retention_days=ret_days,
    )

    sec_event = SecurityEvent(
        event_type=raw_event.event_type,
        timestamp=ev_ts,
        region=raw_event.region,
        username_token=tokens_map["username_token"],
        email_token=tokens_map["email_token"],
        source_ip_token=tokens_map["source_ip_token"],
        dest_ip_token=tokens_map["dest_ip_token"],
        dest_port=raw_event.dest_port,
        bytes_out=raw_event.bytes_out,
        auth_success=raw_event.auth_success,
        file_hash=raw_event.file_hash,
        anomaly_score=0.0,
        is_anomaly=False,
        raw_metadata={
            k: v
            for k, v in (raw_event.metadata or {}).items()
            if k.lower() not in {"username", "email", "ip", "source_ip", "dest_ip"}
        },
    )
    db.add(sec_event)
    db.flush()

    det_input = PseudonymizedEventInput(
        event_id=sec_event.id,
        event_type=sec_event.event_type,
        timestamp=ev_ts,
        region=sec_event.region,
        username_token=sec_event.username_token,
        email_token=sec_event.email_token,
        source_ip_token=sec_event.source_ip_token,
        dest_ip_token=sec_event.dest_ip_token,
        dest_port=sec_event.dest_port,
        bytes_out=sec_event.bytes_out,
        auth_success=sec_event.auth_success,
        file_hash=sec_event.file_hash,
    )

    intel = known_bad_hashes if known_bad_hashes is not None else load_known_bad_hashes(db)
    outcome = detector.evaluate(det_input, known_bad_hashes=intel)
    sec_event.anomaly_score = outcome.anomaly_score
    sec_event.is_anomaly = outcome.is_anomaly

    created_alerts: list[AlertOut] = []
    for match in outcome.alerts:
        alert_row = Alert(
            title=match.title,
            severity=match.severity,
            status="new",
            rule_id=match.rule_id,
            mitre_technique_id=match.mitre.technique_id,
            mitre_technique_name=match.mitre.technique_name,
            mitre_tactic=match.mitre.tactic,
            explanation=match.explanation,
            anomaly_score=outcome.anomaly_score,
            entity_tokens=match.entity_tokens,
            event_ids=match.event_ids,
            region=match.region,
        )
        db.add(alert_row)
        db.flush()
        created_alerts.append(AlertOut.model_validate(alert_row))

    return sec_event, created_alerts


class StreamConsumerWorker:
    """Async worker consuming Redis Streams and publishing sub-second alert broadcasts."""

    def __init__(
        self,
        *,
        settings: Settings,
        broker: StreamBroker,
        session_factory: sessionmaker[Session],
        detector: ThreatDetectionEngine | None = None,
    ) -> None:
        self.settings = settings
        self.broker = broker
        self.session_factory = session_factory
        self.pseudonymizer = Pseudonymizer(settings)
        self.detector = detector or ThreatDetectionEngine()
        self.consumer_name = new_consumer_name()
        self._running = False
        self._cached_hashes: dict[str, tuple[str, str]] = {}
        self._last_hash_refresh = 0.0

    def _get_threat_hashes(self, db: Session) -> dict[str, tuple[str, str]]:
        now = time.monotonic()
        if not self._cached_hashes or (now - self._last_hash_refresh) > 15.0:
            self._cached_hashes = load_known_bad_hashes(db)
            self._last_hash_refresh = now
        return self._cached_hashes

    async def process_once(self, *, count: int = 25, block_ms: int = 200) -> tuple[int, int]:
        """Read and process a single batch from the stream. Returns (events_count, alerts_count)."""
        entries = await self.broker.read_events(self.consumer_name, count=count, block_ms=block_ms)
        if not entries:
            return 0, 0

        t0 = time.perf_counter()
        events_processed = 0
        alerts_to_broadcast: list[AlertOut] = []
        ack_ids: list[str] = []

        def _process_batch() -> None:
            nonlocal events_processed
            with session_scope(self.session_factory) as db:
                intel = self._get_threat_hashes(db)
                for entry_id, payload in entries:
                    try:
                        _, alerts = process_raw_event(
                            db,
                            settings=self.settings,
                            pseudonymizer=self.pseudonymizer,
                            detector=self.detector,
                            raw_payload=payload,
                            known_bad_hashes=intel,
                        )
                        events_processed += 1
                        alerts_to_broadcast.extend(alerts)
                        ack_ids.append(entry_id)
                    except Exception:
                        logger.exception("Failed processing stream entry %s", entry_id)
                        ack_ids.append(entry_id)

        await asyncio.to_thread(_process_batch)
        await self.broker.ack_events(ack_ids)

        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        for alert in alerts_to_broadcast:
            await self.broker.broadcast_alert(alert.model_dump(mode="json"))

        if events_processed > 0:
            await self.broker.broadcast_metrics(
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "events_processed": events_processed,
                    "alerts_triggered": len(alerts_to_broadcast),
                    "latency_ms": latency_ms,
                }
            )
        return events_processed, len(alerts_to_broadcast)

    async def run_forever(self) -> None:
        self._running = True
        await self.broker.ensure_group()
        logger.info("StreamConsumerWorker %s started", self.consumer_name)
        while self._running:
            try:
                await self.process_once(count=30, block_ms=200)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in consumer loop; retrying shortly")
                await asyncio.sleep(0.5)

    def stop(self) -> None:
        self._running = False


async def _main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    _, sf = init_db_globals(settings)
    broker = create_broker(settings)
    worker = StreamConsumerWorker(settings=settings, broker=broker, session_factory=sf)
    try:
        await worker.run_forever()
    finally:
        await broker.close()


if __name__ == "__main__":
    asyncio.run(_main())
