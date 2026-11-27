"""Security event ingestion, listing (pseudonymized), and attack simulation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_broker, get_current_user, require_roles
from app.core.config import Settings
from app.core.database import get_db
from app.core.security import UserRole
from app.detection.engine import ThreatDetectionEngine
from app.models.db import SecurityEvent, User
from app.models.schemas import (
    AlertOut,
    IngestResponse,
    RawSecurityEventIn,
    SecurityEventOut,
    SimulateAttackRequest,
    SimulateAttackResponse,
)
from app.privacy.audit import append_audit_log
from app.privacy.pseudonymizer import Pseudonymizer
from app.streaming.broker import StreamBroker
from app.streaming.consumer import load_known_bad_hashes, process_raw_event
from app.streaming.generator import build_attack_events, enqueue_scenario

router = APIRouter(prefix="/events", tags=["events"])


def _get_inline_detector(request: Request) -> ThreatDetectionEngine:
    det = getattr(request.app.state, "inline_detector", None)
    if det is None:
        det = ThreatDetectionEngine()
        request.app.state.inline_detector = det
    return det


@router.post("/ingest", response_model=IngestResponse, status_code=202)
async def ingest_event(
    event: RawSecurityEventIn,
    request: Request,
    broker: StreamBroker = Depends(get_broker),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    _: User = Depends(require_roles(UserRole.ANALYST, UserRole.ADMIN)),
) -> IngestResponse:
    payload = event.model_dump(mode="json")
    stream_id = await broker.publish_raw_event(payload)
    if settings.stream_mode == "inline":
        process_raw_event(
            db,
            settings=settings,
            pseudonymizer=Pseudonymizer(settings),
            detector=_get_inline_detector(request),
            raw_payload=payload,
            known_bad_hashes=load_known_bad_hashes(db),
        )
        db.commit()
    return IngestResponse(stream_id=stream_id, queued=True)


@router.get("", response_model=list[SecurityEventOut])
def list_events(
    event_type: str | None = Query(default=None),
    region: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[SecurityEventOut]:
    stmt = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc())
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    if region:
        stmt = stmt.where(SecurityEvent.region == region)
    rows = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    return [SecurityEventOut.model_validate(r) for r in rows]


@router.post("/simulate", response_model=SimulateAttackResponse, status_code=202)
async def simulate_attack(
    payload: SimulateAttackRequest,
    request: Request,
    broker: StreamBroker = Depends(get_broker),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    current_user: User = Depends(require_roles(UserRole.ANALYST, UserRole.ADMIN)),
) -> SimulateAttackResponse:
    created_alerts: list[AlertOut] = []
    if settings.stream_mode == "inline":
        events = build_attack_events(
            payload.scenario,
            count=payload.count,
            region=payload.region,
        )
        stream_ids: list[str] = []
        pseudonymizer = Pseudonymizer(settings)
        detector = _get_inline_detector(request)
        intel = load_known_bad_hashes(db)
        for ev in events:
            stream_ids.append(await broker.publish_raw_event(ev))
            _, alerts_out = process_raw_event(
                db,
                settings=settings,
                pseudonymizer=pseudonymizer,
                detector=detector,
                raw_payload=ev,
                known_bad_hashes=intel,
            )
            created_alerts.extend(alerts_out)
    else:
        stream_ids = await enqueue_scenario(
            broker,
            scenario=payload.scenario,
            count=payload.count,
            region=payload.region,
        )
    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="ATTACK_SIMULATION_TRIGGERED",
        resource_type="simulation",
        resource_id=payload.scenario,
        details={"scenario": payload.scenario, "count": len(stream_ids), "region": payload.region},
    )
    db.commit()
    return SimulateAttackResponse(
        scenario=payload.scenario,
        events_enqueued=len(stream_ids),
        stream_ids=stream_ids,
        created_alerts=created_alerts,
    )
