"""Data minimization and retention enforcement job."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models.db import (
    Alert,
    EventDailyAggregate,
    PiiVaultEntry,
    ReidentificationRequest,
    SecurityEvent,
)
from app.models.schemas import RetentionRunOut
from app.privacy.audit import append_audit_log


def run_retention_policy(
    db: Session,
    *,
    retention_days: int,
    actor_id: str = "system",
    actor_role: str = "system",
) -> RetentionRunOut:
    """Aggregate expired security events into daily summaries and purge raw records + vault PII."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)

    old_events = db.execute(
        select(SecurityEvent).where(SecurityEvent.timestamp < cutoff)
    ).scalars().all()

    buckets: dict[tuple, dict[str, int]] = defaultdict(lambda: {"events": 0, "alerts": 0})
    for ev in old_events:
        ev_date = ev.timestamp.date()
        buckets[(ev_date, ev.region, ev.event_type)]["events"] += 1

    old_alerts = db.execute(select(Alert).where(Alert.created_at < cutoff)).scalars().all()
    for al in old_alerts:
        al_date = al.created_at.date()
        buckets[(al_date, al.region, "alert")]["alerts"] += 1

    for (bucket_date, region, event_type), counts in buckets.items():
        existing = db.execute(
            select(EventDailyAggregate).where(
                EventDailyAggregate.bucket_date == bucket_date,
                EventDailyAggregate.region == region,
                EventDailyAggregate.event_type == event_type,
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.event_count += counts["events"]
            existing.alert_count += counts["alerts"]
        else:
            db.add(
                EventDailyAggregate(
                    bucket_date=bucket_date,
                    region=region,
                    event_type=event_type,
                    event_count=counts["events"],
                    alert_count=counts["alerts"],
                )
            )

    events_deleted = 0
    if old_events:
        old_ids = [ev.id for ev in old_events]
        res = db.execute(
            delete(SecurityEvent)
            .where(SecurityEvent.id.in_(old_ids))
            .execution_options(synchronize_session=False)
        )
        events_deleted = int(res.rowcount or len(old_ids))
        db.expire_all()

    # Preserve vault entries actively referenced by an approved, unexpired break-glass grant
    active_grants = db.execute(
        select(ReidentificationRequest).where(
            ReidentificationRequest.status == "approved",
            ReidentificationRequest.expires_at > now,
        )
    ).scalars().all()
    protected_tokens: set[str] = set()
    for grant in active_grants:
        protected_tokens.update(grant.requested_tokens or [])

    expired_vault = db.execute(
        select(PiiVaultEntry).where(
            (PiiVaultEntry.created_at < cutoff)
            | (PiiVaultEntry.expires_at.is_not(None) & (PiiVaultEntry.expires_at < now))
        )
    ).scalars().all()

    vault_deleted = 0
    for entry in expired_vault:
        if entry.token not in protected_tokens:
            db.delete(entry)
            vault_deleted += 1

    append_audit_log(
        db,
        actor_id=actor_id,
        actor_role=actor_role,
        action="RETENTION_POLICY_EXECUTED",
        resource_type="retention_policy",
        resource_id=f"days:{retention_days}",
        details={
            "retention_days": retention_days,
            "events_aggregated": len(old_events),
            "events_deleted": events_deleted,
            "vault_entries_deleted": vault_deleted,
        },
    )
    db.flush()

    return RetentionRunOut(
        cutoff_timestamp=cutoff,
        events_aggregated=len(old_events),
        events_deleted=events_deleted,
        vault_entries_deleted=vault_deleted,
    )
