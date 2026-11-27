"""Append-only, SHA-256 hash-chained audit trail and integrity verifier."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db import AuditLog
from app.models.schemas import AuditVerifyOut

GENESIS_HASH = "0" * 64
FORBIDDEN_DETAIL_KEYS = {"raw_ip", "raw_email", "raw_username", "password", "plaintext"}


def _canonical_ts(ts: datetime) -> str:
    utc_dt = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_entry_hash(
    *,
    timestamp: datetime,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute SHA-256 hash binding this audit event to the previous chain link."""
    payload = {
        "timestamp": _canonical_ts(timestamp),
        "actor_id": actor_id,
        "actor_role": actor_role,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
        "prev_hash": prev_hash,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sanitize_details(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}
    return {k: v for k, v in details.items() if k.lower() not in FORBIDDEN_DETAIL_KEYS}


def append_audit_log(
    db: Session,
    *,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append a tamper-evident entry chained to the latest audit record."""
    latest = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one_or_none()
    prev_hash = latest.entry_hash if latest is not None else GENESIS_HASH
    now = datetime.now(UTC)
    clean_details = _sanitize_details(details)
    entry_hash = compute_entry_hash(
        timestamp=now,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=clean_details,
        prev_hash=prev_hash,
    )
    row = AuditLog(
        timestamp=now,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=clean_details,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(row)
    db.flush()
    return row


def verify_audit_chain(db: Session) -> AuditVerifyOut:
    """Recompute and verify every hash link in the audit log table."""
    entries = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    if not entries:
        return AuditVerifyOut(
            valid=True,
            checked_entries=0,
            broken_at_id=None,
            latest_hash=GENESIS_HASH,
            message="Audit chain is empty (genesis state valid).",
        )

    expected_prev = GENESIS_HASH
    for entry in entries:
        if entry.prev_hash != expected_prev:
            return AuditVerifyOut(
                valid=False,
                checked_entries=len(entries),
                broken_at_id=entry.id,
                latest_hash=entries[-1].entry_hash,
                message=f"Chain break detected at audit entry {entry.id}: prev_hash mismatch.",
            )
        recomputed = compute_entry_hash(
            timestamp=entry.timestamp,
            actor_id=entry.actor_id,
            actor_role=entry.actor_role,
            action=entry.action,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            details=entry.details,
            prev_hash=entry.prev_hash,
        )
        if entry.entry_hash != recomputed:
            return AuditVerifyOut(
                valid=False,
                checked_entries=len(entries),
                broken_at_id=entry.id,
                latest_hash=entries[-1].entry_hash,
                message=f"Tampered audit record detected at entry {entry.id}: entry_hash mismatch.",
            )
        expected_prev = entry.entry_hash

    return AuditVerifyOut(
        valid=True,
        checked_entries=len(entries),
        broken_at_id=None,
        latest_hash=entries[-1].entry_hash,
        message=f"All {len(entries)} audit log entries verified cryptographically intact.",
    )
