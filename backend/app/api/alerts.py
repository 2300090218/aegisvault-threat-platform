"""Threat alerts query, detail timeline, and workflow status transition endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.database import get_db
from app.core.security import UserRole
from app.models.db import Alert, ReidentificationRequest, SecurityEvent, User
from app.models.schemas import (
    AlertDetailOut,
    AlertOut,
    AlertStatusUpdate,
    ReidentificationRequestOut,
    SecurityEventOut,
)
from app.privacy.audit import append_audit_log

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _enrich_request(db: Session, req: ReidentificationRequest) -> ReidentificationRequestOut:
    requester = db.execute(select(User.username).where(User.id == req.requester_id)).scalar_one_or_none()
    reviewer = (
        db.execute(select(User.username).where(User.id == req.reviewer_id)).scalar_one_or_none()
        if req.reviewer_id
        else None
    )
    return ReidentificationRequestOut(
        id=req.id,
        alert_id=req.alert_id,
        requester_id=req.requester_id,
        requester_username=requester,
        reviewer_id=req.reviewer_id,
        reviewer_username=reviewer,
        requested_tokens=req.requested_tokens,
        justification=req.justification,
        status=req.status,
        decision_note=req.decision_note,
        created_at=req.created_at,
        reviewed_at=req.reviewed_at,
        expires_at=req.expires_at,
    )


@router.get("", response_model=list[AlertOut])
def list_alerts(
    alert_status: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[AlertOut]:
    stmt = select(Alert).order_by(Alert.created_at.desc())
    if alert_status:
        stmt = stmt.where(Alert.status == alert_status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    rows = db.execute(stmt.limit(limit)).scalars().all()
    return [AlertOut.model_validate(r) for r in rows]


@router.get("/{alert_id}", response_model=AlertDetailOut)
def get_alert_detail(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertDetailOut:
    alert = db.execute(select(Alert).where(Alert.id == alert_id)).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    timeline_rows: list[SecurityEvent] = []
    if alert.event_ids:
        timeline_rows = (
            db.execute(
                select(SecurityEvent)
                .where(SecurityEvent.id.in_(alert.event_ids))
                .order_by(SecurityEvent.timestamp.asc())
            )
            .scalars()
            .all()
        )

    req_stmt = select(ReidentificationRequest).where(ReidentificationRequest.alert_id == alert.id)
    if current_user.role not in (UserRole.PRIVACY_OFFICER.value, UserRole.ADMIN.value):
        req_stmt = req_stmt.where(ReidentificationRequest.requester_id == current_user.id)
    reqs = db.execute(req_stmt.order_by(ReidentificationRequest.created_at.desc())).scalars().all()

    return AlertDetailOut(
        alert=AlertOut.model_validate(alert),
        timeline_events=[SecurityEventOut.model_validate(e) for e in timeline_rows],
        reidentification_requests=[_enrich_request(db, r) for r in reqs],
    )


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ANALYST, UserRole.ADMIN)),
) -> AlertOut:
    alert = db.execute(select(Alert).where(Alert.id == alert_id)).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    prev_status = alert.status
    alert.status = payload.status
    alert.updated_at = datetime.now(UTC)

    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="ALERT_STATUS_UPDATED",
        resource_type="alert",
        resource_id=alert.id,
        details={"from": prev_status, "to": payload.status},
    )
    db.commit()
    db.refresh(alert)
    return AlertOut.model_validate(alert)
