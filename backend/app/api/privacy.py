"""Privacy Console API: epsilon tuning, key rotation, break-glass, audit log, retention, PSI."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.alerts import _enrich_request
from app.api.deps import get_app_settings, get_current_user, require_roles
from app.core.config import Settings
from app.core.database import get_db
from app.core.security import UserRole
from app.models.db import (
    Alert,
    AuditLog,
    PrivacySetting,
    ReidentificationRequest,
    ThreatIntelHash,
    User,
)
from app.models.schemas import (
    AuditLogOut,
    AuditVerifyOut,
    EpsilonUpdateRequest,
    KeyRotationOut,
    PrivacySettingsOut,
    PsiCheckRequest,
    PsiCheckResponse,
    ReidentificationCreateRequest,
    ReidentificationDecisionRequest,
    ReidentificationRequestOut,
    ReidentificationRevealOut,
    RetentionRunOut,
    RetentionRunRequest,
)
from app.privacy.audit import append_audit_log, verify_audit_chain
from app.privacy.pseudonymizer import ensure_active_hmac_key, rotate_hmac_key
from app.privacy.psi import PsiServer, derive_server_scalar
from app.privacy.retention import run_retention_policy
from app.privacy.vault import reveal_vault_tokens
from app.streaming.generator import KNOWN_MALICIOUS_SAMPLE_HASH

router = APIRouter(prefix="/privacy", tags=["privacy"])


def _get_or_create_settings(db: Session, settings: Settings) -> PrivacySetting:
    cfg = db.execute(select(PrivacySetting).where(PrivacySetting.id == 1)).scalar_one_or_none()
    if cfg is None:
        cfg = PrivacySetting(
            id=1,
            dp_epsilon=settings.default_dp_epsilon,
            retention_days=settings.default_retention_days,
            hmac_rotation_hours=settings.hmac_rotation_hours,
            updated_by="system",
        )
        db.add(cfg)
        db.flush()
    return cfg


@router.get("/settings", response_model=PrivacySettingsOut)
def get_privacy_settings(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    _: User = Depends(get_current_user),
) -> PrivacySettingsOut:
    cfg = _get_or_create_settings(db, settings)
    key_id, _, _ = ensure_active_hmac_key(db, settings)
    db.commit()
    return PrivacySettingsOut(
        dp_epsilon=cfg.dp_epsilon,
        retention_days=cfg.retention_days,
        hmac_rotation_hours=cfg.hmac_rotation_hours,
        active_key_id=key_id,
        updated_at=cfg.updated_at,
        updated_by=cfg.updated_by,
    )


@router.patch("/settings/epsilon", response_model=PrivacySettingsOut)
def update_epsilon(
    payload: EpsilonUpdateRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    current_user: User = Depends(require_roles(UserRole.PRIVACY_OFFICER, UserRole.ADMIN)),
) -> PrivacySettingsOut:
    cfg = _get_or_create_settings(db, settings)
    prev_eps = cfg.dp_epsilon
    cfg.dp_epsilon = round(payload.dp_epsilon, 3)
    cfg.updated_at = datetime.now(UTC)
    cfg.updated_by = current_user.username
    key_id, _, _ = ensure_active_hmac_key(db, settings)

    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="DP_EPSILON_UPDATED",
        resource_type="privacy_settings",
        resource_id="1",
        details={"from_epsilon": prev_eps, "to_epsilon": cfg.dp_epsilon},
    )
    db.commit()
    return PrivacySettingsOut(
        dp_epsilon=cfg.dp_epsilon,
        retention_days=cfg.retention_days,
        hmac_rotation_hours=cfg.hmac_rotation_hours,
        active_key_id=key_id,
        updated_at=cfg.updated_at,
        updated_by=cfg.updated_by,
    )


@router.post("/keys/rotate", response_model=KeyRotationOut)
def rotate_pseudonym_key(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    current_user: User = Depends(require_roles(UserRole.PRIVACY_OFFICER, UserRole.ADMIN)),
) -> KeyRotationOut:
    prev_id, new_id, rotated_at = rotate_hmac_key(db, settings)
    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="HMAC_KEY_ROTATED",
        resource_type="hmac_key",
        resource_id=new_id,
        details={"previous_key_id": prev_id, "new_key_id": new_id},
    )
    db.commit()
    return KeyRotationOut(previous_key_id=prev_id, new_key_id=new_id, rotated_at=rotated_at)


@router.post("/reidentify/request", response_model=ReidentificationRequestOut, status_code=201)
def create_reidentification_request(
    payload: ReidentificationCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ANALYST, UserRole.ADMIN)),
) -> ReidentificationRequestOut:
    alert = db.execute(select(Alert).where(Alert.id == payload.alert_id)).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    alert_tokens = {e.get("token") for e in (alert.entity_tokens or []) if e.get("token")}
    invalid_tokens = [t for t in payload.tokens if t not in alert_tokens]
    if invalid_tokens:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Requested tokens do not belong to alert {alert.id}: {invalid_tokens}",
        )

    req = ReidentificationRequest(
        alert_id=alert.id,
        requester_id=current_user.id,
        requested_tokens=list(dict.fromkeys(payload.tokens)),
        justification=payload.justification.strip(),
        status="pending",
    )
    db.add(req)
    db.flush()

    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="REIDENTIFY_REQUESTED",
        resource_type="reidentify_request",
        resource_id=req.id,
        details={
            "alert_id": alert.id,
            "token_count": len(req.requested_tokens),
            "tokens": req.requested_tokens,
        },
    )
    db.commit()
    db.refresh(req)
    return _enrich_request(db, req)


@router.get("/reidentify/requests", response_model=list[ReidentificationRequestOut])
def list_reidentification_requests(
    req_status: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ReidentificationRequestOut]:
    stmt = select(ReidentificationRequest).order_by(ReidentificationRequest.created_at.desc())
    if current_user.role not in (UserRole.PRIVACY_OFFICER.value, UserRole.ADMIN.value):
        stmt = stmt.where(ReidentificationRequest.requester_id == current_user.id)
    if req_status:
        stmt = stmt.where(ReidentificationRequest.status == req_status)
    rows = db.execute(stmt.limit(100)).scalars().all()
    return [_enrich_request(db, r) for r in rows]


@router.post("/reidentify/requests/{req_id}/decide", response_model=ReidentificationRequestOut)
def decide_reidentification_request(
    req_id: str,
    payload: ReidentificationDecisionRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    current_user: User = Depends(require_roles(UserRole.PRIVACY_OFFICER, UserRole.ADMIN)),
) -> ReidentificationRequestOut:
    req = db.execute(
        select(ReidentificationRequest).where(ReidentificationRequest.id == req_id)
    ).scalar_one_or_none()
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    if req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request already decided with status '{req.status}'",
        )
    if req.requester_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Separation of duties: requester cannot approve or reject their own request",
        )

    now = datetime.now(UTC)
    req.status = payload.decision
    req.reviewer_id = current_user.id
    req.decision_note = payload.decision_note.strip() or None
    req.reviewed_at = now
    if payload.decision == "approved":
        req.expires_at = now + timedelta(minutes=settings.reidentify_grant_ttl_minutes)

    action = "REIDENTIFY_APPROVED" if payload.decision == "approved" else "REIDENTIFY_REJECTED"
    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action=action,
        resource_type="reidentify_request",
        resource_id=req.id,
        details={"alert_id": req.alert_id, "requester_id": req.requester_id},
    )
    db.commit()
    db.refresh(req)
    return _enrich_request(db, req)


@router.post("/reidentify/requests/{req_id}/reveal", response_model=ReidentificationRevealOut)
def reveal_reidentified_entities(
    req_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    current_user: User = Depends(
        require_roles(UserRole.ANALYST, UserRole.PRIVACY_OFFICER, UserRole.ADMIN)
    ),
) -> ReidentificationRevealOut:
    req = db.execute(
        select(ReidentificationRequest).where(ReidentificationRequest.id == req_id)
    ).scalar_one_or_none()
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")

    if current_user.id != req.requester_id and current_user.role not in (
        UserRole.PRIVACY_OFFICER.value,
        UserRole.ADMIN.value,
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this grant")

    if req.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Re-identification grant is not approved (status={req.status})",
        )

    now = datetime.now(UTC)
    exp = req.expires_at
    if exp is not None:
        exp_utc = exp.replace(tzinfo=UTC) if exp.tzinfo is None else exp.astimezone(UTC)
        if exp_utc <= now:
            req.status = "expired"
            db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Break-glass grant expired")

    entities = reveal_vault_tokens(
        db,
        master_key=settings.vault_master_key,
        tokens=req.requested_tokens,
    )
    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="REIDENTIFY_VAULT_REVEALED",
        resource_type="reidentify_request",
        resource_id=req.id,
        details={"alert_id": req.alert_id, "revealed_tokens": [e.token for e in entities]},
    )
    db.commit()
    return ReidentificationRevealOut(
        request_id=req.id,
        alert_id=req.alert_id,
        expires_at=req.expires_at,
        entities=entities,
    )


@router.get("/audit-log", response_model=list[AuditLogOut])
def get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(UserRole.PRIVACY_OFFICER, UserRole.ADMIN)),
) -> list[AuditLogOut]:
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).scalars().all()
    return [AuditLogOut.model_validate(r) for r in rows]


@router.get("/audit-log/verify", response_model=AuditVerifyOut)
def verify_audit_log(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(UserRole.PRIVACY_OFFICER, UserRole.ADMIN)),
) -> AuditVerifyOut:
    return verify_audit_chain(db)


@router.post("/retention/run", response_model=RetentionRunOut)
def trigger_retention_policy(
    payload: RetentionRunRequest | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    current_user: User = Depends(require_roles(UserRole.PRIVACY_OFFICER, UserRole.ADMIN)),
) -> RetentionRunOut:
    cfg = _get_or_create_settings(db, settings)
    days = payload.retention_days if (payload and payload.retention_days is not None) else cfg.retention_days
    result = run_retention_policy(
        db,
        retention_days=days,
        actor_id=current_user.id,
        actor_role=current_user.role,
    )
    db.commit()
    return result


@router.post("/psi/check", response_model=PsiCheckResponse)
def psi_check_hashes(
    payload: PsiCheckRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
    current_user: User = Depends(get_current_user),
) -> PsiCheckResponse:
    threat_hashes = db.execute(select(ThreatIntelHash.sha256_hash)).scalars().all()
    server = PsiServer(derive_server_scalar(settings.vault_master_key))
    try:
        result = server.evaluate(
            client_blinded_points=payload.blinded_points,
            server_items=list(threat_hashes),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid ECDH-PSI point encoding: {exc}",
        ) from exc

    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="ECDH_PSI_CHECK",
        resource_type="threat_intel",
        resource_id="secp256r1",
        details={"queried_count": len(payload.blinded_points), "server_set_size": result.server_set_size},
    )
    db.commit()

    return PsiCheckResponse(
        double_blinded_client_hashes=result.double_blinded_client_hashes,
        server_blinded_points=result.server_blinded_points,
        server_set_size=result.server_set_size,
    )


@router.get("/psi/demo-hints")
def psi_demo_hints(_: User = Depends(get_current_user)) -> dict[str, list[dict[str, str]]]:
    """Provide safe demo candidate hashes for testing client-side ECDH-PSI without exposing the threat DB."""
    return {
        "sample_candidates": [
            {
                "label": "Suspicious Invoice Macro Hash (Sample Test Indicator)",
                "sha256": KNOWN_MALICIOUS_SAMPLE_HASH,
            },
            {
                "label": "Clean OS System Binary Hash",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            },
            {
                "label": "Clean Container Image Layer Hash",
                "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
            },
        ]
    }
