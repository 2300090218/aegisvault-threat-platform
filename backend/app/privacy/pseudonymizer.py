"""HMAC-SHA256 pseudonymization with rotating secret keys and vault persistence."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.db import HmacKey
from app.models.schemas import RawSecurityEventIn
from app.privacy.vault import store_pii_mapping, unwrap_hmac_key, wrap_hmac_key

ENTITY_PREFIXES: dict[str, str] = {
    "username": "usr",
    "email": "eml",
    "ip": "ip",
}


def _normalize_value(entity_type: str, raw_value: str) -> str:
    cleaned = raw_value.strip()
    if entity_type in ("username", "email"):
        return cleaned.lower()
    return cleaned


def compute_hmac_token(
    *,
    raw_key: bytes,
    key_id: str,
    entity_type: str,
    raw_value: str,
) -> str:
    """Compute a deterministic HMAC-SHA256 token scoped to entity_type and key_id."""
    if entity_type not in ENTITY_PREFIXES:
        raise ValueError(f"Unsupported entity_type: {entity_type}")
    normalized = _normalize_value(entity_type, raw_value)
    msg = f"{entity_type}:{normalized}".encode()
    digest = hmac.new(raw_key, msg, hashlib.sha256).hexdigest()[:20]
    prefix = ENTITY_PREFIXES[entity_type]
    return f"{prefix}_{key_id}_{digest}"


def _parse_key_version(key_id: str) -> int:
    if key_id.startswith("kv"):
        suffix = key_id[2:]
        if suffix.isdigit():
            return int(suffix)
    return 0


def ensure_active_hmac_key(db: Session, settings: Settings) -> tuple[str, bytes, HmacKey]:
    """Return active (key_id, raw_key, HmacKey), bootstrapping kv1 from settings if empty."""
    active = db.execute(select(HmacKey).where(HmacKey.is_active.is_(True))).scalar_one_or_none()
    if active is None:
        key_id = "kv1"
        raw_key = settings.initial_hmac_key
        nonce, wrapped = wrap_hmac_key(settings.vault_master_key, key_id, raw_key)
        active = HmacKey(
            key_id=key_id,
            key_nonce=nonce,
            encrypted_key_material=wrapped,
            is_active=True,
        )
        db.add(active)
        db.flush()
        return key_id, raw_key, active

    raw_key = unwrap_hmac_key(
        settings.vault_master_key,
        active.key_id,
        active.key_nonce,
        active.encrypted_key_material,
    )
    return active.key_id, raw_key, active


def rotate_hmac_key(db: Session, settings: Settings) -> tuple[str | None, str, datetime]:
    """Rotate the active HMAC secret key using CSPRNG and wrap the new key in the vault."""
    all_keys = db.execute(select(HmacKey)).scalars().all()
    now = datetime.now(UTC)
    previous_id: str | None = None
    max_ver = 0

    for k in all_keys:
        max_ver = max(max_ver, _parse_key_version(k.key_id))
        if k.is_active:
            previous_id = k.key_id
            k.is_active = False
            k.rotated_at = now

    new_key_id = f"kv{max_ver + 1}"
    new_secret = secrets.token_bytes(32)
    nonce, wrapped = wrap_hmac_key(settings.vault_master_key, new_key_id, new_secret)
    new_row = HmacKey(
        key_id=new_key_id,
        key_nonce=nonce,
        encrypted_key_material=wrapped,
        is_active=True,
        created_at=now,
    )
    db.add(new_row)
    db.flush()
    return previous_id, new_key_id, now


def maybe_rotate_hmac_key(db: Session, settings: Settings, rotation_hours: int) -> tuple[str, bytes]:
    """Auto-rotate HMAC key if active key age exceeds rotation_hours."""
    key_id, raw_key, key_row = ensure_active_hmac_key(db, settings)
    created = key_row.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    if datetime.now(UTC) - created >= timedelta(hours=rotation_hours):
        _, new_key_id, _ = rotate_hmac_key(db, settings)
        key_id, raw_key, _ = ensure_active_hmac_key(db, settings)
        assert key_id == new_key_id
    return key_id, raw_key


class Pseudonymizer:
    """High-level service that pseudonymizes inbound events and vaults raw PII."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def tokenize_and_vault(
        self,
        db: Session,
        *,
        entity_type: str,
        raw_value: str | None,
        key_id: str,
        raw_key: bytes,
        retention_days: int | None = None,
    ) -> str | None:
        if raw_value is None or not raw_value.strip():
            return None
        normalized = _normalize_value(entity_type, raw_value)
        token = compute_hmac_token(
            raw_key=raw_key,
            key_id=key_id,
            entity_type=entity_type,
            raw_value=normalized,
        )
        days = retention_days if retention_days is not None else self.settings.default_retention_days
        expires_at = datetime.now(UTC) + timedelta(days=days)
        store_pii_mapping(
            db,
            master_key=self.settings.vault_master_key,
            token=token,
            entity_type=entity_type,
            key_id=key_id,
            raw_value=normalized,
            expires_at=expires_at,
        )
        return token

    def pseudonymize_event(
        self,
        db: Session,
        event: RawSecurityEventIn,
        *,
        rotation_hours: int | None = None,
        retention_days: int | None = None,
    ) -> tuple[dict[str, str | None], list[dict[str, str]]]:
        """Pseudonymize all PII fields of an event and return tokens + entity reference list."""
        rot_hours = rotation_hours if rotation_hours is not None else self.settings.hmac_rotation_hours
        key_id, raw_key = maybe_rotate_hmac_key(db, self.settings, rot_hours)

        username_token = self.tokenize_and_vault(
            db,
            entity_type="username",
            raw_value=event.username,
            key_id=key_id,
            raw_key=raw_key,
            retention_days=retention_days,
        )
        email_token = self.tokenize_and_vault(
            db,
            entity_type="email",
            raw_value=event.email,
            key_id=key_id,
            raw_key=raw_key,
            retention_days=retention_days,
        )
        source_ip_token = self.tokenize_and_vault(
            db,
            entity_type="ip",
            raw_value=event.source_ip,
            key_id=key_id,
            raw_key=raw_key,
            retention_days=retention_days,
        )
        dest_ip_token = self.tokenize_and_vault(
            db,
            entity_type="ip",
            raw_value=event.dest_ip,
            key_id=key_id,
            raw_key=raw_key,
            retention_days=retention_days,
        )

        tokens_map = {
            "username_token": username_token,
            "email_token": email_token,
            "source_ip_token": source_ip_token,
            "dest_ip_token": dest_ip_token,
        }

        entity_refs: list[dict[str, str]] = []
        if username_token:
            entity_refs.append({"entity_type": "username", "token": username_token})
        if email_token:
            entity_refs.append({"entity_type": "email", "token": email_token})
        if source_ip_token:
            entity_refs.append({"entity_type": "ip", "token": source_ip_token})
        if dest_ip_token:
            entity_refs.append({"entity_type": "ip", "token": dest_ip_token})

        return tokens_map, entity_refs
