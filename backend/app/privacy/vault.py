"""AES-256-GCM encrypted PII vault and HMAC key wrapping."""

from __future__ import annotations

import os
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db import PiiVaultEntry
from app.models.schemas import RevealedEntity


class VaultDecryptionError(Exception):
    """Raised when vault ciphertext authentication or decryption fails."""


def encrypt_aes_gcm(master_key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt bytes with AES-256-GCM using a fresh 96-bit nonce."""
    if len(master_key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(12)
    ciphertext = AESGCM(master_key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_aes_gcm(master_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt and authenticate AES-256-GCM ciphertext."""
    if len(master_key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    try:
        return AESGCM(master_key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise VaultDecryptionError("Failed to authenticate or decrypt vault entry") from exc


def _vault_aad(entity_type: str, key_id: str, token: str) -> bytes:
    return f"pii:{entity_type}:{key_id}:{token}".encode()


def _key_wrap_aad(key_id: str) -> bytes:
    return f"hmac_key:{key_id}".encode()


def wrap_hmac_key(master_key: bytes, key_id: str, raw_hmac_key: bytes) -> tuple[bytes, bytes]:
    """Encrypt an HMAC secret key before persisting to hmac_keys."""
    return encrypt_aes_gcm(master_key, raw_hmac_key, aad=_key_wrap_aad(key_id))


def unwrap_hmac_key(master_key: bytes, key_id: str, nonce: bytes, encrypted_key: bytes) -> bytes:
    """Decrypt a wrapped HMAC secret key."""
    return decrypt_aes_gcm(master_key, nonce, encrypted_key, aad=_key_wrap_aad(key_id))


def store_pii_mapping(
    db: Session,
    *,
    master_key: bytes,
    token: str,
    entity_type: str,
    key_id: str,
    raw_value: str,
    expires_at: datetime | None = None,
) -> PiiVaultEntry:
    """Idempotently store an encrypted raw PII value bound to its pseudonym token."""
    existing = db.execute(
        select(PiiVaultEntry).where(
            PiiVaultEntry.token == token,
            PiiVaultEntry.key_id == key_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    nonce, ciphertext = encrypt_aes_gcm(
        master_key,
        raw_value.encode("utf-8"),
        aad=_vault_aad(entity_type, key_id, token),
    )
    entry = PiiVaultEntry(
        token=token,
        entity_type=entity_type,
        key_id=key_id,
        nonce=nonce,
        ciphertext=ciphertext,
        expires_at=expires_at,
    )
    db.add(entry)
    db.flush()
    return entry


def reveal_vault_tokens(
    db: Session,
    *,
    master_key: bytes,
    tokens: list[str],
) -> list[RevealedEntity]:
    """Decrypt authorized PII tokens from the vault."""
    if not tokens:
        return []

    rows = db.execute(
        select(PiiVaultEntry)
        .where(PiiVaultEntry.token.in_(tokens))
        .order_by(PiiVaultEntry.created_at.desc())
    ).scalars().all()

    seen: set[str] = set()
    revealed: list[RevealedEntity] = []
    for row in rows:
        if row.token in seen:
            continue
        raw_bytes = decrypt_aes_gcm(
            master_key,
            row.nonce,
            row.ciphertext,
            aad=_vault_aad(row.entity_type, row.key_id, row.token),
        )
        seen.add(row.token)
        revealed.append(
            RevealedEntity(
                token=row.token,
                entity_type=row.entity_type,
                raw_value=raw_bytes.decode("utf-8"),
                key_id=row.key_id,
            )
        )
    return revealed
