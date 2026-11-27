"""Unit tests for HMAC-SHA256 rotating pseudonymizer and AES-256-GCM PII vault."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.db import HmacKey, PiiVaultEntry
from app.models.schemas import RawSecurityEventIn
from app.privacy.pseudonymizer import (
    Pseudonymizer,
    compute_hmac_token,
    ensure_active_hmac_key,
    maybe_rotate_hmac_key,
    rotate_hmac_key,
)
from app.privacy.vault import (
    VaultDecryptionError,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    reveal_vault_tokens,
    store_pii_mapping,
    unwrap_hmac_key,
    wrap_hmac_key,
)


def test_aes_gcm_roundtrip_and_tamper_detection() -> None:
    master_key = os.urandom(32)
    nonce, ct = encrypt_aes_gcm(master_key, b"alice@example.com", aad=b"pii:email:kv1")
    pt = decrypt_aes_gcm(master_key, nonce, ct, aad=b"pii:email:kv1")
    assert pt == b"alice@example.com"

    # Wrong AAD fails authentication
    with pytest.raises(VaultDecryptionError):
        decrypt_aes_gcm(master_key, nonce, ct, aad=b"pii:email:kv2")

    # Tampered ciphertext fails authentication
    tampered = bytearray(ct)
    tampered[-1] ^= 0xFF
    with pytest.raises(VaultDecryptionError):
        decrypt_aes_gcm(master_key, nonce, bytes(tampered), aad=b"pii:email:kv1")

    with pytest.raises(ValueError):
        encrypt_aes_gcm(b"short", b"hello")
    with pytest.raises(ValueError):
        decrypt_aes_gcm(b"short", nonce, ct)


def test_wrap_unwrap_hmac_key() -> None:
    master = os.urandom(32)
    secret = os.urandom(32)
    nonce, wrapped = wrap_hmac_key(master, "kv9", secret)
    assert unwrap_hmac_key(master, "kv9", nonce, wrapped) == secret
    with pytest.raises(VaultDecryptionError):
        unwrap_hmac_key(master, "kv10", nonce, wrapped)


def test_pseudonymize_event_and_vault_reveal(db_session, test_settings) -> None:
    pseudo = Pseudonymizer(test_settings)
    ev = RawSecurityEventIn(
        event_type="auth_log",
        region="us-east",
        username="Alice.Admin",
        email="ALICE@corp.local",
        source_ip="192.168.10.42",
        dest_ip="10.0.0.5",
        dest_port=443,
        auth_success=True,
    )
    tokens, refs = pseudo.pseudonymize_event(db_session, ev)

    assert tokens["username_token"].startswith("usr_kv1_")
    assert tokens["email_token"].startswith("eml_kv1_")
    assert tokens["source_ip_token"].startswith("ip_kv1_")
    assert tokens["dest_ip_token"].startswith("ip_kv1_")
    assert "alice" not in tokens["username_token"]
    assert "192.168" not in tokens["source_ip_token"]
    assert len(refs) == 4

    # Deterministic within same key epoch & normalized case
    ev2 = RawSecurityEventIn(
        event_type="auth_log",
        region="us-east",
        username="  alice.admin ",
        email="alice@corp.local",
        source_ip="192.168.10.42",
    )
    tokens2, _ = pseudo.pseudonymize_event(db_session, ev2)
    assert tokens2["username_token"] == tokens["username_token"]
    assert tokens2["email_token"] == tokens["email_token"]

    # Vault holds encrypted records (no plaintext visible)
    vault_rows = db_session.execute(select(PiiVaultEntry)).scalars().all()
    assert len(vault_rows) == 4
    for row in vault_rows:
        assert b"alice" not in row.ciphertext
        assert b"192.168" not in row.ciphertext

    revealed = reveal_vault_tokens(
        db_session,
        master_key=test_settings.vault_master_key,
        tokens=[tokens["username_token"], tokens["source_ip_token"]],
    )
    mapping = {r.token: r.raw_value for r in revealed}
    assert mapping[tokens["username_token"]] == "alice.admin"
    assert mapping[tokens["source_ip_token"]] == "192.168.10.42"
    assert reveal_vault_tokens(db_session, master_key=test_settings.vault_master_key, tokens=[]) == []


def test_hmac_key_rotation_manual_and_scheduled(db_session, test_settings) -> None:
    pseudo = Pseudonymizer(test_settings)
    ev = RawSecurityEventIn(event_type="auth_log", username="bob", source_ip="10.1.2.3")
    t1, _ = pseudo.pseudonymize_event(db_session, ev)
    assert t1["username_token"].startswith("usr_kv1_")

    prev_id, new_id, _ = rotate_hmac_key(db_session, test_settings)
    assert prev_id == "kv1"
    assert new_id == "kv2"

    t2, _ = pseudo.pseudonymize_event(db_session, ev)
    assert t2["username_token"].startswith("usr_kv2_")
    assert t2["username_token"] != t1["username_token"]

    # Both tokens still decrypt cleanly in vault
    revealed = reveal_vault_tokens(
        db_session,
        master_key=test_settings.vault_master_key,
        tokens=[t1["username_token"], t2["username_token"]],
    )
    assert {r.raw_value for r in revealed} == {"bob"}

    # Scheduled rotation triggers when active key age exceeds rotation_hours
    _, _, active_row = ensure_active_hmac_key(db_session, test_settings)
    active_row.created_at = datetime.now(UTC) - timedelta(hours=30)
    db_session.flush()

    kid, _ = maybe_rotate_hmac_key(db_session, test_settings, rotation_hours=24)
    assert kid == "kv3"
    active_keys = db_session.execute(select(HmacKey).where(HmacKey.is_active.is_(True))).scalars().all()
    assert len(active_keys) == 1

    with pytest.raises(ValueError):
        compute_hmac_token(raw_key=b"x" * 32, key_id="kv1", entity_type="ssn", raw_value="123")


def test_store_pii_mapping_idempotent(db_session, test_settings) -> None:
    e1 = store_pii_mapping(
        db_session,
        master_key=test_settings.vault_master_key,
        token="usr_kv1_abc",
        entity_type="username",
        key_id="kv1",
        raw_value="charlie",
    )
    e2 = store_pii_mapping(
        db_session,
        master_key=test_settings.vault_master_key,
        token="usr_kv1_abc",
        entity_type="username",
        key_id="kv1",
        raw_value="charlie",
    )
    assert e1.id == e2.id
