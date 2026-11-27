"""Unit tests for hash-chained audit logs and data minimization retention job."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models.db import (
    Alert,
    EventDailyAggregate,
    PiiVaultEntry,
    ReidentificationRequest,
    SecurityEvent,
    User,
)
from app.privacy.audit import GENESIS_HASH, append_audit_log, verify_audit_chain
from app.privacy.retention import run_retention_policy
from app.privacy.vault import store_pii_mapping


def test_audit_chain_append_verify_and_tamper_detection(db_session) -> None:
    empty_status = verify_audit_chain(db_session)
    assert empty_status.valid is True
    assert empty_status.checked_entries == 0
    assert empty_status.latest_hash == GENESIS_HASH

    e1 = append_audit_log(
        db_session,
        actor_id="user-1",
        actor_role="analyst",
        action="REIDENTIFY_REQUESTED",
        resource_type="alert",
        resource_id="alert-1",
        details={"justification_len": 25, "raw_ip": "1.2.3.4"},
    )
    e2 = append_audit_log(
        db_session,
        actor_id="user-2",
        actor_role="privacy_officer",
        action="REIDENTIFY_APPROVED",
        resource_type="reidentify_request",
        resource_id="req-1",
        details={"decision": "approved"},
    )
    db_session.commit()

    # Forbidden PII keys are stripped automatically
    assert "raw_ip" not in e1.details
    assert e1.prev_hash == GENESIS_HASH
    assert e2.prev_hash == e1.entry_hash

    ok = verify_audit_chain(db_session)
    assert ok.valid is True
    assert ok.checked_entries == 2
    assert ok.latest_hash == e2.entry_hash

    # Tampering with details breaks entry_hash verification
    e1.details = {"justification_len": 999}
    db_session.commit()
    broken = verify_audit_chain(db_session)
    assert broken.valid is False
    assert broken.broken_at_id == e1.id

    # Restoring e1 and tampering with e2.prev_hash triggers prev_hash break
    db_session.rollback()
    e1.details = {"justification_len": 25}
    db_session.commit()
    e2.prev_hash = "f" * 64
    db_session.commit()
    broken_link = verify_audit_chain(db_session)
    assert broken_link.valid is False
    assert broken_link.broken_at_id == e2.id


def test_retention_policy_aggregates_and_purges_respecting_active_grants(db_session, test_settings) -> None:
    now = datetime.now(UTC)
    old_ts = now - timedelta(days=45)

    user = User(username="analyst1", email="a@test.local", hashed_password="h", role="analyst")
    db_session.add(user)
    db_session.flush()

    alert = Alert(
        title="Old Alert",
        severity="high",
        status="new",
        rule_id="RULE_BRUTE_FORCE",
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        mitre_tactic="Credential Access",
        explanation="Test",
        anomaly_score=0.8,
        entity_tokens=[{"entity_type": "ip", "token": "ip_kv1_protected"}],
        event_ids=[],
        region="us-east",
        created_at=old_ts,
        updated_at=old_ts,
    )
    db_session.add(alert)
    db_session.flush()

    # Active grant protects ip_kv1_protected from vault deletion
    grant = ReidentificationRequest(
        alert_id=alert.id,
        requester_id=user.id,
        requested_tokens=["ip_kv1_protected"],
        justification="Active investigation needs IP",
        status="approved",
        expires_at=now + timedelta(minutes=10),
    )
    db_session.add(grant)

    # Vault entries: one protected, one expired unprotected
    v_prot = store_pii_mapping(
        db_session,
        master_key=test_settings.vault_master_key,
        token="ip_kv1_protected",
        entity_type="ip",
        key_id="kv1",
        raw_value="203.0.113.9",
        expires_at=old_ts,
    )
    v_prot.created_at = old_ts
    v_exp = store_pii_mapping(
        db_session,
        master_key=test_settings.vault_master_key,
        token="ip_kv1_expired",
        entity_type="ip",
        key_id="kv1",
        raw_value="203.0.113.10",
        expires_at=old_ts,
    )
    v_exp.created_at = old_ts

    # Old events + fresh event
    for _i in range(3):
        db_session.add(
            SecurityEvent(
                event_type="auth_log",
                timestamp=old_ts,
                region="us-east",
                source_ip_token="ip_kv1_expired",
            )
        )
    db_session.add(
        SecurityEvent(
            event_type="auth_log",
            timestamp=now,
            region="eu-west",
            source_ip_token="ip_kv1_fresh",
        )
    )
    db_session.commit()

    res = run_retention_policy(db_session, retention_days=30, actor_id=user.id, actor_role="privacy_officer")
    db_session.commit()

    assert res.events_aggregated == 3
    assert res.events_deleted == 3
    assert res.vault_entries_deleted == 1

    remaining_events = db_session.execute(select(SecurityEvent)).scalars().all()
    assert len(remaining_events) == 1
    assert remaining_events[0].region == "eu-west"

    remaining_vault = db_session.execute(select(PiiVaultEntry)).scalars().all()
    assert [v.token for v in remaining_vault] == ["ip_kv1_protected"]

    aggs = db_session.execute(select(EventDailyAggregate)).scalars().all()
    assert any(a.region == "us-east" and a.event_count == 3 for a in aggs)
