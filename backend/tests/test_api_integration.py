"""End-to-end REST API, RBAC, rate-limiting, break-glass, PSI, FL, and WebSocket tests."""

from __future__ import annotations

import base64
import secrets

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.database import Base, create_db_engine
from app.main import create_app
from app.privacy.psi import PsiClient
from app.streaming.generator import KNOWN_MALICIOUS_SAMPLE_HASH


@pytest.fixture()
def api_client(tmp_path):
    db_file = tmp_path / "api_test.db"
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{db_file.as_posix()}",
        redis_url="redis://localhost:6379/0",
        stream_mode="memory",
        jwt_secret_key=secrets.token_hex(32),
        vault_master_key_b64=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        initial_hmac_key_hex=secrets.token_hex(32),
        rate_limit_enabled=True,
        rate_limit_requests_per_minute=300,
        login_rate_limit_per_minute=20,
        seed_demo_data=True,
        demo_user_password="TestDemoPass!2026",
    )
    engine = create_db_engine(settings.database_url)
    Base.metadata.create_all(engine)
    engine.dispose()

    app = create_app(settings)
    with TestClient(app) as client:
        yield client, settings


def _login(client: TestClient, username: str, password: str = "TestDemoPass!2026") -> str:
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_auth_rbac_and_login_rate_limit(api_client) -> None:
    client, _ = api_client
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    # Unauthenticated request rejected
    assert client.get("/api/v1/alerts").status_code == 401

    viewer_tok = _login(client, "viewer")
    analyst_tok = _login(client, "analyst")
    officer_tok = _login(client, "officer")
    admin_tok = _login(client, "admin")

    assert client.get("/api/v1/auth/me", headers=_headers(viewer_tok)).json()["role"] == "viewer"

    # RBAC boundaries
    assert client.post("/api/v1/events/simulate", json={"scenario": "brute_force"}, headers=_headers(viewer_tok)).status_code == 403
    assert client.get("/api/v1/privacy/audit-log", headers=_headers(analyst_tok)).status_code == 403
    assert client.get("/api/v1/privacy/audit-log", headers=_headers(officer_tok)).status_code == 200
    assert client.get("/api/v1/auth/users", headers=_headers(admin_tok)).status_code == 200

    # Bad credentials eventually hit 429 login rate limit (limit=20, 4 already used above)
    got_429 = False
    for _ in range(25):
        r = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "wrong"})
        if r.status_code == 429:
            got_429 = True
            break
    assert got_429 is True


def test_realtime_ws_attack_flow_and_break_glass_reidentification(api_client) -> None:
    client, _ = api_client
    analyst_tok = _login(client, "analyst")
    officer_tok = _login(client, "officer")

    # Connect WebSocket as analyst and trigger simulated brute force attack
    with client.websocket_connect(f"/ws/alerts?token={analyst_tok}") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "connected"

        sim = client.post(
            "/api/v1/events/simulate",
            json={"scenario": "brute_force", "count": 7, "region": "us-east"},
            headers=_headers(analyst_tok),
        )
        assert sim.status_code == 202
        assert sim.json()["events_enqueued"] == 7

        # Wait for live RULE_BRUTE_FORCE alert broadcast over WebSocket
        live_alert = None
        for _ in range(10):
            msg = ws.receive_json()
            if msg["type"] == "alert" and msg["data"]["rule_id"] == "RULE_BRUTE_FORCE":
                live_alert = msg["data"]
                break
        assert live_alert is not None
        assert live_alert["rule_id"] == "RULE_BRUTE_FORCE"
        assert live_alert["mitre_technique_id"] == "T1110"

    # Alert detail & timeline contain only pseudonymized tokens
    alert_id = live_alert["id"]
    detail = client.get(f"/api/v1/alerts/{alert_id}", headers=_headers(analyst_tok))
    assert detail.status_code == 200
    detail_json = detail.json()
    assert len(detail_json["timeline_events"]) >= 5
    tokens = [e["token"] for e in detail_json["alert"]["entity_tokens"]]
    assert any(t.startswith("ip_") for t in tokens)
    assert "198.51.100.77" not in detail.text

    # Analyst updates status
    upd = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "investigating"},
        headers=_headers(analyst_tok),
    )
    assert upd.status_code == 200
    assert upd.json()["status"] == "investigating"

    # Break-glass re-identification workflow
    req_resp = client.post(
        "/api/v1/privacy/reidentify/request",
        json={
            "alert_id": alert_id,
            "tokens": tokens[:2],
            "justification": "Incident response requires blocking source IP at perimeter firewall.",
        },
        headers=_headers(analyst_tok),
    )
    assert req_resp.status_code == 201
    req_id = req_resp.json()["id"]

    # Cannot reveal before approval
    assert (
        client.post(
            f"/api/v1/privacy/reidentify/requests/{req_id}/reveal",
            headers=_headers(analyst_tok),
        ).status_code
        == 403
    )

    # Privacy officer approves
    dec = client.post(
        f"/api/v1/privacy/reidentify/requests/{req_id}/decide",
        json={"decision": "approved", "decision_note": "Verified ticket IR-402"},
        headers=_headers(officer_tok),
    )
    assert dec.status_code == 200
    assert dec.json()["status"] == "approved"

    # Analyst reveals decrypted vault entities
    rev = client.post(
        f"/api/v1/privacy/reidentify/requests/{req_id}/reveal",
        headers=_headers(analyst_tok),
    )
    assert rev.status_code == 200
    raw_values = {e["raw_value"] for e in rev.json()["entities"]}
    assert "198.51.100.77" in raw_values or "alex.mercer" in raw_values

    # Audit log chain verifies cleanly
    verify = client.get("/api/v1/privacy/audit-log/verify", headers=_headers(officer_tok))
    assert verify.status_code == 200
    assert verify.json()["valid"] is True
    assert verify.json()["checked_entries"] >= 5


def test_privacy_console_dp_psi_key_rotation_retention_and_federated(api_client) -> None:
    client, _ = api_client
    officer_tok = _login(client, "officer")
    analyst_tok = _login(client, "analyst")
    admin_tok = _login(client, "admin")

    # Direct event ingestion
    ing = client.post(
        "/api/v1/events/ingest",
        json={
            "event_type": "network_flow",
            "region": "eu-west",
            "source_ip": "10.0.5.9",
            "dest_port": 443,
            "bytes_out": 4096,
        },
        headers=_headers(analyst_tok),
    )
    assert ing.status_code == 202

    # Epsilon slider update & DP dashboard analytics
    eps_upd = client.patch(
        "/api/v1/privacy/settings/epsilon",
        json={"dp_epsilon": 0.5},
        headers=_headers(officer_tok),
    )
    assert eps_upd.status_code == 200
    assert eps_upd.json()["dp_epsilon"] == 0.5

    dash = client.get("/api/v1/analytics/dashboard", headers=_headers(analyst_tok))
    assert dash.status_code == 200
    dash_json = dash.json()
    assert dash_json["epsilon"] == 0.5
    assert dash_json["mechanism"] == "Laplace"
    assert len(dash_json["region_counts"]) >= 4

    # Key rotation
    rot = client.post("/api/v1/privacy/keys/rotate", headers=_headers(officer_tok))
    assert rot.status_code == 200
    assert rot.json()["new_key_id"] == "kv2"

    # ECDH-PSI check via endpoint
    hints = client.get("/api/v1/privacy/psi/demo-hints", headers=_headers(analyst_tok))
    assert hints.status_code == 200
    candidates = [KNOWN_MALICIOUS_SAMPLE_HASH, "9" * 64]
    psi_client = PsiClient()
    blinded = psi_client.blind_items(candidates)
    psi_resp = client.post(
        "/api/v1/privacy/psi/check",
        json={"blinded_points": blinded},
        headers=_headers(analyst_tok),
    )
    assert psi_resp.status_code == 200
    psi_data = psi_resp.json()
    matches = psi_client.find_matches(
        candidate_items=candidates,
        double_blinded_client_hashes=psi_data["double_blinded_client_hashes"],
        server_blinded_points=psi_data["server_blinded_points"],
    )
    assert matches == [KNOWN_MALICIOUS_SAMPLE_HASH]

    # Federated Learning rounds
    fl = client.post(
        "/api/v1/federated/train-round",
        json={"rounds": 3, "local_epochs": 2},
        headers=_headers(analyst_tok),
    )
    assert fl.status_code == 200
    assert fl.json()["current_round"] == 3
    assert fl.json()["global_accuracy"] >= 0.80

    # Reset FL (admin) & run retention policy
    fl_reset = client.post("/api/v1/federated/reset", headers=_headers(admin_tok))
    assert fl_reset.status_code == 200
    assert fl_reset.json()["current_round"] == 0

    ret = client.post(
        "/api/v1/privacy/retention/run",
        json={"retention_days": 30},
        headers=_headers(officer_tok),
    )
    assert ret.status_code == 200
    assert ret.json()["events_deleted"] >= 0


def test_inline_stream_mode_and_vercel_entrypoint(tmp_path) -> None:
    db_file = tmp_path / "inline.db"
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{db_file.as_posix()}",
        redis_url="redis://localhost:6379/0",
        stream_mode="inline",
        jwt_secret_key=secrets.token_hex(32),
        vault_master_key_b64=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        initial_hmac_key_hex=secrets.token_hex(32),
        rate_limit_enabled=False,
        seed_demo_data=True,
        demo_user_password="TestDemoPass!2026",
    )
    engine = create_db_engine(settings.database_url)
    Base.metadata.create_all(engine)
    engine.dispose()

    app = create_app(settings)
    with TestClient(app) as client:
        tok = _login(client, "analyst")
        sim = client.post(
            "/api/v1/events/simulate",
            json={"scenario": "port_scan", "count": 10, "region": "eu-west"},
            headers=_headers(tok),
        )
        assert sim.status_code == 202
        alerts = client.get("/api/v1/alerts?rule_id=RULE_PORT_SCAN", headers=_headers(tok)).json()
        assert len(alerts) == 1
        assert alerts[0]["mitre_technique_id"] == "T1046"
