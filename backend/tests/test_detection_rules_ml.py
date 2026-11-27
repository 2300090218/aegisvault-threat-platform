"""Unit tests for detection rules, MITRE mapping, and Isolation Forest scorer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.detection.engine import ThreatDetectionEngine
from app.detection.ml_model import AnomalyScorer, extract_event_features
from app.detection.rules import PseudonymizedEventInput, RuleEngine, haversine_km


def _ev(
    *,
    event_id: str = "e1",
    event_type: str = "auth_log",
    ts: datetime | None = None,
    region: str = "us-east",
    username_token: str | None = "usr_kv1_u1",
    source_ip_token: str | None = "ip_kv1_s1",
    dest_port: int | None = 443,
    bytes_out: int = 800,
    auth_success: bool | None = True,
    file_hash: str | None = None,
) -> PseudonymizedEventInput:
    return PseudonymizedEventInput(
        event_id=event_id,
        event_type=event_type,
        timestamp=ts or datetime.now(UTC),
        region=region,
        username_token=username_token,
        email_token=None,
        source_ip_token=source_ip_token,
        dest_ip_token=None,
        dest_port=dest_port,
        bytes_out=bytes_out,
        auth_success=auth_success,
        file_hash=file_hash,
    )


def test_brute_force_rule_fires_at_threshold() -> None:
    engine = RuleEngine(brute_force_threshold=5, cooldown_sec=60)
    t0 = datetime.now(UTC)
    for i in range(4):
        matches = engine.evaluate(_ev(event_id=f"bf-{i}", ts=t0 + timedelta(seconds=i), auth_success=False))
        assert matches == []

    matches = engine.evaluate(_ev(event_id="bf-4", ts=t0 + timedelta(seconds=4), auth_success=False))
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE_BRUTE_FORCE"
    assert matches[0].mitre.technique_id == "T1110"
    assert matches[0].severity == "high"
    assert len(matches[0].event_ids) == 5

    # Cooldown suppresses immediate duplicate alert
    dup = engine.evaluate(_ev(event_id="bf-5", ts=t0 + timedelta(seconds=5), auth_success=False))
    assert dup == []


def test_impossible_travel_rule() -> None:
    assert haversine_km(39.04, -77.49, 19.08, 72.88) > 10_000
    engine = RuleEngine(cooldown_sec=0)
    t0 = datetime.now(UTC)

    assert engine.evaluate(_ev(event_id="it-1", ts=t0, region="us-east", auth_success=True)) == []
    # Same region is fine
    assert engine.evaluate(_ev(event_id="it-2", ts=t0 + timedelta(seconds=30), region="us-east", auth_success=True)) == []
    # Jump to ap-south 120 seconds later -> impossible travel
    matches = engine.evaluate(_ev(event_id="it-3", ts=t0 + timedelta(seconds=120), region="ap-south", auth_success=True))
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE_IMPOSSIBLE_TRAVEL"
    assert matches[0].mitre.technique_id == "T1078"
    assert matches[0].severity == "critical"


def test_data_exfiltration_and_port_scan_and_threat_intel_rules() -> None:
    engine = RuleEngine(port_scan_threshold=8, cooldown_sec=0)
    t0 = datetime.now(UTC)

    # Data exfiltration burst
    exfil = engine.evaluate(
        _ev(
            event_id="ex-1",
            event_type="network_flow",
            ts=t0,
            bytes_out=25_000_000,
            dest_port=8443,
            auth_success=None,
        )
    )
    assert len(exfil) == 1
    assert exfil[0].rule_id == "RULE_DATA_EXFILTRATION"
    assert exfil[0].mitre.technique_id == "T1041"

    # Port scan across 8 distinct ports
    for p in range(1001, 1008):
        assert (
            engine.evaluate(
                _ev(
                    event_id=f"ps-{p}",
                    event_type="network_flow",
                    ts=t0 + timedelta(seconds=1),
                    source_ip_token="ip_kv1_scanner",
                    dest_port=p,
                    bytes_out=512,
                    auth_success=None,
                )
            )
            == []
        )
    scan = engine.evaluate(
        _ev(
            event_id="ps-final",
            event_type="network_flow",
            ts=t0 + timedelta(seconds=2),
            source_ip_token="ip_kv1_scanner",
            dest_port=1099,
            bytes_out=512,
            auth_success=None,
        )
    )
    assert len(scan) == 1
    assert scan[0].rule_id == "RULE_PORT_SCAN"
    assert scan[0].mitre.technique_id == "T1046"

    # Malicious file hash match
    bad_hash = "a" * 64
    ti = engine.evaluate(
        _ev(event_id="fh-1", event_type="file_hash", file_hash=bad_hash, auth_success=None),
        known_bad_hashes={bad_hash: ("LockBit3", "critical")},
    )
    assert len(ti) == 1
    assert ti[0].rule_id == "RULE_THREAT_INTEL_HASH"
    assert ti[0].mitre.technique_id == "T1204.002"

    engine.reset()


def test_isolation_forest_and_unified_engine() -> None:
    scorer = AnomalyScorer()
    normal_vec = extract_event_features(
        event_type="network_flow",
        bytes_out=4096,
        dest_port=443,
        auth_success=None,
        recent_rate=1,
        recent_unique_ports=1,
    )
    n_score, n_flag = scorer.score_features(normal_vec)
    assert 0.0 <= n_score <= 1.0
    assert n_flag is False

    outlier_vec = extract_event_features(
        event_type="network_flow",
        bytes_out=950_000_000,
        dest_port=31337,
        auth_success=False,
        recent_rate=40,
        recent_unique_ports=35,
    )
    a_score, a_flag = scorer.score_features(outlier_vec)
    assert a_score > n_score
    assert a_flag is True

    # Unified engine triggers ML alert when outlier has no deterministic rule firing
    unified = ThreatDetectionEngine(
        rule_engine=RuleEngine(
            exfil_single_bytes=999_999_999,
            exfil_window_bytes=999_999_999,
            port_scan_threshold=99,
            cooldown_sec=0,
        ),
        ml_scorer=scorer,
        ml_alert_threshold=0.55,
    )
    outcome = unified.evaluate(
        _ev(
            event_id="ml-1",
            event_type="network_flow",
            dest_port=31337,
            bytes_out=500_000_000,
            auth_success=False,
        )
    )
    assert outcome.is_anomaly is True
    assert any(a.rule_id == "RULE_ML_ISOLATION_FOREST" for a in outcome.alerts)
