"""Deterministic stateful and stateless threat detection rules operating on pseudonymized events."""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.detection.mitre import MITRE_TECHNIQUES, MitreTechnique

# Approximate region centroids (latitude, longitude) for impossible-travel detection
REGION_COORDS: dict[str, tuple[float, float]] = {
    "us-east": (39.04, -77.49),
    "us-west": (37.39, -122.08),
    "eu-west": (53.35, -6.26),
    "eu-central": (50.11, 8.68),
    "ap-south": (19.08, 72.88),
    "ap-northeast": (35.68, 139.69),
    "sa-east": (-23.55, -46.63),
}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometers between two geographic coordinates."""
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lam = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lam / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


@dataclass(frozen=True)
class PseudonymizedEventInput:
    event_id: str
    event_type: str
    timestamp: datetime
    region: str
    username_token: str | None
    email_token: str | None
    source_ip_token: str | None
    dest_ip_token: str | None
    dest_port: int | None
    bytes_out: int
    auth_success: bool | None
    file_hash: str | None


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    title: str
    severity: str
    mitre: MitreTechnique
    explanation: str
    entity_tokens: list[dict[str, str]]
    event_ids: list[str]
    region: str


class RuleEngine:
    """Stateful sliding-window threat rule engine over pseudonymized telemetry."""

    def __init__(
        self,
        *,
        brute_force_threshold: int = 5,
        brute_force_window_sec: int = 120,
        impossible_travel_max_kmh: float = 900.0,
        impossible_travel_window_sec: int = 1800,
        exfil_single_bytes: int = 15_000_000,
        exfil_window_bytes: int = 25_000_000,
        exfil_window_sec: int = 120,
        port_scan_threshold: int = 8,
        port_scan_window_sec: int = 60,
        cooldown_sec: int = 20,
    ) -> None:
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window_sec = brute_force_window_sec
        self.impossible_travel_max_kmh = impossible_travel_max_kmh
        self.impossible_travel_window_sec = impossible_travel_window_sec
        self.exfil_single_bytes = exfil_single_bytes
        self.exfil_window_bytes = exfil_window_bytes
        self.exfil_window_sec = exfil_window_sec
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_sec = port_scan_window_sec
        self.cooldown_sec = cooldown_sec

        self._failed_auth_by_ip: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        self._last_success_by_user: dict[str, tuple[datetime, str, str]] = {}
        self._bytes_by_ip: dict[str, deque[tuple[datetime, int, str]]] = defaultdict(deque)
        self._ports_by_ip: dict[str, deque[tuple[datetime, int, str]]] = defaultdict(deque)
        self._last_fired: dict[tuple[str, str], datetime] = {}

    def reset(self) -> None:
        """Clear all stateful sliding windows and cooldowns."""
        self._failed_auth_by_ip.clear()
        self._last_success_by_user.clear()
        self._bytes_by_ip.clear()
        self._ports_by_ip.clear()
        self._last_fired.clear()

    @staticmethod
    def _utc(ts: datetime) -> datetime:
        return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)

    def _in_cooldown(self, rule_id: str, actor_key: str, now: datetime) -> bool:
        if self.cooldown_sec <= 0:
            return False
        prev = self._last_fired.get((rule_id, actor_key))
        return bool(prev is not None and (now - prev).total_seconds() < self.cooldown_sec)

    def _mark_fired(self, rule_id: str, actor_key: str, now: datetime) -> None:
        self._last_fired[(rule_id, actor_key)] = now

    @staticmethod
    def _collect_entities(ev: PseudonymizedEventInput) -> list[dict[str, str]]:
        entities: list[dict[str, str]] = []
        if ev.username_token:
            entities.append({"entity_type": "username", "token": ev.username_token})
        if ev.email_token:
            entities.append({"entity_type": "email", "token": ev.email_token})
        if ev.source_ip_token:
            entities.append({"entity_type": "ip", "token": ev.source_ip_token})
        if ev.dest_ip_token:
            entities.append({"entity_type": "ip", "token": ev.dest_ip_token})
        return entities

    def get_ip_activity_features(self, source_ip_token: str | None, now: datetime) -> tuple[int, int]:
        """Return (recent_events_count, distinct_ports_60s) for ML feature enrichment."""
        if not source_ip_token:
            return 0, 0
        now_utc = self._utc(now)
        cutoff = now_utc - timedelta(seconds=60)
        ports_q = self._ports_by_ip.get(source_ip_token)
        failed_q = self._failed_auth_by_ip.get(source_ip_token)
        bytes_q = self._bytes_by_ip.get(source_ip_token)

        recent_ports = {p for ts, p, _ in (ports_q or []) if ts >= cutoff}
        rate = (
            sum(1 for ts, _ in (failed_q or []) if ts >= cutoff)
            + sum(1 for ts, _, _ in (bytes_q or []) if ts >= cutoff)
        )
        return rate, len(recent_ports)

    def evaluate(
        self,
        ev: PseudonymizedEventInput,
        *,
        known_bad_hashes: dict[str, tuple[str, str]] | None = None,
    ) -> list[RuleMatch]:
        """Evaluate all detection rules for a single pseudonymized event."""
        now = self._utc(ev.timestamp)
        matches: list[RuleMatch] = []
        entities = self._collect_entities(ev)

        if ev.event_type == "auth_log":
            self._check_brute_force(ev, now, entities, matches)
            self._check_impossible_travel(ev, now, entities, matches)

        if ev.event_type == "network_flow":
            self._check_data_exfiltration(ev, now, entities, matches)
            self._check_port_scan(ev, now, entities, matches)

        if ev.file_hash and known_bad_hashes:
            self._check_threat_intel_hash(ev, known_bad_hashes, entities, matches)

        return matches

    def _check_brute_force(
        self,
        ev: PseudonymizedEventInput,
        now: datetime,
        entities: list[dict[str, str]],
        matches: list[RuleMatch],
    ) -> None:
        actor = ev.source_ip_token or ev.username_token
        if ev.auth_success is not False or not actor:
            return

        q = self._failed_auth_by_ip[actor]
        q.append((now, ev.event_id))
        cutoff = now - timedelta(seconds=self.brute_force_window_sec)
        while q and q[0][0] < cutoff:
            q.popleft()

        if len(q) >= self.brute_force_threshold and not self._in_cooldown("RULE_BRUTE_FORCE", actor, now):
            self._mark_fired("RULE_BRUTE_FORCE", actor, now)
            matches.append(
                RuleMatch(
                    rule_id="RULE_BRUTE_FORCE",
                    title="Credential Brute Force Burst Detected",
                    severity="high",
                    mitre=MITRE_TECHNIQUES["T1110"],
                    explanation=(
                        f"Observed {len(q)} failed authentication attempts from entity {actor} "
                        f"within {self.brute_force_window_sec}s (threshold={self.brute_force_threshold})."
                    ),
                    entity_tokens=entities,
                    event_ids=[eid for _, eid in q],
                    region=ev.region,
                )
            )

    def _check_impossible_travel(
        self,
        ev: PseudonymizedEventInput,
        now: datetime,
        entities: list[dict[str, str]],
        matches: list[RuleMatch],
    ) -> None:
        if ev.auth_success is not True or not ev.username_token:
            return

        prev = self._last_success_by_user.get(ev.username_token)
        self._last_success_by_user[ev.username_token] = (now, ev.region, ev.event_id)
        if prev is None:
            return

        prev_ts, prev_region, prev_event_id = prev
        if prev_region == ev.region:
            return
        if ev.region not in REGION_COORDS or prev_region not in REGION_COORDS:
            return

        elapsed_sec = max(1.0, (now - prev_ts).total_seconds())
        if elapsed_sec > self.impossible_travel_window_sec:
            return

        lat1, lon1 = REGION_COORDS[prev_region]
        lat2, lon2 = REGION_COORDS[ev.region]
        distance_km = haversine_km(lat1, lon1, lat2, lon2)
        speed_kmh = distance_km / (elapsed_sec / 3600.0)

        if speed_kmh > self.impossible_travel_max_kmh and not self._in_cooldown(
            "RULE_IMPOSSIBLE_TRAVEL", ev.username_token, now
        ):
            self._mark_fired("RULE_IMPOSSIBLE_TRAVEL", ev.username_token, now)
            matches.append(
                RuleMatch(
                    rule_id="RULE_IMPOSSIBLE_TRAVEL",
                    title="Impossible Travel Authentication Detected",
                    severity="critical",
                    mitre=MITRE_TECHNIQUES["T1078"],
                    explanation=(
                        f"User token {ev.username_token} authenticated in {ev.region} just "
                        f"{int(elapsed_sec)}s after authenticating in {prev_region} "
                        f"({distance_km:,.0f} km apart, implied speed {speed_kmh:,.0f} km/h)."
                    ),
                    entity_tokens=entities,
                    event_ids=[prev_event_id, ev.event_id],
                    region=ev.region,
                )
            )

    def _check_data_exfiltration(
        self,
        ev: PseudonymizedEventInput,
        now: datetime,
        entities: list[dict[str, str]],
        matches: list[RuleMatch],
    ) -> None:
        actor = ev.source_ip_token or "unknown_ip"
        q = self._bytes_by_ip[actor]
        q.append((now, ev.bytes_out, ev.event_id))
        cutoff = now - timedelta(seconds=self.exfil_window_sec)
        while q and q[0][0] < cutoff:
            q.popleft()

        total_bytes = sum(b for _, b, _ in q)
        triggered = ev.bytes_out >= self.exfil_single_bytes or total_bytes >= self.exfil_window_bytes
        if triggered and not self._in_cooldown("RULE_DATA_EXFILTRATION", actor, now):
            self._mark_fired("RULE_DATA_EXFILTRATION", actor, now)
            mb_single = ev.bytes_out / 1_000_000
            mb_total = total_bytes / 1_000_000
            matches.append(
                RuleMatch(
                    rule_id="RULE_DATA_EXFILTRATION",
                    title="Anomalous Outbound Data Exfiltration",
                    severity="critical",
                    mitre=MITRE_TECHNIQUES["T1041"],
                    explanation=(
                        f"Source entity {actor} transferred {mb_single:.2f} MB in a single flow "
                        f"({mb_total:.2f} MB over {self.exfil_window_sec}s window), exceeding exfiltration threshold."
                    ),
                    entity_tokens=entities,
                    event_ids=[eid for _, _, eid in q],
                    region=ev.region,
                )
            )

    def _check_port_scan(
        self,
        ev: PseudonymizedEventInput,
        now: datetime,
        entities: list[dict[str, str]],
        matches: list[RuleMatch],
    ) -> None:
        if not ev.source_ip_token or ev.dest_port is None:
            return
        q = self._ports_by_ip[ev.source_ip_token]
        q.append((now, ev.dest_port, ev.event_id))
        cutoff = now - timedelta(seconds=self.port_scan_window_sec)
        while q and q[0][0] < cutoff:
            q.popleft()

        unique_ports = sorted({p for _, p, _ in q})
        if len(unique_ports) >= self.port_scan_threshold and not self._in_cooldown(
            "RULE_PORT_SCAN", ev.source_ip_token, now
        ):
            self._mark_fired("RULE_PORT_SCAN", ev.source_ip_token, now)
            severity = "high" if len(unique_ports) >= 15 else "medium"
            sample_ports = ", ".join(str(p) for p in unique_ports[:8])
            matches.append(
                RuleMatch(
                    rule_id="RULE_PORT_SCAN",
                    title="Rapid Network Port Scan Activity",
                    severity=severity,
                    mitre=MITRE_TECHNIQUES["T1046"],
                    explanation=(
                        f"Source IP token {ev.source_ip_token} probed {len(unique_ports)} distinct "
                        f"destination ports within {self.port_scan_window_sec}s (sample: {sample_ports})."
                    ),
                    entity_tokens=entities,
                    event_ids=[eid for _, _, eid in q],
                    region=ev.region,
                )
            )

    def _check_threat_intel_hash(
        self,
        ev: PseudonymizedEventInput,
        known_bad_hashes: dict[str, tuple[str, str]],
        entities: list[dict[str, str]],
        matches: list[RuleMatch],
    ) -> None:
        assert ev.file_hash is not None
        hit = known_bad_hashes.get(ev.file_hash.lower())
        if hit is None:
            return
        family, intel_severity = hit
        matches.append(
            RuleMatch(
                rule_id="RULE_THREAT_INTEL_HASH",
                title=f"Known Malicious File Hash Observed ({family})",
                severity=intel_severity,
                mitre=MITRE_TECHNIQUES["T1204.002"],
                explanation=(
                    f"File SHA-256 {ev.file_hash[:16]}... matched threat-intelligence indicator "
                    f"for malware family '{family}'."
                ),
                entity_tokens=entities,
                event_ids=[ev.event_id],
                region=ev.region,
            )
        )
