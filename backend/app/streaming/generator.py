"""Security telemetry generator producing normal traffic plus realistic attack scenarios."""

from __future__ import annotations

import argparse
import asyncio
import logging
import random
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import get_settings
from app.models.schemas import AttackScenario
from app.streaming.broker import StreamBroker, create_broker

logger = logging.getLogger(__name__)

REGIONS = ["us-east", "us-west", "eu-west", "ap-south"]
USERS = [
    ("alex.mercer", "alex.mercer@acme-sec.io"),
    ("priya.nair", "priya.nair@acme-sec.io"),
    ("marcus.chen", "marcus.chen@acme-sec.io"),
    ("elena.rostova", "elena.rostova@acme-sec.io"),
    ("sam.okafor", "sam.okafor@acme-sec.io"),
]
KNOWN_MALICIOUS_SAMPLE_HASH = "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"


def build_normal_event(rng: random.Random | None = None) -> dict[str, Any]:
    r = rng or random
    username, email = r.choice(USERS)
    region = r.choice(REGIONS)
    src_ip = f"10.{r.randint(10, 99)}.{r.randint(1, 254)}.{r.randint(1, 254)}"
    dst_ip = f"172.16.{r.randint(1, 30)}.{r.randint(10, 200)}"
    kind = r.choices(["auth_log", "network_flow", "file_hash"], weights=[0.45, 0.45, 0.10])[0]
    now = datetime.now(UTC).isoformat()

    if kind == "auth_log":
        return {
            "event_type": "auth_log",
            "timestamp": now,
            "region": region,
            "username": username,
            "email": email,
            "source_ip": src_ip,
            "dest_port": 443,
            "bytes_out": r.randint(350, 1800),
            "auth_success": r.random() > 0.05,
            "metadata": {"service": "sso-gateway", "mfa": True},
        }
    if kind == "network_flow":
        return {
            "event_type": "network_flow",
            "timestamp": now,
            "region": region,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "dest_port": r.choice([443, 80, 22, 8443, 53]),
            "bytes_out": r.randint(1200, 120_000),
            "metadata": {"protocol": "TCP", "direction": "egress"},
        }
    benign_hash = f"{r.getrandbits(256):064x}"
    return {
        "event_type": "file_hash",
        "timestamp": now,
        "region": region,
        "username": username,
        "source_ip": src_ip,
        "file_hash": benign_hash,
        "bytes_out": r.randint(2048, 32768),
        "metadata": {"artifact": "build-agent.bin"},
    }


def build_attack_events(
    scenario: AttackScenario,
    *,
    count: int = 8,
    region: str = "us-east",
) -> list[dict[str, Any]]:
    """Build a coherent burst of events representing a simulated attack scenario."""
    now = datetime.now(UTC)
    if scenario == "normal":
        return [build_normal_event() for _ in range(count)]

    if scenario == "brute_force":
        attacker_ip = "198.51.100.77"
        username, email = USERS[0]
        burst_count = max(6, count)
        return [
            {
                "event_type": "auth_log",
                "timestamp": (now + timedelta(milliseconds=i * 40)).isoformat(),
                "region": region,
                "username": username,
                "email": email,
                "source_ip": attacker_ip,
                "dest_port": 443,
                "bytes_out": 520,
                "auth_success": False,
                "metadata": {"service": "vpn-portal", "simulation": "brute_force"},
            }
            for i in range(burst_count)
        ]

    if scenario == "impossible_travel":
        username, email = USERS[1]
        remote_region = "ap-south" if region != "ap-south" else "eu-west"
        return [
            {
                "event_type": "auth_log",
                "timestamp": now.isoformat(),
                "region": region,
                "username": username,
                "email": email,
                "source_ip": "203.0.113.15",
                "dest_port": 443,
                "bytes_out": 900,
                "auth_success": True,
                "metadata": {"service": "corp-idp", "simulation": "impossible_travel_leg1"},
            },
            {
                "event_type": "auth_log",
                "timestamp": (now + timedelta(seconds=15)).isoformat(),
                "region": remote_region,
                "username": username,
                "email": email,
                "source_ip": "192.0.2.244",
                "dest_port": 443,
                "bytes_out": 940,
                "auth_success": True,
                "metadata": {"service": "corp-idp", "simulation": "impossible_travel_leg2"},
            },
        ]

    if scenario == "data_exfiltration":
        username, email = USERS[2]
        return [
            {
                "event_type": "network_flow",
                "timestamp": now.isoformat(),
                "region": region,
                "username": username,
                "email": email,
                "source_ip": "10.44.8.19",
                "dest_ip": "185.220.101.45",
                "dest_port": 8443,
                "bytes_out": 48_500_000,
                "metadata": {"protocol": "TCP", "simulation": "data_exfiltration"},
            }
        ]

    if scenario == "port_scan":
        ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 8080]
        scan_count = max(10, min(len(ports), count))
        return [
            {
                "event_type": "network_flow",
                "timestamp": (now + timedelta(milliseconds=i * 30)).isoformat(),
                "region": region,
                "source_ip": "198.51.100.212",
                "dest_ip": "10.12.0.10",
                "dest_port": ports[i % len(ports)],
                "bytes_out": 640,
                "metadata": {"protocol": "SYN", "simulation": "port_scan"},
            }
            for i in range(scan_count)
        ]

    # malicious_hash
    username, email = USERS[3]
    return [
        {
            "event_type": "file_hash",
            "timestamp": now.isoformat(),
            "region": region,
            "username": username,
            "email": email,
            "source_ip": "10.22.5.14",
            "file_hash": KNOWN_MALICIOUS_SAMPLE_HASH,
            "bytes_out": 145_000,
            "metadata": {"artifact": "invoice_macro.exe", "simulation": "malicious_hash"},
        }
    ]


async def enqueue_scenario(
    broker: StreamBroker,
    *,
    scenario: AttackScenario,
    count: int = 8,
    region: str = "us-east",
) -> list[str]:
    events = build_attack_events(scenario, count=count, region=region)
    stream_ids: list[str] = []
    for ev in events:
        sid = await broker.publish_raw_event(ev)
        stream_ids.append(sid)
    return stream_ids


async def run_demo_burst(broker: StreamBroker) -> None:
    """Emit normal traffic plus all 4 core attack scenarios + malicious hash into Redis Streams."""
    for _ in range(12):
        await broker.publish_raw_event(build_normal_event())
    for scenario in ("brute_force", "impossible_travel", "data_exfiltration", "port_scan", "malicious_hash"):
        await enqueue_scenario(broker, scenario=scenario, count=8)  # type: ignore[arg-type]
    logger.info("Demo attack burst enqueued.")


async def run_continuous_generator(broker: StreamBroker, interval_sec: float) -> None:
    scenarios: list[AttackScenario] = [
        "brute_force",
        "impossible_travel",
        "data_exfiltration",
        "port_scan",
        "malicious_hash",
    ]
    tick = 0
    while True:
        await broker.publish_raw_event(build_normal_event())
        tick += 1
        if tick % 12 == 0:
            scenario = scenarios[(tick // 12 - 1) % len(scenarios)]
            await enqueue_scenario(broker, scenario=scenario, count=8)
            logger.info("Injected periodic attack scenario: %s", scenario)
        await asyncio.sleep(interval_sec)


async def _main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Security telemetry event generator")
    parser.add_argument("--demo-burst", action="store_true", help="Emit an attack demo burst and exit")
    args = parser.parse_args()

    settings = get_settings()
    if not settings.generator_enabled and not args.demo_burst:
        logger.info("Generator disabled via GENERATOR_ENABLED=false; idling.")
        while True:
            await asyncio.sleep(60)

    broker = create_broker(settings)
    try:
        if args.demo_burst:
            await run_demo_burst(broker)
        else:
            await run_continuous_generator(broker, settings.generator_interval_seconds)
    finally:
        await broker.close()


if __name__ == "__main__":
    asyncio.run(_main())
