"""Database initialization, threat-intel seeding, and demo bootstrap."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import UserRole, hash_password
from app.detection.engine import ThreatDetectionEngine
from app.models.db import PrivacySetting, SecurityEvent, ThreatIntelHash, User
from app.privacy.audit import append_audit_log
from app.privacy.pseudonymizer import Pseudonymizer, ensure_active_hmac_key
from app.streaming.consumer import load_known_bad_hashes, process_raw_event
from app.streaming.generator import KNOWN_MALICIOUS_SAMPLE_HASH, build_attack_events, build_normal_event

SEED_THREAT_HASHES: list[tuple[str, str, str]] = [
    (KNOWN_MALICIOUS_SAMPLE_HASH, "EmotetLoader", "critical"),
    ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "CobaltStrikeBeacon", "critical"),
    ("4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce", "LockBit3Ransom", "critical"),
    ("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", "QakBotDropper", "high"),
    ("d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", "MimikatzCredentialTool", "high"),
]


def bootstrap_database(db: Session, settings: Settings) -> None:
    """Ensure baseline privacy settings, HMAC key, threat intel, and optional demo users exist."""
    privacy_cfg = db.execute(select(PrivacySetting).where(PrivacySetting.id == 1)).scalar_one_or_none()
    if privacy_cfg is None:
        db.add(
            PrivacySetting(
                id=1,
                dp_epsilon=settings.default_dp_epsilon,
                retention_days=settings.default_retention_days,
                hmac_rotation_hours=settings.hmac_rotation_hours,
                updated_by="system",
            )
        )
        db.flush()

    ensure_active_hmac_key(db, settings)

    existing_hashes = {
        h for h in db.execute(select(ThreatIntelHash.sha256_hash)).scalars().all()
    }
    for sha_hex, family, sev in SEED_THREAT_HASHES:
        if sha_hex not in existing_hashes:
            db.add(
                ThreatIntelHash(
                    sha256_hash=sha_hex,
                    malware_family=family,
                    severity=sev,
                    source="curated-feed",
                )
            )
    db.flush()

    if settings.seed_demo_data:
        if not settings.demo_user_password:
            raise ValueError("DEMO_USER_PASSWORD must be configured when SEED_DEMO_DATA=true")

        demo_accounts = [
            ("viewer", "viewer@privacy-soc.io", UserRole.VIEWER.value),
            ("analyst", "analyst@privacy-soc.io", UserRole.ANALYST.value),
            ("officer", "officer@privacy-soc.io", UserRole.PRIVACY_OFFICER.value),
            ("admin", "admin@privacy-soc.io", UserRole.ADMIN.value),
        ]
        created_users = False
        for uname, email, role in demo_accounts:
            existing_user = db.execute(select(User).where(User.username == uname)).scalar_one_or_none()
            if existing_user is None:
                db.add(
                    User(
                        username=uname,
                        email=email,
                        hashed_password=hash_password(settings.demo_user_password),
                        role=role,
                        is_active=True,
                    )
                )
                created_users = True
        db.flush()

        if created_users:
            append_audit_log(
                db,
                actor_id="system",
                actor_role="system",
                action="SYSTEM_BOOTSTRAPPED",
                resource_type="platform",
                resource_id="init",
                details={"seeded_roles": [r for _, _, r in demo_accounts]},
            )

        ev_count = db.execute(select(func.count(SecurityEvent.id))).scalar_one()
        if ev_count == 0 and settings.environment != "test":
            pseudonymizer = Pseudonymizer(settings)
            detector = ThreatDetectionEngine()
            intel = load_known_bad_hashes(db)
            now = datetime.now(UTC)
            for idx in range(10):
                ev = build_normal_event()
                ev["timestamp"] = (now - timedelta(seconds=60 - idx * 5)).isoformat()
                process_raw_event(
                    db,
                    settings=settings,
                    pseudonymizer=pseudonymizer,
                    detector=detector,
                    raw_payload=ev,
                    known_bad_hashes=intel,
                )
            for ev in build_attack_events("brute_force", count=6, region="us-east"):
                process_raw_event(
                    db,
                    settings=settings,
                    pseudonymizer=pseudonymizer,
                    detector=detector,
                    raw_payload=ev,
                    known_bad_hashes=intel,
                )
            db.flush()
