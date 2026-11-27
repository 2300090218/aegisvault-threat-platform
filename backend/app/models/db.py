"""SQLAlchemy 2.0 ORM data models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class HmacKey(Base):
    __tablename__ = "hmac_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    key_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    key_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_key_material: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PiiVaultEntry(Base):
    __tablename__ = "pii_vault"
    __table_args__ = (UniqueConstraint("token", "key_id", name="uq_pii_vault_token_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    token: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True, default=_utcnow)
    region: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Strictly pseudonymized entity tokens (never raw PII)
    username_token: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    email_token: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    source_ip_token: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    dest_ip_token: Mapped[str | None] = mapped_column(String(128), nullable=True)

    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_out: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    auth_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    raw_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="new", index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mitre_technique_id: Mapped[str] = mapped_column(String(32), nullable=False)
    mitre_technique_name: Mapped[str] = mapped_column(String(128), nullable=False)
    mitre_tactic: Mapped[str] = mapped_column(String(64), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    entity_tokens: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="us-east", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    reidentification_requests: Mapped[list[ReidentificationRequest]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
    )


class ReidentificationRequest(Base):
    __tablename__ = "reidentification_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    requester_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    reviewer_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    requested_tokens: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending", index=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    alert: Mapped[Alert] = relationship(back_populates="reidentification_requests")
    requester: Mapped[User] = relationship(foreign_keys=[requester_id])
    reviewer: Mapped[User | None] = relationship(foreign_keys=[reviewer_id])


class AuditLog(Base):
    """Append-only, SHA-256 hash-chained audit trail."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_role: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class PrivacySetting(Base):
    __tablename__ = "privacy_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    dp_epsilon: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    hmac_rotation_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")


class EventDailyAggregate(Base):
    __tablename__ = "event_daily_aggregates"
    __table_args__ = (UniqueConstraint("bucket_date", "region", "event_type", name="uq_daily_agg_bucket"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    bucket_date: Mapped[datetime] = mapped_column(Date, nullable=False, index=True)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class ThreatIntelHash(Base):
    __tablename__ = "threat_intel_hashes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    sha256_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    malware_family: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False, default="high")
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="curated-feed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class FederatedRound(Base):
    __tablename__ = "federated_rounds"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    round_number: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    global_accuracy: Mapped[float] = mapped_column(Float, nullable=False)
    global_loss: Mapped[float] = mapped_column(Float, nullable=False)
    org_metrics: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    model_weights: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
