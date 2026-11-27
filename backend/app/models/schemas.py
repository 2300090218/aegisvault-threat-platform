"""Pydantic v2 request and response schemas with strict validation."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.security import UserRole

EventType = Literal["auth_log", "network_flow", "file_hash"]
SeverityLevel = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "investigating", "resolved"]
AttackScenario = Literal[
    "normal",
    "brute_force",
    "impossible_travel",
    "data_exfiltration",
    "port_scan",
    "malicious_hash",
]


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=4, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class RawSecurityEventIn(BaseModel):
    """Inbound raw security event before stream pseudonymization."""

    event_type: EventType
    timestamp: datetime | None = None
    region: str = Field(default="us-east", min_length=2, max_length=64, pattern=r"^[a-z0-9-]+$")
    username: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    dest_ip: str | None = Field(default=None, max_length=64)
    dest_port: int | None = Field(default=None, ge=1, le=65535)
    bytes_out: int = Field(default=0, ge=0, le=10_000_000_000)
    auth_success: bool | None = None
    file_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("file_hash")
    @classmethod
    def _normalize_hash(cls, value: str | None) -> str | None:
        return value.lower() if value else None


class IngestResponse(BaseModel):
    stream_id: str
    queued: bool = True


class SimulateAttackRequest(BaseModel):
    scenario: AttackScenario = "brute_force"
    count: int = Field(default=8, ge=1, le=50)
    region: str = Field(default="us-east", pattern=r"^[a-z0-9-]+$")


class SimulateAttackResponse(BaseModel):
    scenario: AttackScenario
    events_enqueued: int
    stream_ids: list[str]


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: str
    timestamp: datetime
    region: str
    username_token: str | None = None
    email_token: str | None = None
    source_ip_token: str | None = None
    dest_ip_token: str | None = None
    dest_port: int | None = None
    bytes_out: int
    auth_success: bool | None = None
    file_hash: str | None = None
    anomaly_score: float
    is_anomaly: bool
    raw_metadata: dict[str, Any]


class EntityTokenRef(BaseModel):
    entity_type: Literal["username", "email", "ip"]
    token: str


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    severity: SeverityLevel
    status: AlertStatus
    rule_id: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    explanation: str
    anomaly_score: float
    entity_tokens: list[dict[str, str]]
    event_ids: list[str]
    region: str
    created_at: datetime
    updated_at: datetime


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class AlertDetailOut(BaseModel):
    alert: AlertOut
    timeline_events: list[SecurityEventOut]
    reidentification_requests: list[ReidentificationRequestOut]


class RegionStatOut(BaseModel):
    region: str
    noisy_count: int


class TopSourceStatOut(BaseModel):
    source_ip_token: str
    noisy_count: int


class EventRateBucketOut(BaseModel):
    bucket: str
    events: int
    alerts: int


class DashboardAnalyticsOut(BaseModel):
    epsilon: float
    mechanism: str = "Laplace"
    total_events_noisy: int
    total_alerts_noisy: int
    open_alerts_count: int
    region_counts: list[RegionStatOut]
    top_sources: list[TopSourceStatOut]
    severity_counts: dict[str, int]
    event_rate_series: list[EventRateBucketOut]
    privacy_note: str


class PrivacySettingsOut(BaseModel):
    dp_epsilon: float
    retention_days: int
    hmac_rotation_hours: int
    active_key_id: str
    updated_at: datetime
    updated_by: str


class EpsilonUpdateRequest(BaseModel):
    dp_epsilon: float = Field(..., ge=0.05, le=10.0)


class KeyRotationOut(BaseModel):
    previous_key_id: str | None
    new_key_id: str
    rotated_at: datetime


class ReidentificationCreateRequest(BaseModel):
    alert_id: str
    tokens: list[str] = Field(..., min_length=1, max_length=20)
    justification: str = Field(..., min_length=12, max_length=1000)


class ReidentificationDecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    decision_note: str = Field(default="", max_length=500)


class ReidentificationRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    requester_id: str
    requester_username: str | None = None
    reviewer_id: str | None = None
    reviewer_username: str | None = None
    requested_tokens: list[str]
    justification: str
    status: str
    decision_note: str | None = None
    created_at: datetime
    reviewed_at: datetime | None = None
    expires_at: datetime | None = None


class RevealedEntity(BaseModel):
    token: str
    entity_type: str
    raw_value: str
    key_id: str


class ReidentificationRevealOut(BaseModel):
    request_id: str
    alert_id: str
    expires_at: datetime | None
    entities: list[RevealedEntity]


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    actor_id: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str


class AuditVerifyOut(BaseModel):
    valid: bool
    checked_entries: int
    broken_at_id: int | None = None
    latest_hash: str | None = None
    message: str


class RetentionRunRequest(BaseModel):
    retention_days: int | None = Field(default=None, ge=0, le=3650)


class RetentionRunOut(BaseModel):
    cutoff_timestamp: datetime
    events_aggregated: int
    events_deleted: int
    vault_entries_deleted: int


class PsiCheckRequest(BaseModel):
    """ECDH P-256 blinded points from client (compressed hex points, 33 bytes = 66 hex chars)."""

    blinded_points: list[str] = Field(..., min_length=1, max_length=100)


class PsiCheckResponse(BaseModel):
    curve: str = "secp256r1"
    double_blinded_client_hashes: list[str]
    server_blinded_points: list[str]
    server_set_size: int


class OrgRoundMetric(BaseModel):
    org_id: str
    org_name: str
    sample_count: int
    local_accuracy: float
    local_loss: float


class FederatedRoundOut(BaseModel):
    round_number: int
    global_accuracy: float
    global_loss: float
    org_metrics: list[OrgRoundMetric]
    created_at: datetime


class FederatedStatusOut(BaseModel):
    current_round: int
    global_accuracy: float
    global_loss: float
    rounds: list[FederatedRoundOut]


class FederatedTrainRequest(BaseModel):
    rounds: int = Field(default=1, ge=1, le=20)
    local_epochs: int = Field(default=3, ge=1, le=15)
