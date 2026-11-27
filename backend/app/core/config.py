"""Application configuration loaded exclusively from environment variables."""

from __future__ import annotations

import base64
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings validated via Pydantic v2."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "Privacy-Preserving Threat Detection Platform"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Persistence & Streaming
    database_url: str = Field(..., min_length=1)
    redis_url: str = "redis://localhost:6379/0"
    redis_stream_key: str = "events:raw"
    redis_consumer_group: str = "threat-detectors"
    redis_alert_channel: str = "alerts:broadcast"
    redis_metrics_channel: str = "metrics:broadcast"
    stream_mode: Literal["redis", "memory", "inline"] = "redis"

    # Cryptographic Secrets (must be supplied via environment, never hardcoded)
    jwt_secret_key: str = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = Field(default=120, ge=5, le=1440)

    vault_master_key_b64: str = Field(..., min_length=32)
    initial_hmac_key_hex: str = Field(..., min_length=64)

    # Privacy & Detection Defaults
    default_dp_epsilon: float = Field(default=1.0, ge=0.05, le=10.0)
    default_retention_days: int = Field(default=30, ge=1, le=3650)
    hmac_rotation_hours: int = Field(default=24, ge=1, le=720)
    reidentify_grant_ttl_minutes: int = Field(default=15, ge=1, le=240)

    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = Field(default=240, ge=10, le=10000)
    login_rate_limit_per_minute: int = Field(default=25, ge=3, le=1000)

    # Streaming Generator & Demo Seeding
    generator_interval_seconds: float = Field(default=1.5, ge=0.1, le=60.0)
    generator_enabled: bool = True
    seed_demo_data: bool = False
    demo_user_password: str | None = None

    @field_validator("vault_master_key_b64")
    @classmethod
    def _validate_vault_master_key(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise ValueError("VAULT_MASTER_KEY_B64 must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError("VAULT_MASTER_KEY_B64 must decode to exactly 32 bytes for AES-256-GCM")
        return value

    @field_validator("initial_hmac_key_hex")
    @classmethod
    def _validate_hmac_hex(cls, value: str) -> str:
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("INITIAL_HMAC_KEY_HEX must be valid hexadecimal") from exc
        if len(raw) < 32:
            raise ValueError("INITIAL_HMAC_KEY_HEX must represent at least 32 bytes")
        return value

    @property
    def vault_master_key(self) -> bytes:
        return base64.b64decode(self.vault_master_key_b64)

    @property
    def initial_hmac_key(self) -> bytes:
        return bytes.fromhex(self.initial_hmac_key_hex)

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()
