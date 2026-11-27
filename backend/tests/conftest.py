"""Shared pytest fixtures for unit, detection, streaming, and API integration tests."""

from __future__ import annotations

import base64
import os
import secrets
from collections.abc import Generator

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

# Populate non-hardcoded ephemeral test env before app settings load
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_unused.db")
os.environ.setdefault("JWT_SECRET_KEY", secrets.token_hex(32))
os.environ.setdefault("VAULT_MASTER_KEY_B64", base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
os.environ.setdefault("INITIAL_HMAC_KEY_HEX", secrets.token_hex(32))
os.environ.setdefault("STREAM_MODE", "memory")
os.environ.setdefault("SEED_DEMO_DATA", "true")
os.environ.setdefault("DEMO_USER_PASSWORD", "TestDemoPass!2026")

from app.core.config import Settings
from app.core.database import Base, create_db_engine, create_session_factory


@pytest.fixture()
def test_settings(tmp_path) -> Settings:
    db_file = tmp_path / "test.db"
    return Settings(
        environment="test",
        database_url=f"sqlite:///{db_file.as_posix()}",
        redis_url="redis://localhost:6379/0",
        stream_mode="memory",
        jwt_secret_key=secrets.token_hex(32),
        vault_master_key_b64=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        initial_hmac_key_hex=secrets.token_hex(32),
        rate_limit_enabled=True,
        rate_limit_requests_per_minute=200,
        login_rate_limit_per_minute=10,
        seed_demo_data=True,
        demo_user_password="TestDemoPass!2026",
    )


@pytest.fixture()
def db_engine(test_settings: Settings) -> Generator[Engine, None, None]:
    engine = create_db_engine(test_settings.database_url)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture()
def db_session_factory(db_engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(db_engine)


@pytest.fixture()
def db_session(db_session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    session = db_session_factory()
    try:
        yield session
        session.commit()
    finally:
        session.close()
