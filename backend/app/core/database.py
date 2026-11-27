"""SQLAlchemy 2 database engine and session management."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import Settings, get_settings


class Base(DeclarativeBase):
    """Base declarative class for all ORM models."""


def create_db_engine(database_url: str) -> Engine:
    """Create a configured SQLAlchemy 2 Engine for PostgreSQL or SQLite."""
    is_sqlite = database_url.startswith("sqlite")
    connect_args: dict[str, object] = {"check_same_thread": False} if is_sqlite else {}
    engine_kwargs: dict[str, object] = {
        "connect_args": connect_args,
        "pool_pre_ping": True,
        "future": True,
    }
    if not is_sqlite:
        engine_kwargs["pool_size"] = 10
        engine_kwargs["max_overflow"] = 20

    engine = create_engine(database_url, **engine_kwargs)

    if is_sqlite:
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a SQLAlchemy sessionmaker bound to the given engine."""
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def init_db_globals(settings: Settings | None = None) -> tuple[Engine, sessionmaker[Session]]:
    """Initialize global engine and session factory from settings."""
    global _engine, _session_factory
    cfg = settings or get_settings()
    _engine = create_db_engine(cfg.database_url)
    _session_factory = create_session_factory(_engine)
    return _engine, _session_factory


def get_engine() -> Engine:
    """Return initialized engine, lazily initializing if needed."""
    global _engine
    if _engine is None:
        init_db_globals()
    assert _engine is not None
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return initialized session factory, lazily initializing if needed."""
    global _session_factory
    if _session_factory is None:
        init_db_globals()
    assert _session_factory is not None
    return _session_factory


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a DB session per request."""
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope(factory: sessionmaker[Session] | None = None) -> Generator[Session, None, None]:
    """Context manager handling commit/rollback for background workers and scripts."""
    sf = factory or get_session_factory()
    session = sf()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
