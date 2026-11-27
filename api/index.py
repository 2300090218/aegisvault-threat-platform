"""Vercel Serverless Python entrypoint exposing the FastAPI application."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

if os.environ.get("VERCEL"):
    tmp_db = Path(tempfile.gettempdir()) / "aegisvault_vercel.db"
    if not os.environ.get("DATABASE_URL"):
        os.environ["DATABASE_URL"] = f"sqlite:///{tmp_db.as_posix()}"
    os.environ.setdefault("STREAM_MODE", "inline")
    os.environ.setdefault("SEED_DEMO_DATA", "true")

from app.core.bootstrap import bootstrap_database  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.database import Base, init_db_globals, session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.streaming.broker import create_broker  # noqa: E402

settings = get_settings()
app = create_app(settings)

_init_lock = threading.Lock()
_initialized = False


def _ensure_serverless_ready() -> None:
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        engine, session_factory = init_db_globals(settings)
        Base.metadata.create_all(engine)
        with session_scope(session_factory) as db:
            bootstrap_database(db, settings)
        app.state.settings = settings
        app.state.session_factory = session_factory
        if getattr(app.state, "broker", None) is None:
            app.state.broker = create_broker(settings)
        _initialized = True


@app.middleware("http")
async def vercel_cold_start_middleware(request, call_next):
    _ensure_serverless_ready()
    return await call_next(request)


__all__ = ["app"]
