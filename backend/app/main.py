"""FastAPI application factory, middleware, lifespan, and route mounting."""

from __future__ import annotations

import asyncio
import contextlib
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect

from app.api import alerts, analytics, auth, events, federated, privacy, ws
from app.core.bootstrap import bootstrap_database
from app.core.config import Settings, get_settings
from app.core.database import Base, init_db_globals, session_scope
from app.core.rate_limit import RateLimitMiddleware
from app.streaming.broker import create_broker
from app.streaming.consumer import StreamConsumerWorker


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine, session_factory = init_db_globals(cfg)
        if not inspect(engine).has_table("privacy_settings"):
            Base.metadata.create_all(engine)
        with session_scope(session_factory) as db:
            bootstrap_database(db, cfg)

        broker = create_broker(cfg)
        await broker.ensure_group()

        app.state.settings = cfg
        app.state.broker = broker
        app.state.session_factory = session_factory

        embedded_consumer_task: asyncio.Task[None] | None = None
        embedded_worker: StreamConsumerWorker | None = None

        if cfg.stream_mode == "memory":
            embedded_worker = StreamConsumerWorker(
                settings=cfg,
                broker=broker,
                session_factory=session_factory,
            )
            embedded_consumer_task = asyncio.create_task(embedded_worker.run_forever())

        if cfg.stream_mode != "inline":
            listener_task = asyncio.create_task(ws.broadcast_listener_loop(broker, ws.ws_manager))
        else:
            listener_task = None

        try:
            yield
        finally:
            if embedded_worker is not None:
                embedded_worker.stop()
            if embedded_consumer_task is not None:
                embedded_consumer_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await embedded_consumer_task
            if listener_task is not None:
                listener_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await listener_task
            await broker.close()

    app = FastAPI(
        title=cfg.app_name,
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RateLimitMiddleware, settings=cfg)

    @app.get("/health", tags=["health"])
    def health_check() -> dict[str, str]:
        return {"status": "ok", "stream_mode": cfg.stream_mode}

    api_prefix = "/api/v1"
    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(events.router, prefix=api_prefix)
    app.include_router(alerts.router, prefix=api_prefix)
    app.include_router(analytics.router, prefix=api_prefix)
    app.include_router(privacy.router, prefix=api_prefix)
    app.include_router(federated.router, prefix=api_prefix)
    app.include_router(ws.router)

    return app


app = create_app()
