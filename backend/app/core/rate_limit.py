"""Sliding-window API rate limiter middleware."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import Settings


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter keyed by client IP and bucket."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, now: float | None = None) -> tuple[bool, int, int]:
        """Check and record a request. Returns (allowed, remaining, retry_after_seconds)."""
        current = now if now is not None else time.monotonic()
        cutoff = current - self.window_seconds
        with self._lock:
            dq = self._hits[key]
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= limit:
                retry_after = max(1, int(self.window_seconds - (current - dq[0])) + 1)
                return False, 0, retry_after
            dq.append(current)
            remaining = max(0, limit - len(dq))
            return True, remaining, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Applies per-IP rate limits with stricter thresholds on authentication routes."""

    def __init__(self, app, settings: Settings, limiter: SlidingWindowRateLimiter | None = None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.settings = settings
        self.limiter = limiter or SlidingWindowRateLimiter(window_seconds=60)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.settings.rate_limit_enabled:
            return await call_next(request)

        path = request.url.path
        if path == "/health" or not path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        is_login = path.endswith("/auth/login")
        limit = (
            self.settings.login_rate_limit_per_minute
            if is_login
            else self.settings.rate_limit_requests_per_minute
        )
        bucket = f"{'login' if is_login else 'api'}:{client_ip}"
        allowed, remaining, retry_after = self.limiter.allow(bucket, limit)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please retry later."},
                headers={"Retry-After": str(retry_after), "X-RateLimit-Remaining": "0"},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
