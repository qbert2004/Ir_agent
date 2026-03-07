"""
Security and observability middleware.

- API key authentication
- Rate limiting (Redis if REDIS_URL set, else in-memory per-instance)
- Request ID injection for tracing
"""
from __future__ import annotations

import os
import time
import uuid
import logging
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

logger = logging.getLogger("ir-agent")

# Paths that bypass both authentication AND rate limiting.
# Swagger/ReDoc UI paths are included so they are freely accessible in dev
# mode and so the rate-limiter does not consume quota for browser asset requests.
PUBLIC_PATHS = {
    "/",
    "/health",
    "/health/live",
    "/health/ready",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/favicon.ico",
    "/dashboard",      # Platform UI — token sent by JS inside the page
    "/report_ui",      # Legacy report UI
}


# ---------------------------------------------------------------------------
# Redis-backed rate limiter (optional, falls back to in-memory)
# ---------------------------------------------------------------------------

class _RateLimitBackend:
    def is_allowed(self, key: str, max_requests: int, window: int) -> bool:
        raise NotImplementedError


class _InMemoryBackend(_RateLimitBackend):
    def __init__(self):
        self._requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int, window: int) -> bool:
        now = time.time()
        self._requests[key] = [t for t in self._requests[key] if now - t < window]
        if len(self._requests[key]) >= max_requests:
            return False
        self._requests[key].append(now)
        return True


class _RedisBackend(_RateLimitBackend):
    def __init__(self, redis_url: str):
        import redis as redis_lib
        self._redis = redis_lib.from_url(redis_url, decode_responses=True)
        logger.info("Rate limiter: Redis backend (%s)", redis_url.split("@")[-1])

    def is_allowed(self, key: str, max_requests: int, window: int) -> bool:
        now = time.time()
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, window)
        results = pipe.execute()
        return results[2] <= max_requests


def _build_rate_limit_backend() -> _RateLimitBackend:
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            return _RedisBackend(redis_url)
        except ImportError:
            logger.warning("redis package not installed — using in-memory rate limiter")
        except Exception as e:
            logger.warning("Redis unavailable (%s) — using in-memory rate limiter", e)
    return _InMemoryBackend()


# ---------------------------------------------------------------------------
# 1. Request-ID middleware
# ---------------------------------------------------------------------------
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ---------------------------------------------------------------------------
# 2. API-key authentication middleware
# ---------------------------------------------------------------------------
class AuthMiddleware(BaseHTTPMiddleware):
    """
    Validates ``Authorization: Bearer <token>`` header against
    ``settings.api_token``.  Skipped when ``api_token`` is empty (dev mode)
    or for PUBLIC_PATHS.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip if no token configured (development mode)
        if not settings.api_token:
            return await call_next(request)

        path = request.url.path.rstrip("/") or "/"

        # PUBLIC_PATHS covers /, /health/*, /docs, /redoc, /openapi.json
        if path in PUBLIC_PATHS:
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Missing Authorization header"})

        token = auth[len("Bearer "):].strip()
        if token != settings.api_token:
            return JSONResponse(status_code=403, content={"detail": "Invalid API token"})

        return await call_next(request)


# ---------------------------------------------------------------------------
# 3. Rate-limiting middleware  (sliding window, per-IP)
# ---------------------------------------------------------------------------
class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter.
    Uses Redis if REDIS_URL env var is set, otherwise in-memory (single-instance).
    """

    def __init__(self, app, max_requests: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self._backend = _build_rate_limit_backend()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path.rstrip("/") or "/"
        if path in PUBLIC_PATHS:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        key = f"rl:{client_ip}"

        if not self._backend.is_allowed(key, self.max_requests, window=60):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": "60"},
            )

        return await call_next(request)


# ---------------------------------------------------------------------------
# 4. Request logging middleware (replaces the ad-hoc version in main.py)
# ---------------------------------------------------------------------------
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.time()
        request_id = getattr(request.state, "request_id", "-")

        response = await call_next(request)

        duration_ms = (time.time() - start) * 1000
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round(duration_ms, 1),
                "client_ip": request.client.host if request.client else "-",
            },
        )
        return response
