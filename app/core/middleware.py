"""
Security and observability middleware.

- API key authentication
- Rate limiting (in-memory, per-IP)
- Request ID injection for tracing
"""
from __future__ import annotations

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

# Paths that do NOT require authentication
PUBLIC_PATHS = {"/", "/health", "/health/live", "/health/ready", "/docs", "/openapi.json", "/redoc"}


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

        if path in PUBLIC_PATHS or path.startswith("/docs") or path.startswith("/redoc"):
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
    Simple in-memory sliding-window rate limiter.
    Limits requests per IP per minute.
    """

    def __init__(self, app, max_requests: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        # ip -> list of timestamps
        self._requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path.rstrip("/") or "/"
        if path in PUBLIC_PATHS:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = 60.0  # 1 minute

        # Prune old entries
        timestamps = self._requests[client_ip]
        self._requests[client_ip] = [t for t in timestamps if now - t < window]

        if len(self._requests[client_ip]) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": "60"},
            )

        self._requests[client_ip].append(now)
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
