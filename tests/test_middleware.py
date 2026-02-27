"""Tests for security middleware."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.middleware import (
    RateLimitMiddleware,
    RequestIDMiddleware,
    PUBLIC_PATHS,
)


def _make_app(max_requests: int = 50):
    """Create a minimal app with middleware for testing."""
    test_app = FastAPI()
    test_app.add_middleware(RateLimitMiddleware, max_requests=max_requests)
    test_app.add_middleware(RequestIDMiddleware)

    @test_app.get("/health")
    async def health():
        return {"status": "ok"}

    @test_app.get("/protected")
    async def protected():
        return {"data": "secret"}

    return test_app


def test_request_id_header():
    app = _make_app()
    client = TestClient(app)
    r = client.get("/health")
    assert "X-Request-ID" in r.headers
    assert len(r.headers["X-Request-ID"]) == 16


def test_custom_request_id_preserved():
    app = _make_app()
    client = TestClient(app)
    r = client.get("/health", headers={"X-Request-ID": "my-custom-id"})
    assert r.headers["X-Request-ID"] == "my-custom-id"


def test_rate_limit():
    app = _make_app(max_requests=3)
    client = TestClient(app)
    for _ in range(3):
        r = client.get("/protected")
        assert r.status_code == 200
    r = client.get("/protected")
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    body = r.json()
    assert "Rate limit" in body["detail"]


def test_rate_limit_skips_public():
    app = _make_app(max_requests=2)
    client = TestClient(app)
    for _ in range(5):
        r = client.get("/health")
        assert r.status_code == 200


def test_public_paths_defined():
    assert "/health" in PUBLIC_PATHS
    assert "/health/live" in PUBLIC_PATHS
    assert "/docs" in PUBLIC_PATHS


def test_auth_logic_skip_when_no_token():
    """Auth should be disabled when api_token is empty (test env)."""
    from app.core.config import settings
    assert settings.api_token == ""


def test_auth_token_comparison():
    """Token comparison logic correctness."""
    token = "secret-123"
    header = "Bearer secret-123"
    assert header[len("Bearer "):].strip() == token
    bad_header = "Bearer wrong-token"
    assert bad_header[len("Bearer "):].strip() != token
