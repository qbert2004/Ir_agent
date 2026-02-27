"""Tests for health endpoints."""


def test_health_root(client):
    r = client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_health_endpoint(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_liveness(client):
    r = client.get("/health/live")
    assert r.status_code == 200
    assert r.json()["status"] == "alive"


def test_readiness(client):
    r = client.get("/health/ready")
    assert r.status_code == 200
    assert "status" in r.json()
