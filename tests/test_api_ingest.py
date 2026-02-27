"""Tests for telemetry ingestion API."""


def test_ingest_single_event(client, sample_event):
    r = client.post("/ingest/telemetry", json=sample_event)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["received"] == 1


def test_ingest_batch(client, sample_event, benign_event):
    r = client.post("/ingest/telemetry", json=[sample_event, benign_event])
    assert r.status_code == 200
    data = r.json()
    assert data["received"] == 2


def test_ingest_empty(client):
    r = client.post("/ingest/telemetry", json=[])
    assert r.status_code == 200
    assert r.json()["received"] == 0


def test_metrics_endpoint(client):
    r = client.get("/ingest/metrics")
    assert r.status_code == 200
    data = r.json()
    assert "processing" in data
    assert "paths" in data


def test_ml_status(client):
    r = client.get("/ingest/ml/status")
    assert r.status_code == 200
    data = r.json()
    assert "status" in data
    assert "thresholds" in data
