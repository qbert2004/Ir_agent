"""Tests for the EventProcessor hybrid pipeline."""

from app.services.event_processor import EventProcessor


def test_is_anomalous_suspicious_keyword():
    proc = EventProcessor()
    event = {
        "command_line": "powershell -enc SGVsbG8= mimikatz",
        "process_name": "powershell.exe",
    }
    assert proc._is_anomalous(event) is True


def test_is_anomalous_benign():
    proc = EventProcessor()
    event = {
        "command_line": "notepad.exe readme.txt",
        "process_name": "notepad.exe",
        "event_id": 4624,
    }
    assert proc._is_anomalous(event) is False


def test_is_anomalous_service_install():
    proc = EventProcessor()
    event = {"event_id": 7045, "process_name": "svchost.exe"}
    assert proc._is_anomalous(event) is True


def test_parse_agent_response_malicious():
    proc = EventProcessor()
    verdict, conf = proc._parse_agent_response("This event is MALICIOUS based on analysis.")
    assert verdict == "MALICIOUS"
    assert conf == 0.9


def test_parse_agent_response_false_positive():
    proc = EventProcessor()
    verdict, conf = proc._parse_agent_response("This is a FALSE_POSITIVE, benign activity.")
    assert verdict == "FALSE_POSITIVE"
    assert conf == 0.8


def test_parse_agent_response_not_malicious():
    proc = EventProcessor()
    verdict, conf = proc._parse_agent_response("The event is NOT MALICIOUS.")
    assert verdict == "FALSE_POSITIVE"


def test_parse_agent_response_ambiguous():
    proc = EventProcessor()
    verdict, conf = proc._parse_agent_response("Unable to determine the nature of this event.")
    assert verdict == "SUSPICIOUS"
    assert conf == 0.5


def test_build_event_summary():
    proc = EventProcessor()
    event = {
        "event_id": 4688,
        "process_name": "cmd.exe",
        "command_line": "whoami",
        "user": "admin",
    }
    summary = proc._build_event_summary(event)
    assert "cmd.exe" in summary
    assert "whoami" in summary


def test_metrics_initial():
    proc = EventProcessor()
    metrics = proc.get_metrics()
    assert metrics["total_processed"] == 0
    assert metrics["benign_filtered"] == 0


def test_enrich_event():
    proc = EventProcessor()
    event = {"process_name": "test.exe"}
    enriched = proc._enrich_event(event, 0.85, "test reason", path="fast")
    assert enriched["ml_detection"]["is_malicious"] is True
    assert enriched["level"] == "error"
    assert "THREAT" in enriched["message"]
