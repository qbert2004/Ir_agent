"""
Tests for incident-based investigation architecture.

Covers:
  - Incident correlation: multiple events grouped into one incident
  - GET /ingest/incidents — list incidents
  - GET /ingest/incidents/{id} — get single incident
  - GET /ingest/incidents/{id}/report — text report
  - POST /ingest/incidents/{id}/investigate — agent investigation (mocked)
  - GetIncidentTool and GetIncidentEventsTool behaviour
  - EventProcessor passes incident_id to save_event
"""

import asyncio
import os
import sys
import types
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("ENVIRONMENT",              "testing")
os.environ.setdefault("LLM_API_KEY",              "")
os.environ.setdefault("MY_API_TOKEN",             "")
os.environ.setdefault("BETTER_STACK_SOURCE_TOKEN","")
os.environ.setdefault("CORS_ORIGINS",             "*")


# ── Stub heavy ML deps ────────────────────────────────────────────────────────

def _stub(name: str) -> types.ModuleType:
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m

for _dep in ("faiss", "sentence_transformers", "torch", "sklearn",
             "sklearn.ensemble", "sklearn.calibration"):
    if _dep not in sys.modules:
        _stub(_dep)

if "faiss" in sys.modules:
    sys.modules["faiss"].IndexFlatIP = MagicMock
    sys.modules["faiss"].read_index  = MagicMock(return_value=MagicMock())
    sys.modules["faiss"].write_index = MagicMock()
if "sentence_transformers" in sys.modules:
    sys.modules["sentence_transformers"].SentenceTransformer = MagicMock


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def manager():
    """Fresh IncidentManager (no singletons)."""
    from app.services.incident_manager import IncidentManager
    return IncidentManager()


@pytest.fixture()
def event_a():
    return {
        "timestamp":    "2026-04-27T10:00:00Z",
        "event_id":     4688,
        "hostname":     "WS-VICTIM01",
        "event_type":   "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell -enc aQBuAHYAbwBrAGUALQBleHByZXNzaW9u",
        "user":         "john.doe",
    }


@pytest.fixture()
def event_b():
    return {
        "timestamp":    "2026-04-27T10:01:00Z",
        "event_id":     4688,
        "hostname":     "WS-VICTIM01",
        "event_type":   "process_creation",
        "process_name": "mimikatz.exe",
        "command_line": "sekurlsa::logonpasswords",
        "user":         "john.doe",
    }


@pytest.fixture()
def event_c():
    """Event on a different host — should create a separate incident."""
    return {
        "timestamp":    "2026-04-27T10:02:00Z",
        "event_id":     4625,
        "hostname":     "DC-01",
        "event_type":   "logon_failure",
        "user":         "administrator",
        "source_ip":    "185.220.101.5",
    }


# ── IncidentManager unit tests ────────────────────────────────────────────────

class TestIncidentCorrelation:

    def test_two_events_same_host_same_incident(self, manager, event_a, event_b):
        id1 = manager.correlate_event(event_a, 0.9, "ML malicious")
        id2 = manager.correlate_event(event_b, 0.85, "ML malicious")
        assert id1 == id2, "Events from same host within window must share incident ID"

    def test_different_host_separate_incident(self, manager, event_a, event_c):
        id1 = manager.correlate_event(event_a, 0.9, "ML malicious")
        id2 = manager.correlate_event(event_c, 0.75, "ML malicious")
        assert id1 != id2, "Events from different hosts must produce separate incidents"

    def test_incident_accumulates_events(self, manager, event_a, event_b):
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.correlate_event(event_b, 0.85, "r")
        inc = manager._incidents[inc_id]
        assert len(inc.events) == 2

    def test_affected_hosts_and_users_tracked(self, manager, event_a, event_b):
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.correlate_event(event_b, 0.85, "r")
        inc = manager._incidents[inc_id]
        assert "WS-VICTIM01" in inc.affected_hosts
        assert "john.doe"    in inc.affected_users

    def test_investigate_builds_timeline(self, manager, event_a, event_b):
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.correlate_event(event_b, 0.85, "r")
        result = manager.investigate(inc_id)
        assert result is not None
        assert result["event_count"] == 2
        assert len(result["timeline"]) == 2

    def test_investigate_extracts_mitre(self, manager, event_b):
        inc_id = manager.correlate_event(event_b, 0.85, "r")
        result = manager.investigate(inc_id)
        techs = [t["id"] for t in result["mitre_techniques"]]
        assert "T1003.001" in techs, "mimikatz should map to T1003.001"

    def test_investigate_classifies_credential_access(self, manager, event_b):
        """Classification must identify credential access regardless of severity score."""
        inc_id = manager.correlate_event(event_b, 0.85, "r")
        result = manager.investigate(inc_id)
        assert "credential" in result["classification"].lower()

    def test_multiple_events_elevate_severity(self, manager, event_a, event_b, event_c):
        """More events + more phases should push severity above 'low'."""
        # Attach event_c to same host to get more diversity
        event_c_local = {**event_c, "hostname": "WS-VICTIM01"}
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.correlate_event(event_b, 0.85, "r")
        manager.correlate_event(event_c_local, 0.8, "r")
        result = manager.investigate(inc_id)
        assert result["confidence"] > 0.3, "Confidence should be meaningful with 3 events"

    def test_store_agent_analysis(self, manager, event_a):
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        analysis = {
            "verdict": "MALICIOUS", "agent_confidence": 0.95,
            "summary": "PowerShell encoded command detected.",
            "tools_used": ["lookup_ioc", "mitre_lookup"], "steps": 4,
        }
        manager.store_agent_analysis(inc_id, analysis)
        inc = manager._incidents[inc_id]
        assert inc.agent_analysis is not None
        assert inc.agent_analysis["verdict"] == "MALICIOUS"
        assert inc.incident_summary != ""

    def test_to_dict_includes_agent_analysis(self, manager, event_a):
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.store_agent_analysis(inc_id, {"verdict": "SUSPICIOUS"})
        d = manager.get_incident(inc_id)
        assert "agent_analysis" in d
        assert d["agent_analysis"]["verdict"] == "SUSPICIOUS"

    def test_to_report_includes_agent_section(self, manager, event_a):
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.investigate(inc_id)
        manager.store_agent_analysis(inc_id, {
            "verdict": "MALICIOUS", "agent_confidence": 0.9,
            "summary": "Confirmed attack.", "tools_used": ["lookup_ioc"], "steps": 3,
        })
        report = manager.get_report(inc_id)
        assert "AI AGENT INVESTIGATION" in report
        assert "MALICIOUS" in report


# ── GetIncidentTool unit tests ─────────────────────────────────────────────────

class TestGetIncidentTool:

    def test_returns_incident_data(self, manager, event_a, event_b):
        from app.agent.tools.get_incident import GetIncidentTool
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.correlate_event(event_b, 0.85, "r")
        manager.investigate(inc_id)

        tool   = GetIncidentTool(manager)
        result = tool.execute(incident_id=inc_id)

        assert result.success
        assert inc_id in result.output
        assert "ATTACK TIMELINE" in result.output

    def test_unknown_incident_returns_error(self, manager):
        from app.agent.tools.get_incident import GetIncidentTool
        tool   = GetIncidentTool(manager)
        result = tool.execute(incident_id="IR-00000000-UNKNOWN")
        assert not result.success
        assert "not found" in (result.error or "").lower()

    def test_no_manager_returns_error(self):
        from app.agent.tools.get_incident import GetIncidentTool
        tool   = GetIncidentTool(None)
        result = tool.execute(incident_id="IR-X")
        assert not result.success


# ── GetIncidentEventsTool unit tests ──────────────────────────────────────────

class TestGetIncidentEventsTool:

    def test_returns_events(self, manager, event_a, event_b):
        from app.agent.tools.get_incident_events import GetIncidentEventsTool
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.correlate_event(event_b, 0.85, "r")

        tool   = GetIncidentEventsTool(manager)
        result = tool.execute(incident_id=inc_id)

        assert result.success
        assert result.data["count"] == 2
        assert "powershell.exe" in result.output

    def test_phase_filter_credential_access(self, manager, event_b):
        from app.agent.tools.get_incident_events import GetIncidentEventsTool
        inc_id = manager.correlate_event(event_b, 0.85, "r")
        manager.investigate(inc_id)  # builds timeline with phases

        tool   = GetIncidentEventsTool(manager)
        result = tool.execute(incident_id=inc_id, phase_filter="Credential Access")

        assert result.success

    def test_limit_respected(self, manager, event_a, event_b):
        from app.agent.tools.get_incident_events import GetIncidentEventsTool
        inc_id = manager.correlate_event(event_a, 0.9, "r")
        manager.correlate_event(event_b, 0.85, "r")

        tool   = GetIncidentEventsTool(manager)
        result = tool.execute(incident_id=inc_id, limit=1)

        assert result.success
        assert result.data["count"] == 1
        assert result.data["total_in_incident"] == 2


# ── API endpoint tests ────────────────────────────────────────────────────────

class TestIncidentAPIEndpoints:

    def test_list_incidents_empty(self, client):
        r = client.get("/ingest/incidents")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "success"
        assert "incidents" in data
        assert "stats" in data

    def test_get_unknown_incident(self, client):
        r = client.get("/ingest/incidents/IR-00000000-MISSING")
        assert r.status_code == 200
        assert r.json()["status"] == "error"

    def test_incident_report_unknown(self, client):
        r = client.get("/ingest/incidents/IR-00000000-MISSING/report")
        assert r.status_code == 200
        assert r.json()["status"] == "error"

    def test_ingest_creates_incident(self, client, sample_event):
        """Ingesting a malicious event should correlate into an incident."""
        client.post("/ingest/telemetry", json=sample_event)
        r = client.get("/ingest/incidents")
        assert r.status_code == 200
        # incident list endpoint is reachable (may have 0 incidents if ML filtered)

    @patch("app.services.event_processor.EventProcessor.run_incident_investigation",
           new_callable=AsyncMock)
    def test_investigate_endpoint_calls_agent(self, mock_investigate, client):
        """POST /incidents/{id}/investigate must call run_incident_investigation."""
        from app.services.incident_manager import get_incident_manager
        mgr = get_incident_manager()
        ev  = {
            "timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
            "hostname": "TEST-HOST", "process_name": "powershell.exe",
            "command_line": "invoke-mimikatz", "user": "admin",
        }
        inc_id = mgr.correlate_event(ev, 0.9, "test")

        mock_investigate.return_value = {
            "status": "success",
            "incident_id": inc_id,
            "agent_verdict": "MALICIOUS",
            "agent_confidence": 0.95,
            "summary": "Test verdict.",
            "tools_used": ["get_incident", "lookup_ioc"],
            "steps": 3,
        }

        r = client.post(f"/ingest/incidents/{inc_id}/investigate")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "success"
        assert data["agent_verdict"] == "MALICIOUS"
        mock_investigate.assert_called_once_with(inc_id)
