"""
ML-First Cyber Incident Investigator

This is the main entry point for incident investigation.
Uses ML Engine for ALL analysis, LLM only for report text generation.

Usage:
    from app.ml.investigator import MLInvestigator

    investigator = MLInvestigator()

    # Investigate incident
    result = investigator.investigate("INC-001", events)

    # Get report (LLM used only here for prose)
    report = investigator.get_report("INC-001")

    # Or get report without LLM
    report = investigator.get_report("INC-001", use_llm=False)
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from app.ml.cyber_ml_engine import (
    CyberMLEngine,
    MLInvestigationResult,
    IncidentType,
    ThreatLevel,
    get_ml_engine,
)
from app.ml.report_generator import ReportGenerator, generate_report

logger = logging.getLogger("ml-investigator")


class MLInvestigator:
    """
    ML-First Incident Investigator.

    Architecture:
        ┌──────────────────────────────────────────────────────────┐
        │                    MLInvestigator                        │
        │                                                          │
        │   Events ──▶ [CyberMLEngine] ──▶ MLInvestigationResult  │
        │                  (ML only)              │                │
        │                                         ▼                │
        │                              [ReportGenerator]           │
        │                              (LLM for prose only)        │
        │                                         │                │
        │                                         ▼                │
        │                                  Text Report             │
        └──────────────────────────────────────────────────────────┘

    The CyberMLEngine performs:
        - Event classification (malicious/benign)
        - Incident type detection
        - MITRE ATT&CK mapping
        - IoC extraction
        - Timeline building
        - Threat scoring

    The ReportGenerator uses LLM ONLY for:
        - Executive summary prose
        - Narrative descriptions
        - Detailed remediation text
    """

    def __init__(self, models_dir: str = "models", use_llm_for_reports: bool = True):
        """
        Initialize the investigator.

        Args:
            models_dir: Directory containing ML models
            use_llm_for_reports: If True, use LLM for report prose generation
        """
        self.ml_engine = get_ml_engine(models_dir)
        self.use_llm = use_llm_for_reports
        self.investigations: Dict[str, MLInvestigationResult] = {}

        logger.info("MLInvestigator initialized")
        logger.info(f"  ML Engine: {self.ml_engine.get_model_info()}")
        logger.info(f"  LLM for reports: {self.use_llm}")

    def investigate(self, incident_id: str, events: List[Dict[str, Any]]) -> MLInvestigationResult:
        """
        Perform full incident investigation using ML.

        This method uses ONLY the ML engine - NO LLM calls.

        Args:
            incident_id: Unique incident identifier
            events: List of security events to analyze

        Returns:
            MLInvestigationResult with all analysis done by ML
        """
        logger.info(f"Starting investigation: {incident_id}")
        logger.info(f"Events to analyze: {len(events)}")

        # ALL analysis is done by ML engine
        result = self.ml_engine.investigate(incident_id, events)

        # Store for later retrieval
        self.investigations[incident_id] = result

        logger.info(f"Investigation complete: {incident_id}")
        logger.info(f"  Incident type: {result.incident_type.value}")
        logger.info(f"  Threat level: {result.threat_level.value}")
        logger.info(f"  Threat score: {result.threat_score:.0f}/100")

        return result

    def get_report(
        self,
        incident_id: str,
        format: str = "text",
        use_llm: Optional[bool] = None
    ) -> str:
        """
        Get investigation report.

        LLM is used ONLY for prose generation if enabled.
        All analysis data comes from ML engine.

        Args:
            incident_id: Incident to report on
            format: "text" or "json"
            use_llm: Override default LLM usage for this report

        Returns:
            Formatted report string
        """
        if incident_id not in self.investigations:
            return f"Investigation {incident_id} not found"

        result = self.investigations[incident_id]

        # Determine if we should use LLM for this report
        llm_enabled = use_llm if use_llm is not None else self.use_llm

        return generate_report(result, format=format, use_llm=llm_enabled)

    def get_investigation(self, incident_id: str) -> Optional[MLInvestigationResult]:
        """Get raw investigation result."""
        return self.investigations.get(incident_id)

    def classify_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a single event (ML only, no LLM).

        Returns:
            Classification result dict
        """
        result = self.ml_engine.classify_event(event)
        return {
            "label": result.label,
            "confidence": result.confidence,
            "probabilities": result.probabilities,
            "explanation": result.explanation,
        }

    def map_to_mitre(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Map event to MITRE ATT&CK (rule-based, no LLM).

        Returns:
            List of matched techniques
        """
        techniques = self.ml_engine.map_to_mitre(event)
        return [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "tactic": t.tactic,
                "confidence": t.confidence,
                "evidence": t.evidence,
            }
            for t in techniques
        ]

    def extract_iocs(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract IoCs from event (regex-based, no LLM).

        Returns:
            List of extracted IoCs
        """
        iocs = self.ml_engine.extract_iocs(event)
        return [
            {
                "type": i.type,
                "value": i.value,
                "confidence": i.confidence,
                "context": i.context,
            }
            for i in iocs
        ]

    def list_investigations(self) -> List[Dict[str, Any]]:
        """List all investigations."""
        return [
            {
                "incident_id": result.incident_id,
                "incident_type": result.incident_type.value,
                "threat_level": result.threat_level.value,
                "threat_score": result.threat_score,
                "timestamp": result.analysis_timestamp,
            }
            for result in self.investigations.values()
        ]

    def get_engine_info(self) -> Dict[str, Any]:
        """Get ML engine information."""
        return self.ml_engine.get_model_info()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

_investigator: Optional[MLInvestigator] = None


def get_investigator(models_dir: str = "models", use_llm: bool = True) -> MLInvestigator:
    """Get investigator singleton."""
    global _investigator
    if _investigator is None:
        _investigator = MLInvestigator(models_dir=models_dir, use_llm_for_reports=use_llm)
    return _investigator


async def quick_investigate(incident_id: str, events: List[Dict]) -> Dict:
    """
    Quick investigation returning dict result.

    Example:
        result = await quick_investigate("INC-001", events)
        print(result["threat_level"])
    """
    investigator = get_investigator()
    ml_result = investigator.investigate(incident_id, events)

    return {
        "incident_id": ml_result.incident_id,
        "incident_type": ml_result.incident_type.value,
        "threat_level": ml_result.threat_level.value,
        "threat_score": ml_result.threat_score,
        "malicious_events": ml_result.malicious_events,
        "total_events": ml_result.total_events,
        "affected_hosts": ml_result.affected_hosts,
        "techniques_count": len(ml_result.mitre_techniques),
        "iocs_count": len(ml_result.iocs),
        "key_findings": ml_result.key_findings,
        "recommended_actions": ml_result.recommended_actions,
    }


# ============================================================================
# CLI DEMO
# ============================================================================

def demo():
    """Demo the ML investigator."""
    print("=" * 70)
    print("ML-First Cyber Incident Investigator Demo")
    print("=" * 70)

    # Sample ransomware events
    events = [
        {
            "timestamp": "2024-01-15T08:30:00Z",
            "event_id": 4624,
            "hostname": "WS-USER01",
            "event_type": "logon",
            "user": "john.doe",
            "logon_type": 2,
        },
        {
            "timestamp": "2024-01-15T08:35:00Z",
            "event_id": 4688,
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "outlook.exe",
            "user": "john.doe",
        },
        {
            "timestamp": "2024-01-15T08:37:00Z",
            "event_id": 4688,
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "invoice_2024.exe",
            "parent_image": "outlook.exe",
            "user": "john.doe",
            "command_line": "invoice_2024.exe -silent"
        },
        {
            "timestamp": "2024-01-15T08:38:00Z",
            "event_id": 3,
            "hostname": "WS-USER01",
            "event_type": "network",
            "destination_ip": "185.220.101.45",
            "destination_port": 443,
        },
        {
            "timestamp": "2024-01-15T08:40:00Z",
            "event_id": 4688,
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
        },
        {
            "timestamp": "2024-01-15T08:42:00Z",
            "event_id": 4688,
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQA",
        },
    ]

    investigator = MLInvestigator(use_llm_for_reports=False)  # No LLM for demo

    print("\n[1/3] Investigating incident (ML only)...")
    result = investigator.investigate("DEMO-001", events)

    print(f"\n[2/3] Investigation Results:")
    print(f"  Incident Type: {result.incident_type.value}")
    print(f"  Threat Level: {result.threat_level.value}")
    print(f"  Threat Score: {result.threat_score:.0f}/100")
    print(f"  MITRE Techniques: {len(result.mitre_techniques)}")
    print(f"  IoCs Found: {len(result.iocs)}")
    print(f"  Timeline Events: {len(result.timeline)}")

    print("\n[3/3] Key Findings:")
    for finding in result.key_findings:
        print(f"  - {finding}")

    print("\n" + "=" * 70)
    print("Full report (template-based, no LLM):")
    print("=" * 70)
    report = investigator.get_report("DEMO-001", use_llm=False)
    print(report)


if __name__ == "__main__":
    demo()
