"""
LLM Report Generator - Uses Groq ONLY for text generation.

The CyberMLEngine does ALL the actual analysis (classification, detection, mapping).
This module only converts structured ML results into human-readable reports.

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                        INVESTIGATION FLOW                        │
    │                                                                  │
    │   Events ──▶ [CyberMLEngine] ──▶ MLInvestigationResult          │
    │                   (ML only)           │                          │
    │                                       ▼                          │
    │                              [ReportGenerator] ──▶ Text Report  │
    │                                (LLM only for text)               │
    └─────────────────────────────────────────────────────────────────┘

LLM is used ONLY for:
    - Executive summary prose
    - Narrative timeline description
    - Human-readable recommendations

LLM is NOT used for:
    - Event classification (ML model)
    - MITRE mapping (rule-based)
    - IoC extraction (regex)
    - Threat scoring (algorithmic)
    - Incident type detection (ML + rules)
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime

from app.ml.cyber_ml_engine import (
    MLInvestigationResult,
    IncidentType,
    ThreatLevel,
    TimelineEntry,
    MITRETechnique,
    IoC,
)

logger = logging.getLogger("report-generator")


class ReportGenerator:
    """
    Generates human-readable reports from ML investigation results.

    Uses LLM (Groq) ONLY for prose generation - all analysis is already done by ML.
    Can also generate reports WITHOUT LLM using templates.
    """

    def __init__(self, use_llm: bool = True):
        """
        Initialize report generator.

        Args:
            use_llm: If True, use Groq for prose. If False, use templates only.
        """
        self.use_llm = use_llm
        self.client = None
        self.model = None

        if use_llm:
            self._init_llm()

    def _init_llm(self):
        """Initialize LLM client (Groq)."""
        try:
            import groq
            api_key = os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY")
            if api_key:
                self.client = groq.Groq(api_key=api_key)
                self.model = os.getenv("LLM_ANALYZER_MODEL", "llama-3.3-70b-versatile")
                logger.info(f"LLM initialized: {self.model}")
            else:
                logger.warning("No LLM API key - using template-based reports")
                self.use_llm = False
        except Exception as e:
            logger.error(f"Failed to initialize LLM: {e}")
            self.use_llm = False

    def generate_report(self, result: MLInvestigationResult, format: str = "text") -> str:
        """
        Generate full investigation report.

        Args:
            result: MLInvestigationResult from CyberMLEngine
            format: "text" for human-readable, "json" for structured

        Returns:
            Formatted report string
        """
        if format == "json":
            return self._generate_json_report(result)

        # Generate sections
        header = self._generate_header(result)
        executive_summary = self._generate_executive_summary(result)
        timeline_section = self._generate_timeline_section(result)
        iocs_section = self._generate_iocs_section(result)
        mitre_section = self._generate_mitre_section(result)
        recommendations_section = self._generate_recommendations_section(result)
        footer = self._generate_footer(result)

        # Combine
        sections = [
            header,
            executive_summary,
            timeline_section,
            iocs_section,
            mitre_section,
            recommendations_section,
            footer,
        ]

        return "\n".join(sections)

    def _generate_header(self, result: MLInvestigationResult) -> str:
        """Generate report header."""
        threat_emoji = {
            ThreatLevel.CRITICAL: "[!!!]",
            ThreatLevel.HIGH: "[!!]",
            ThreatLevel.MEDIUM: "[!]",
            ThreatLevel.LOW: "[.]",
            ThreatLevel.INFORMATIONAL: "[i]",
        }

        header = f"""
{'='*80}
                    CYBER INCIDENT INVESTIGATION REPORT
{'='*80}

Incident ID:      {result.incident_id}
Incident Type:    {result.incident_type.value.upper()} ({result.incident_type_confidence:.0%} confidence)
Threat Level:     {threat_emoji.get(result.threat_level, '')} {result.threat_level.value.upper()}
Threat Score:     {result.threat_score:.0f}/100

Analysis Date:    {result.analysis_timestamp}
Events Analyzed:  {result.total_events}
Malicious Events: {result.malicious_events}
Hosts Affected:   {len(result.affected_hosts)}
Users Affected:   {len(result.affected_users)}

{'='*80}
"""
        return header

    def _generate_executive_summary(self, result: MLInvestigationResult) -> str:
        """Generate executive summary - uses LLM if available."""
        section = f"""
EXECUTIVE SUMMARY
{'='*80}

"""
        if self.use_llm and self.client:
            summary = self._llm_generate_summary(result)
            section += summary
        else:
            # Template-based summary
            section += self._template_summary(result)

        # Add key findings
        section += "\n\nKEY FINDINGS:\n"
        for i, finding in enumerate(result.key_findings, 1):
            section += f"  {i}. {finding}\n"

        return section

    def _template_summary(self, result: MLInvestigationResult) -> str:
        """Generate template-based summary without LLM."""
        summary_templates = {
            IncidentType.RANSOMWARE: (
                f"A ransomware attack has been detected affecting {len(result.affected_hosts)} system(s). "
                f"The attack shows indicators of file encryption and system recovery inhibition. "
                f"Immediate containment is required."
            ),
            IncidentType.CREDENTIAL_THEFT: (
                f"Credential theft activity detected on {len(result.affected_hosts)} system(s). "
                f"Attackers may have compromised user credentials. "
                f"Password reset and MFA enforcement recommended."
            ),
            IncidentType.LATERAL_MOVEMENT: (
                f"Lateral movement detected across {len(result.affected_hosts)} hosts. "
                f"Attackers are actively spreading through the network. "
                f"Network segmentation and isolation required."
            ),
            IncidentType.DATA_EXFILTRATION: (
                f"Data exfiltration indicators found. "
                f"Sensitive data may have been transferred outside the network. "
                f"Egress traffic review and data scope assessment needed."
            ),
            IncidentType.COMMAND_AND_CONTROL: (
                f"Command and control (C2) activity detected on {len(result.affected_hosts)} host(s). "
                f"Systems may be under remote attacker control. "
                f"Block C2 indicators and isolate affected systems."
            ),
            IncidentType.MALWARE: (
                f"Malware activity detected on {len(result.affected_hosts)} system(s). "
                f"Malicious code execution observed. "
                f"Containment and forensic analysis required."
            ),
            IncidentType.PERSISTENCE: (
                f"Persistence mechanisms established on {len(result.affected_hosts)} system(s). "
                f"Attackers have created backdoors for continued access. "
                f"Complete remediation of persistence mechanisms required."
            ),
        }

        base_summary = summary_templates.get(
            result.incident_type,
            f"Security incident detected affecting {len(result.affected_hosts)} system(s). "
            f"Threat level: {result.threat_level.value}. Investigation and response required."
        )

        # Add MITRE context
        if result.mitre_techniques:
            tactics = list(set(t.tactic for t in result.mitre_techniques))
            base_summary += f"\n\nAttack utilized {len(result.mitre_techniques)} MITRE ATT&CK techniques "
            base_summary += f"across tactics: {', '.join(tactics)}."

        return base_summary

    def _llm_generate_summary(self, result: MLInvestigationResult) -> str:
        """Use LLM to generate executive summary prose."""
        # Prepare context from ML results
        context = {
            "incident_type": result.incident_type.value,
            "threat_level": result.threat_level.value,
            "threat_score": result.threat_score,
            "hosts_affected": len(result.affected_hosts),
            "events_analyzed": result.total_events,
            "malicious_events": result.malicious_events,
            "top_techniques": [
                f"{t.technique_id}: {t.technique_name}"
                for t in result.mitre_techniques[:5]
            ],
            "key_findings": result.key_findings,
            "ioc_count": len(result.iocs),
        }

        prompt = f"""Write a 2-3 paragraph executive summary for this cybersecurity incident.
Use clear, professional language suitable for C-level executives.

INCIDENT DATA (from ML analysis):
{json.dumps(context, indent=2)}

Requirements:
- Start with the type and severity
- Explain what happened in business terms
- Mention affected scope
- Note immediate risks
- Keep it concise and actionable

Write ONLY the summary text, no headers or formatting:"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity analyst writing incident reports. Be concise and professional."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"LLM summary generation failed: {e}")
            return self._template_summary(result)

    def _generate_timeline_section(self, result: MLInvestigationResult) -> str:
        """Generate timeline section."""
        section = f"""
{'='*80}
ATTACK TIMELINE
{'='*80}

"""
        if not result.timeline:
            section += "No significant events in timeline.\n"
            return section

        for i, entry in enumerate(result.timeline[:20], 1):  # Limit to 20 entries
            severity_marker = {
                ThreatLevel.CRITICAL: "[CRIT]",
                ThreatLevel.HIGH: "[HIGH]",
                ThreatLevel.MEDIUM: "[MED ]",
                ThreatLevel.LOW: "[LOW ]",
                ThreatLevel.INFORMATIONAL: "[INFO]",
            }.get(entry.severity, "[    ]")

            section += f"""
[{i:02d}] {entry.timestamp}
     Host: {entry.hostname} | Type: {entry.event_type}
     {severity_marker} {entry.description}
     ML Confidence: {entry.ml_confidence:.0%}
"""
            if entry.mitre_techniques:
                techs = ", ".join(f"{t.technique_id}" for t in entry.mitre_techniques)
                section += f"     MITRE: {techs}\n"

            if entry.iocs:
                iocs_str = ", ".join(f"{i.type}:{i.value[:30]}" for i in entry.iocs[:3])
                section += f"     IoCs: {iocs_str}\n"

        if len(result.timeline) > 20:
            section += f"\n... and {len(result.timeline) - 20} more events\n"

        return section

    def _generate_iocs_section(self, result: MLInvestigationResult) -> str:
        """Generate IoCs section."""
        section = f"""
{'='*80}
INDICATORS OF COMPROMISE (IoCs)
{'='*80}

Total IoCs Extracted: {len(result.iocs)}
"""
        if not result.iocs:
            section += "\nNo IoCs extracted.\n"
            return section

        # Group by type
        by_type: Dict[str, list] = {}
        for ioc in result.iocs:
            if ioc.type not in by_type:
                by_type[ioc.type] = []
            by_type[ioc.type].append(ioc)

        for ioc_type, iocs in by_type.items():
            section += f"\n{ioc_type.upper()} ({len(iocs)}):\n"
            for ioc in sorted(iocs, key=lambda x: x.confidence, reverse=True)[:10]:
                section += f"  - {ioc.value} (confidence: {ioc.confidence:.0%})\n"
            if len(iocs) > 10:
                section += f"  ... and {len(iocs) - 10} more\n"

        return section

    def _generate_mitre_section(self, result: MLInvestigationResult) -> str:
        """Generate MITRE ATT&CK section."""
        section = f"""
{'='*80}
MITRE ATT&CK MAPPING
{'='*80}

Techniques Identified: {len(result.mitre_techniques)}
"""
        if not result.mitre_techniques:
            section += "\nNo MITRE techniques identified.\n"
            return section

        # Group by tactic
        by_tactic: Dict[str, list] = {}
        for tech in result.mitre_techniques:
            if tech.tactic not in by_tactic:
                by_tactic[tech.tactic] = []
            by_tactic[tech.tactic].append(tech)

        tactic_order = [
            "initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery", "lateral_movement",
            "collection", "command_and_control", "exfiltration", "impact"
        ]

        for tactic in tactic_order:
            if tactic in by_tactic:
                techs = by_tactic[tactic]
                section += f"\n{tactic.upper().replace('_', ' ')}:\n"
                for tech in sorted(techs, key=lambda x: x.confidence, reverse=True):
                    section += f"  - {tech.technique_id}: {tech.technique_name} ({tech.confidence:.0%})\n"

        return section

    def _generate_recommendations_section(self, result: MLInvestigationResult) -> str:
        """Generate recommendations section - can use LLM for prose."""
        section = f"""
{'='*80}
RECOMMENDED ACTIONS
{'='*80}

IMMEDIATE ACTIONS:
"""
        for i, action in enumerate(result.recommended_actions[:5], 1):
            section += f"  {i}. {action}\n"

        if self.use_llm and self.client and len(result.recommended_actions) > 0:
            section += "\nDETAILED REMEDIATION GUIDANCE:\n"
            section += self._llm_generate_remediation(result)
        else:
            section += "\nADDITIONAL RECOMMENDATIONS:\n"
            for i, action in enumerate(result.recommended_actions[5:10], 6):
                section += f"  {i}. {action}\n"

        return section

    def _llm_generate_remediation(self, result: MLInvestigationResult) -> str:
        """Use LLM to generate detailed remediation guidance."""
        context = {
            "incident_type": result.incident_type.value,
            "threat_level": result.threat_level.value,
            "affected_hosts": result.affected_hosts[:5],
            "top_techniques": [t.technique_id for t in result.mitre_techniques[:5]],
            "ioc_types": list(set(i.type for i in result.iocs)),
            "recommended_actions": result.recommended_actions,
        }

        prompt = f"""Based on this incident analysis, provide 3-5 detailed remediation steps.
Each step should be actionable and specific.

INCIDENT DATA:
{json.dumps(context, indent=2)}

Write numbered, detailed remediation steps. Be specific and technical:"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior incident responder providing remediation guidance."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=600
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"LLM remediation generation failed: {e}")
            return "Detailed guidance unavailable. Follow immediate actions above."

    def _generate_footer(self, result: MLInvestigationResult) -> str:
        """Generate report footer."""
        return f"""
{'='*80}
END OF REPORT
{'='*80}

Report Generated: {datetime.utcnow().isoformat()}Z
Analysis Method: ML-based (CyberMLEngine)
Report Format: LLM-enhanced (Groq) if available

{'='*80}
"""

    def _generate_json_report(self, result: MLInvestigationResult) -> str:
        """Generate JSON format report."""
        from app.ml.cyber_ml_engine import get_ml_engine
        engine = get_ml_engine()
        data = engine.to_dict(result)

        # Add report metadata
        data["report_metadata"] = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "analysis_method": "ML-based",
            "llm_enhanced": self.use_llm,
        }

        return json.dumps(data, indent=2, ensure_ascii=False)


# Convenience function
def generate_report(result: MLInvestigationResult, format: str = "text", use_llm: bool = True) -> str:
    """Generate report from ML investigation result."""
    generator = ReportGenerator(use_llm=use_llm)
    return generator.generate_report(result, format=format)
