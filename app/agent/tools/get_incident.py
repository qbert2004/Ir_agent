"""Get full incident details — lets the agent query a correlated incident."""

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult


class GetIncidentTool(BaseTool):
    """Retrieve full correlated incident: timeline, IoCs, MITRE, key findings."""

    name = "get_incident"
    description = (
        "Retrieve full details of a correlated security incident including the attack timeline, "
        "all Indicators of Compromise, MITRE ATT&CK techniques, affected hosts/users, "
        "root cause, and impact assessment. Use this to understand the full scope of an "
        "attack across multiple log entries before making a verdict."
    )
    parameters = [
        ToolParameter(
            name="incident_id",
            description="Incident ID (e.g., IR-20250401-ABC123)",
            type="string",
            required=True,
        ),
    ]

    def __init__(self, incident_manager=None):
        self._incident_manager = incident_manager

    def execute(self, **kwargs) -> ToolResult:
        incident_id = kwargs.get("incident_id", "").strip()

        if not self._incident_manager:
            return ToolResult(success=False, output="", error="Incident manager not available")

        incident = self._incident_manager.get_incident(incident_id)
        if not incident:
            return ToolResult(
                success=False,
                output="",
                error=f"Incident {incident_id} not found",
            )

        lines = []
        lines.append(f"INCIDENT: {incident['id']}")
        lines.append(f"Host: {incident['host']}")
        lines.append(f"Severity: {incident['severity'].upper()}")
        lines.append(f"Confidence: {incident['confidence']:.0%}")
        lines.append(f"Classification: {incident['classification']}")
        lines.append(f"Status: {incident['status']}")
        lines.append(f"Total Events: {incident['event_count']}")
        lines.append(f"Affected Hosts: {', '.join(incident.get('affected_hosts', []))}")
        lines.append(f"Affected Users: {', '.join(incident.get('affected_users', []))}")
        lines.append("")

        if incident.get("timeline"):
            lines.append(f"ATTACK TIMELINE ({len(incident['timeline'])} entries):")
            for entry in incident["timeline"][:20]:
                ts = entry["timestamp"][:19] if len(entry.get("timestamp", "")) >= 19 else entry.get("timestamp", "?")
                lines.append(f"  [{entry['phase']}] {ts} — {entry['description'][:120]}")
                if entry.get("mitre_techniques"):
                    lines.append(f"    MITRE: {', '.join(entry['mitre_techniques'])}")
                if entry.get("iocs"):
                    lines.append(f"    IoCs: {', '.join(entry['iocs'][:3])}")
            lines.append("")

        if incident.get("iocs"):
            lines.append(f"INDICATORS OF COMPROMISE ({len(incident['iocs'])} total):")
            for ioc in incident["iocs"][:15]:
                lines.append(f"  {ioc['type']}: {ioc['value']} — {ioc['context']}")
            lines.append("")

        if incident.get("mitre_techniques"):
            lines.append(f"MITRE ATT&CK TECHNIQUES ({len(incident['mitre_techniques'])} identified):")
            for tech in incident["mitre_techniques"]:
                lines.append(f"  {tech['id']} — {tech['name']} [{tech.get('tactic', '')}]")
            lines.append("")

        if incident.get("key_findings"):
            lines.append("KEY FINDINGS:")
            for finding in incident["key_findings"]:
                lines.append(f"  • {finding}")
            lines.append("")

        if incident.get("root_cause"):
            lines.append(f"ROOT CAUSE: {incident['root_cause']}")

        if incident.get("impact_assessment"):
            lines.append(f"IMPACT: {incident['impact_assessment']}")

        if incident.get("recommendations"):
            lines.append("RECOMMENDATIONS:")
            for rec in incident["recommendations"][:5]:
                lines.append(f"  • {rec}")

        output = "\n".join(lines)
        return ToolResult(
            success=True,
            output=output[:3500],
            data={"incident_id": incident_id, "event_count": incident["event_count"]},
        )
