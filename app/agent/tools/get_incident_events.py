"""Get raw events from an incident — lets the agent do forensic analysis per log."""

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult


class GetIncidentEventsTool(BaseTool):
    """Retrieve raw log events from an incident for detailed forensic analysis."""

    name = "get_incident_events"
    description = (
        "Get raw log events that belong to a correlated incident. Returns individual event "
        "details: process names, command lines, user activity, timestamps, source IPs, etc. "
        "Use for deep forensic analysis of exact actions taken in each step of the attack. "
        "Can filter by attack phase to focus on specific stages."
    )
    parameters = [
        ToolParameter(
            name="incident_id",
            description="Incident ID (e.g., IR-20250401-ABC123)",
            type="string",
            required=True,
        ),
        ToolParameter(
            name="phase_filter",
            description=(
                "Filter by attack phase (optional). Valid values: "
                "'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', "
                "'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', "
                "'Collection', 'Exfiltration', 'Command and Control', 'Impact'"
            ),
            type="string",
            required=False,
        ),
        ToolParameter(
            name="limit",
            description="Max number of events to return (default: 20, max: 50)",
            type="integer",
            required=False,
            default=20,
        ),
    ]

    _IMPORTANT_FIELDS = [
        "timestamp", "event_id", "event_type", "hostname", "user",
        "process_name", "command_line", "parent_image", "source_ip",
        "destination_ip", "destination_port", "logon_type",
        "service_file", "image_loaded", "query_name",
    ]

    def __init__(self, incident_manager=None):
        self._incident_manager = incident_manager

    def execute(self, **kwargs) -> ToolResult:
        incident_id = kwargs.get("incident_id", "").strip()
        phase_filter = kwargs.get("phase_filter", "").strip().lower()
        limit = min(int(kwargs.get("limit", 20)), 50)

        if not self._incident_manager:
            return ToolResult(success=False, output="", error="Incident manager not available")

        incident_obj = self._incident_manager._incidents.get(incident_id)
        if not incident_obj:
            return ToolResult(
                success=False,
                output="",
                error=f"Incident {incident_id} not found",
            )

        events = list(incident_obj.events)
        total = len(events)

        # Filter by attack phase using timeline entries
        if phase_filter and incident_obj.timeline:
            phase_timestamps = {
                entry.timestamp
                for entry in incident_obj.timeline
                if phase_filter in entry.phase.value.lower()
            }
            if phase_timestamps:
                events = [e for e in events if e.get("timestamp", "") in phase_timestamps]

        events = events[:limit]

        if not events:
            msg = f"No events in incident {incident_id}"
            if phase_filter:
                msg += f" matching phase '{phase_filter}'"
            return ToolResult(success=True, output=msg, data={"count": 0, "total": total})

        lines = [f"Events from {incident_id} — showing {len(events)} of {total} total:"]
        if phase_filter:
            lines[0] += f" (phase filter: '{phase_filter}')"

        for i, ev in enumerate(events, 1):
            lines.append(f"\n[Event {i}]")
            for field in self._IMPORTANT_FIELDS:
                val = ev.get(field)
                if val is not None and val != "":
                    val_str = str(val)
                    if len(val_str) > 250:
                        val_str = val_str[:250] + "…"
                    lines.append(f"  {field}: {val_str}")
            # Script block (4104) - may be long
            script = ev.get("script_block_text", "")
            if script:
                lines.append(f"  script_block_text: {script[:300]}{'…' if len(script) > 300 else ''}")
            ml_conf = ev.get("_ml_confidence")
            if ml_conf is not None:
                lines.append(f"  ml_confidence: {ml_conf:.0%}")

        output = "\n".join(lines)
        return ToolResult(
            success=True,
            output=output[:4000],
            data={"count": len(events), "total_in_incident": total},
        )
