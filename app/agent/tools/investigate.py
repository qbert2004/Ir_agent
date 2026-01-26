"""Full investigation trigger tool wrapping CyberIncidentInvestigator."""

import uuid
from typing import Dict, List

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult


class InvestigateTool(BaseTool):
    """Trigger a full cyber incident investigation."""

    name = "investigate"
    description = (
        "Trigger a full 8-step cyber incident investigation using the "
        "CyberIncidentInvestigator. Analyzes events through classification, "
        "timeline building, IoC extraction, TTP analysis, root cause, "
        "impact assessment, response plan, and executive summary."
    )
    parameters = [
        ToolParameter(
            name="incident_id",
            description="Unique incident identifier (auto-generated if not provided)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="events_json",
            description="JSON string of events to investigate (list of event dicts)",
            type="string",
            required=False,
        ),
    ]

    def execute(self, **kwargs) -> ToolResult:
        try:
            from app.services.investigation_service import investigation_service
        except Exception as e:
            return ToolResult(
                success=False, output="",
                error=f"Investigation service not available: {e}",
            )

        if not investigation_service.is_available:
            return ToolResult(
                success=False, output="",
                error="CyberIncidentInvestigator is not available",
            )

        incident_id = kwargs.get("incident_id", "").strip()
        if not incident_id:
            incident_id = f"agent-{uuid.uuid4().hex[:8]}"

        events_json = kwargs.get("events_json", "")
        events: List[Dict] = []

        if events_json:
            import json
            try:
                events = json.loads(events_json)
                if isinstance(events, dict):
                    events = [events]
            except json.JSONDecodeError:
                return ToolResult(
                    success=False, output="",
                    error="Invalid events_json format",
                )

        if not events:
            # Use a minimal event set to trigger investigation
            events = [{
                "event_type": "SecurityAlert",
                "event_id": "0000",
                "hostname": "unknown",
                "user": "unknown",
                "timestamp": "unknown",
                "description": "Agent-triggered investigation",
            }]

        try:
            result = investigation_service.start_investigation(incident_id, events)
            report = investigation_service.get_report(incident_id, format="text")

            if report:
                output = f"Investigation {incident_id} completed.\n\n{report[:1800]}"
            else:
                output = f"Investigation {incident_id} started. Status: {result.get('status', 'unknown')}"

            return ToolResult(
                success=True,
                output=output[:2000],
                data={"incident_id": incident_id, "status": result.get("status")},
            )
        except Exception as e:
            return ToolResult(
                success=False, output="",
                error=f"Investigation failed: {e}",
            )
