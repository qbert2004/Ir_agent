"""AI event analysis tool wrapping AIAnalyzer."""

import asyncio

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult


class AnalyzeEventTool(BaseTool):
    """Analyze a security event using the AI threat analyzer."""

    name = "analyze_event"
    description = (
        "Analyze a security event using the AI-powered threat analyzer. "
        "Returns threat score, level, summary, indicators, and recommended actions."
    )
    parameters = [
        ToolParameter(
            name="event_type",
            description="Type of event (e.g., ProcessCreate, LogonSuccess)",
            type="string",
            required=True,
        ),
        ToolParameter(
            name="event_id",
            description="Windows Event ID (e.g., 4688, 4624)",
            type="string",
            required=True,
        ),
        ToolParameter(
            name="hostname",
            description="Host where event occurred",
            type="string",
            required=False,
            default="unknown",
        ),
        ToolParameter(
            name="user",
            description="User associated with the event",
            type="string",
            required=False,
            default="unknown",
        ),
        ToolParameter(
            name="command_line",
            description="Command line if applicable",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="process_name",
            description="Process name if applicable",
            type="string",
            required=False,
        ),
    ]

    def execute(self, **kwargs) -> ToolResult:
        try:
            from app.services.ai_analyzer import ai_analyzer
        except Exception as e:
            return ToolResult(success=False, output="", error=f"AIAnalyzer not available: {e}")

        event = {
            "event_type": kwargs.get("event_type", ""),
            "event_id": kwargs.get("event_id", ""),
            "hostname": kwargs.get("hostname", "unknown"),
            "user": kwargs.get("user", "unknown"),
        }
        if kwargs.get("command_line"):
            event["command_line"] = kwargs["command_line"]
        if kwargs.get("process_name"):
            event["process_name"] = kwargs["process_name"]

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(
                        asyncio.run, ai_analyzer.analyze_event(event)
                    ).result()
            else:
                result = asyncio.run(ai_analyzer.analyze_event(event))
        except Exception as e:
            return ToolResult(success=False, output="", error=f"Analysis failed: {e}")

        threat_score = result.get("threat_score", 0)
        threat_level = result.get("threat_level", "unknown")
        summary = result.get("summary", "No summary")
        indicators = result.get("indicators", [])
        actions = result.get("recommended_actions", [])

        output = (
            f"AI Threat Analysis:\n"
            f"  Threat Score: {threat_score}/100\n"
            f"  Threat Level: {threat_level}\n"
            f"  Summary: {summary}\n"
        )
        if indicators:
            output += f"  Indicators: {', '.join(indicators[:5])}\n"
        if actions:
            output += f"  Recommended Actions:\n"
            for a in actions[:5]:
                output += f"    - {a}\n"

        return ToolResult(
            success=True,
            output=output,
            data=result,
        )
