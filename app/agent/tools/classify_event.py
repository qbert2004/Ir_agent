"""ML-based event classification tool wrapping MLAttackDetector."""

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult


class ClassifyEventTool(BaseTool):
    """Classify a security event as malicious or benign using ML model."""

    name = "classify_event"
    description = (
        "Classify a security event using the ML attack detector. "
        "Returns whether the event is malicious, confidence score (0-1), and reason. "
        "Use this for fast initial triage before deeper analysis."
    )
    parameters = [
        ToolParameter(
            name="event_id",
            description="Windows Event ID (e.g., 4688, 4624, 7045)",
            type="string",
            required=False,
            default="0",
        ),
        ToolParameter(
            name="event_type",
            description="Type of event (e.g., ProcessCreate, LogonSuccess)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="process_name",
            description="Name of the process (e.g., powershell.exe, cmd.exe)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="command_line",
            description="Full command line if available",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="parent_image",
            description="Parent process path",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="user",
            description="Username associated with the event",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="logon_type",
            description="Logon type for authentication events (3=network, 10=remote)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="destination_port",
            description="Destination port for network events",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="channel",
            description="Event log channel (Security, Sysmon, etc.)",
            type="string",
            required=False,
            default="Security",
        ),
    ]

    def execute(self, **kwargs) -> ToolResult:
        try:
            from app.services.ml_detector import get_detector
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"ML Detector not available: {e}"
            )

        # Build event dict from parameters
        event = {}

        if kwargs.get("event_id"):
            try:
                event["event_id"] = int(kwargs["event_id"])
            except (ValueError, TypeError):
                event["event_id"] = 0

        if kwargs.get("event_type"):
            event["event_type"] = kwargs["event_type"]
        if kwargs.get("process_name"):
            event["process_name"] = kwargs["process_name"]
        if kwargs.get("command_line"):
            event["command_line"] = kwargs["command_line"]
        if kwargs.get("parent_image"):
            event["parent_image"] = kwargs["parent_image"]
        if kwargs.get("user"):
            event["user"] = kwargs["user"]
        if kwargs.get("channel"):
            event["channel"] = kwargs["channel"]

        if kwargs.get("logon_type"):
            try:
                event["logon_type"] = int(kwargs["logon_type"])
            except (ValueError, TypeError):
                pass

        if kwargs.get("destination_port"):
            try:
                event["destination_port"] = int(kwargs["destination_port"])
            except (ValueError, TypeError):
                pass

        try:
            detector = get_detector()
            is_malicious, confidence, reason = detector.predict(event)
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"ML prediction failed: {e}"
            )

        # Determine threat level
        if confidence >= 0.8:
            threat_level = "HIGH"
        elif confidence >= 0.6:
            threat_level = "MEDIUM"
        elif confidence >= 0.5:
            threat_level = "LOW"
        else:
            threat_level = "BENIGN"

        output = (
            f"ML Classification Result:\n"
            f"  Is Malicious: {is_malicious}\n"
            f"  Confidence: {confidence:.1%}\n"
            f"  Threat Level: {threat_level}\n"
            f"  Reason: {reason}\n"
        )

        if is_malicious:
            output += "\n  Recommendation: Further investigation recommended"
            if confidence < 0.8:
                output += " (confidence below 80%)"

        return ToolResult(
            success=True,
            output=output,
            data={
                "is_malicious": is_malicious,
                "confidence": confidence,
                "threat_level": threat_level,
                "reason": reason,
                "model_ready": detector.is_ready,
            },
        )
