"""Search ingested telemetry events tool."""

from typing import List, Dict

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult


class SearchLogsTool(BaseTool):
    """Search in-memory ingested security events."""

    name = "search_logs"
    description = (
        "Search through ingested security events/logs by keywords, event IDs, "
        "hostnames, or users. Returns matching events from the in-memory store."
    )
    parameters = [
        ToolParameter(
            name="keyword",
            description="Keyword to search for in event fields",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="event_id",
            description="Windows Event ID to filter by (e.g., 4688, 4624)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="hostname",
            description="Hostname to filter by",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="limit",
            description="Max number of results (default: 10)",
            type="integer",
            required=False,
            default=10,
        ),
    ]

    def __init__(self, event_store: List[Dict] = None):
        self._events = event_store if event_store is not None else []

    def set_event_store(self, events: List[Dict]):
        """Update the reference to the event store."""
        self._events = events

    def execute(self, **kwargs) -> ToolResult:
        keyword = kwargs.get("keyword", "").lower()
        event_id = kwargs.get("event_id", "")
        hostname = kwargs.get("hostname", "").lower()
        limit = int(kwargs.get("limit", 10))

        matches = []
        for event in self._events:
            if event_id and str(event.get("event_id", "")) != str(event_id):
                continue
            if hostname and hostname not in str(event.get("hostname", "")).lower():
                continue
            if keyword:
                event_str = str(event).lower()
                if keyword not in event_str:
                    continue
            matches.append(event)
            if len(matches) >= limit:
                break

        if not matches:
            return ToolResult(
                success=True,
                output="No matching events found.",
                data={"count": 0},
            )

        lines = [f"Found {len(matches)} matching events:"]
        for i, event in enumerate(matches, 1):
            eid = event.get("event_id", "?")
            host = event.get("hostname", "?")
            user = event.get("user", "?")
            etype = event.get("event_type", "?")
            ts = event.get("timestamp", "?")
            cmd = event.get("command_line", "")
            entry = f"\n[{i}] EventID={eid} | Host={host} | User={user} | Type={etype} | Time={ts}"
            if cmd:
                entry += f"\n    Command: {cmd[:200]}"
            lines.append(entry)

        output = "\n".join(lines)
        return ToolResult(
            success=True,
            output=output[:2000],
            data={"count": len(matches)},
        )
