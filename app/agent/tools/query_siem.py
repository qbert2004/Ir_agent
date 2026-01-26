"""Better Stack SIEM query tool."""

import os

import httpx

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult


class QuerySIEMTool(BaseTool):
    """Query Better Stack for security logs and events."""

    name = "query_siem"
    description = (
        "Query the Better Stack SIEM/logging platform for security events. "
        "Search by keywords, time range, or severity level."
    )
    parameters = [
        ToolParameter(
            name="query",
            description="Search query string for Better Stack logs",
            type="string",
            required=True,
        ),
        ToolParameter(
            name="limit",
            description="Max number of results (default: 20)",
            type="integer",
            required=False,
            default=20,
        ),
    ]

    def execute(self, **kwargs) -> ToolResult:
        query = kwargs.get("query", "")
        limit = int(kwargs.get("limit", 20))

        token = os.getenv("BETTER_STACK_SOURCE_TOKEN", "")
        if not token:
            return ToolResult(
                success=False,
                output="",
                error="Better Stack token not configured (BETTER_STACK_SOURCE_TOKEN)",
            )

        try:
            # Better Stack Logs API query
            response = httpx.get(
                "https://logs.betterstack.com/api/v1/query",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                params={"query": query, "limit": limit},
                timeout=15.0,
            )

            if response.status_code == 200:
                data = response.json()
                events = data.get("data", [])

                if not events:
                    return ToolResult(
                        success=True,
                        output="No events found matching the query.",
                        data={"count": 0},
                    )

                lines = [f"Found {len(events)} events from Better Stack:"]
                for i, event in enumerate(events[:limit], 1):
                    attrs = event.get("attributes", {})
                    msg = attrs.get("message", "")[:200]
                    level = attrs.get("level", "info")
                    ts = attrs.get("dt", "")
                    lines.append(f"\n[{i}] [{level}] {ts}: {msg}")

                output = "\n".join(lines)
                return ToolResult(
                    success=True,
                    output=output[:2000],
                    data={"count": len(events)},
                )
            else:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Better Stack API returned status {response.status_code}",
                )

        except httpx.TimeoutException:
            return ToolResult(success=False, output="", error="Better Stack query timed out")
        except Exception as e:
            return ToolResult(success=False, output="", error=f"SIEM query failed: {e}")
