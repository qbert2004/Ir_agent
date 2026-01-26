"""
Better Stack Integration Service
"""
import httpx
from typing import Dict, Any, List
from datetime import datetime, timezone
from app.core.config import settings


class BetterStackService:
    """Better Stack log forwarding service"""

    def __init__(self):
        self.enabled = False
        self.token = settings.betterstack_token

        # ⬇️ ИСПРАВЛЕННЫЙ URL для EU региона
        self.url = "https://s1564996.eu-nbg-2.betterstackdata.com/"

        if self.token:
            self.enabled = True
            print(f"OK Better Stack: Enabled")
            print(f"   URL: {self.url}")
        else:
            print("WARNING  Better Stack: Disabled (no token)")

    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Send a single event to Better Stack"""
        if not self.enabled:
            return False

        try:
            log_entry = self._format_log(event)

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    self.url,
                    json=log_entry,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.token}"
                    }
                )

                if response.status_code in [200, 202, 204]:
                    print(f"OK Sent to Better Stack: {event.get('event_type', 'Unknown')}")
                    return True
                else:
                    print(f"ERROR Better Stack error {response.status_code}: {response.text}")
                    return False

        except Exception as e:
            print(f"ERROR Failed to send to Better Stack: {e}")
            return False

    async def send_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send multiple events to Better Stack"""
        if not self.enabled:
            return {"success": False, "error": "Better Stack disabled"}

        if not events:
            return {"success": True, "sent": 0}

        success_count = 0
        failed_count = 0

        for event in events:
            if await self.send_event(event):
                success_count += 1
            else:
                failed_count += 1

        result = {
            "success": success_count > 0,
            "sent": success_count,
            "failed": failed_count,
            "total": len(events)
        }

        if success_count > 0:
            print(f"📊 Better Stack batch: {success_count}/{len(events)} sent")

        return result

    def _format_log(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for Better Stack"""
        ai_analysis = event.get("ai_analysis", {})
        threat_score = ai_analysis.get("threat_score", 0)

        # Build message
        if threat_score > 0:
            message = (
                f"🚨 THREAT DETECTED [{threat_score}/100] "
                f"{event.get('event_type', 'Unknown')} on {event.get('hostname', 'unknown')} - "
                f"{ai_analysis.get('summary', 'Suspicious activity')}"
            )
        else:
            message = (
                f"{event.get('event_type', 'Unknown')} on {event.get('hostname', 'unknown')} - "
                f"User: {event.get('user', 'N/A')}"
            )

        # Build log entry
        log_entry = {
            "dt": datetime.now(timezone.utc).isoformat(),
            "message": message,
            "level": self._get_log_level(threat_score),
            "event_type": event.get("event_type"),
            "event_id": event.get("event_id"),
            "hostname": event.get("hostname"),
            "user": event.get("user"),
        }

        # Add AI analysis fields
        if ai_analysis:
            log_entry["threat_score"] = threat_score
            log_entry["threat_level"] = ai_analysis.get("threat_level", "unknown")
            log_entry["reasoning"] = ai_analysis.get("reasoning", "")

            if "indicators" in ai_analysis:
                log_entry["indicators"] = ", ".join(ai_analysis["indicators"])

        # Add optional fields
        if "command_line" in event:
            log_entry["command_line"] = event["command_line"]
        if "process_name" in event:
            log_entry["process_name"] = event["process_name"]

        return log_entry

    def _get_log_level(self, threat_score: int) -> str:
        """Determine log level based on threat score"""
        if threat_score >= 80:
            return "error"
        elif threat_score >= 60:
            return "warn"
        else:
            return "info"


# Global service instance
betterstack_service = BetterStackService()