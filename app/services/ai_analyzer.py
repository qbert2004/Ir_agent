"""
AI Analyzer Service
Uses Groq AI to analyze security events
"""
import json
from typing import Dict, Any, List
from groq import AsyncGroq
from app.core.config import settings
import os
from dotenv import load_dotenv
load_dotenv()
class AIAnalyzer:
    """AI-powered security event analyzer"""

    def __init__(self):
        self.client = None
        self.enabled = False
        self.model = settings.ai_model
        self.threshold = settings.ai_threat_threshold

        if settings.ai_enabled:
            self.client = AsyncGroq(api_key=settings.groq_api_key)
            self.enabled = True
            print(f"OK AI Analyzer: Enabled ({settings.ai_provider}/{settings.ai_model})")
        else:
            print("WARNING  AI Analyzer: Disabled (no API key)")

    async def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a security event for threats"""
        if not self.enabled:
            return self._default_analysis()

        try:
            # Create analysis prompt
            prompt = self._build_prompt(event)

            # Call Groq API
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing Windows security events. Provide threat assessment in JSON format."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1024,
                response_format={"type": "json_object"}
            )

            # Parse response
            result = json.loads(response.choices[0].message.content)

            # Normalize result
            return self._normalize_result(result)

        except Exception as e:
            print(f"ERROR AI Analysis error: {e}")
            return self._default_analysis()

    def _build_prompt(self, event: Dict[str, Any]) -> str:
        """Build analysis prompt from event"""
        event_type = event.get("event_type", "Unknown")
        event_id = event.get("event_id", "Unknown")
        hostname = event.get("hostname", "Unknown")
        user = event.get("user", "Unknown")
        command_line = event.get("command_line", "N/A")
        process_name = event.get("process_name", "N/A")

        prompt = f"""Analyze this Windows security event for potential threats:

Event Type: {event_type}
Event ID: {event_id}
Hostname: {hostname}
User: {user}
Process: {process_name}
Command Line: {command_line}

Provide a JSON response with this structure:
{{
  "threat_score": <0-100>,
  "threat_level": "<low|medium|high|critical>",
  "summary": "<brief summary>",
  "reasoning": "<detailed reasoning>",
  "indicators": ["<indicator1>", "<indicator2>"],
  "recommended_actions": ["<action1>", "<action2>"]
}}

Focus on:
- Suspicious command-line arguments (base64, encoded, obfuscated)
- Known attack patterns (mimikatz, PowerShell abuse, lateral movement)
- Unusual user/process combinations
- Privilege escalation attempts"""

        return prompt

    def _normalize_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize AI response to standard format"""
        return {
            "threat_score": int(result.get("threat_score", 0)),
            "threat_level": result.get("threat_level", "low"),
            "summary": result.get("summary", "No threat detected"),
            "reasoning": result.get("reasoning", ""),
            "indicators": result.get("indicators", []),
            "recommended_actions": result.get("recommended_actions", [])
        }

    def _default_analysis(self) -> Dict[str, Any]:
        """Default analysis when AI is disabled"""
        return {
            "threat_score": 0,
            "threat_level": "unknown",
            "summary": "AI analysis not available",
            "reasoning": "AI analyzer is disabled or unavailable",
            "indicators": [],
            "recommended_actions": []
        }


# Global analyzer instance
ai_analyzer = AIAnalyzer()