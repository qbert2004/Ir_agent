"""
AI Analysis Models
Models for threat analysis results
"""
from pydantic import BaseModel, Field
from typing import Optional, List


class AIAnalysisResult(BaseModel):
    """AI analysis result"""
    threat_score: int = Field(..., ge=0, le=100, description="Threat score (0-100)")
    threat_level: str = Field(..., description="Threat level (low/medium/high/critical)")
    summary: str = Field(..., description="Brief summary of the threat")
    reasoning: str = Field(..., description="Detailed reasoning")
    indicators: list[str] = Field(default_factory=list, description="Threat indicators")
    recommended_actions: list[str] = Field(default_factory=list, description="Recommended actions")

    class Config:
        json_schema_extra = {
            "example": {
                "threat_score": 85,
                "threat_level": "high",
                "summary": "Suspicious PowerShell execution detected",
                "reasoning": "Base64 encoded command detected with hidden window",
                "indicators": [
                    "base64_encoding",
                    "hidden_window",
                    "suspicious_cmdline"
                ],
                "recommended_actions": [
                    "Investigate the user account",
                    "Check for lateral movement",
                    "Review related events"
                ]
            }
        }


class AnalysisRequest(BaseModel):
    """Request for AI analysis"""
    event_type: str
    event_id: str
    hostname: str
    user: str
    command_line: Optional[str] = None
    process_name: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "event_type": "ProcessCreation",
                "event_id": "4688",
                "hostname": "WIN-PC-01",
                "user": "admin",
                "command_line": "powershell -enc SGVsbG8=",
                "process_name": "powershell.exe"
            }
        }


class AnalysisResponse(BaseModel):
    """Response with analysis results"""
    status: str = "success"
    event: dict
    analysis: AIAnalysisResult
    timestamp: str