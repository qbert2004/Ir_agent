"""
Telemetry Models
Pydantic models for telemetry events
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class TelemetryEventCreate(BaseModel):
    """Event creation model"""
    event_type: str = Field(..., description="Type of event (e.g., ProcessCreation, Logon)")
    event_id: str = Field(..., description="Event ID (e.g., 4688, 4624)")
    hostname: str = Field(..., description="Hostname where event occurred")
    user: Optional[str] = Field(None, description="User associated with event")
    timestamp: Optional[str] = Field(None, description="Event timestamp (ISO 8601)")

    # Process-related fields
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None

    # Network-related fields
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

    # PowerShell fields
    script_block_text: Optional[str] = None
    script_block_id: Optional[str] = None

    # Additional metadata
    platform: Optional[str] = Field("Windows", description="Platform (Windows, Linux, etc.)")
    source_type: Optional[str] = Field("windows_event_log", description="Source type")
    channel: Optional[str] = None
    severity: Optional[str] = None


class TelemetryEventRead(TelemetryEventCreate):
    """Event read model (includes AI analysis)"""
    ai_analysis: Optional[Dict[str, Any]] = None


class TelemetryBatch(BaseModel):
    """Batch of telemetry events"""
    events: List[TelemetryEventCreate]