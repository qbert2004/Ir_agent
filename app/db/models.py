"""
SQLAlchemy ORM models for IR-Agent persistence.

Таблицы:
    events      — сырые телеметрические события
    incidents   — скоррелированные инциденты
    iocs        — индикаторы компрометации (привязаны к инциденту)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


def _uuid() -> str:
    return uuid.uuid4().hex


# ── SecurityEvent ─────────────────────────────────────────────────────────────

class SecurityEvent(Base):
    """Raw telemetry event from an endpoint/SIEM."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    # Core event fields
    timestamp: Mapped[Optional[str]] = mapped_column(String(64))
    event_id: Mapped[Optional[str]] = mapped_column(String(16), index=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(64))
    hostname: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    user: Mapped[Optional[str]] = mapped_column(String(128))
    channel: Mapped[Optional[str]] = mapped_column(String(64))

    # Process
    process_name: Mapped[Optional[str]] = mapped_column(String(256))
    process_id: Mapped[Optional[int]] = mapped_column(Integer)
    command_line: Mapped[Optional[str]] = mapped_column(Text)
    parent_process: Mapped[Optional[str]] = mapped_column(String(256))

    # Network
    source_ip: Mapped[Optional[str]] = mapped_column(String(64))
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64))
    destination_port: Mapped[Optional[int]] = mapped_column(Integer)

    # PowerShell
    script_block_text: Mapped[Optional[str]] = mapped_column(Text)

    # ML classification
    ml_confidence: Mapped[Optional[float]] = mapped_column(Float)
    ml_label: Mapped[Optional[str]] = mapped_column(String(32))  # malicious / benign
    ml_reason: Mapped[Optional[str]] = mapped_column(String(512))
    processing_path: Mapped[Optional[str]] = mapped_column(String(16))  # fast / deep / filtered

    # ThreatAssessment Engine results
    threat_score: Mapped[Optional[float]] = mapped_column(Float, index=True)
    threat_severity: Mapped[Optional[str]] = mapped_column(String(16), index=True)  # critical/high/medium/low/info
    assessment_json: Mapped[Optional[str]] = mapped_column(Text)  # full ThreatAssessment.to_dict() JSON

    # Correlation
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(32), ForeignKey("incidents.id", ondelete="SET NULL"), index=True, nullable=True
    )

    incident: Mapped[Optional["Incident"]] = relationship(
        "Incident", back_populates="events", foreign_keys=[incident_id]
    )

    __table_args__ = (
        Index("ix_events_hostname_ts", "hostname", "timestamp"),
        Index("ix_events_incident", "incident_id"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "hostname": self.hostname,
            "user": self.user,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "ml_confidence": self.ml_confidence,
            "ml_label": self.ml_label,
            "ml_reason": self.ml_reason,
            "processing_path": self.processing_path,
            "threat_score": self.threat_score,
            "threat_severity": self.threat_severity,
            "incident_id": self.incident_id,
        }


# ── Incident ──────────────────────────────────────────────────────────────────

class Incident(Base):
    """Correlated security incident."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Core
    host: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    classification: Mapped[Optional[str]] = mapped_column(String(256))

    # ThreatAssessment Engine (агрегированная оценка инцидента)
    threat_score: Mapped[Optional[float]] = mapped_column(Float, index=True)
    assessment_json: Mapped[Optional[str]] = mapped_column(Text)  # ThreatAssessment.to_dict() JSON

    # Investigation results (JSON stored as text)
    timeline_json: Mapped[Optional[str]] = mapped_column(Text)
    mitre_techniques_json: Mapped[Optional[str]] = mapped_column(Text)
    key_findings_json: Mapped[Optional[str]] = mapped_column(Text)
    recommendations_json: Mapped[Optional[str]] = mapped_column(Text)
    affected_hosts_json: Mapped[Optional[str]] = mapped_column(Text)
    affected_users_json: Mapped[Optional[str]] = mapped_column(Text)

    root_cause: Mapped[Optional[str]] = mapped_column(Text)
    impact_assessment: Mapped[Optional[str]] = mapped_column(Text)

    # Agent investigation results
    agent_analysis_json: Mapped[Optional[str]] = mapped_column(Text)  # AgentAnalysis dict JSON
    incident_summary: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    events: Mapped[list["SecurityEvent"]] = relationship(
        "SecurityEvent",
        back_populates="incident",
        foreign_keys="SecurityEvent.incident_id",
        lazy="select",
    )
    iocs: Mapped[list["IoC"]] = relationship(
        "IoC", back_populates="incident", cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        import json
        return {
            "id": self.id,
            "host": self.host,
            "status": self.status,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "classification": self.classification,
            "event_count": len(self.events),
            "ioc_count": len(self.iocs),
            "timeline": json.loads(self.timeline_json) if self.timeline_json else [],
            "mitre_techniques": json.loads(self.mitre_techniques_json) if self.mitre_techniques_json else [],
            "key_findings": json.loads(self.key_findings_json) if self.key_findings_json else [],
            "recommendations": json.loads(self.recommendations_json) if self.recommendations_json else [],
            "affected_hosts": json.loads(self.affected_hosts_json) if self.affected_hosts_json else [],
            "affected_users": json.loads(self.affected_users_json) if self.affected_users_json else [],
            "root_cause": self.root_cause,
            "impact_assessment": self.impact_assessment,
            "threat_score": self.threat_score,
            "assessment": json.loads(self.assessment_json) if self.assessment_json else None,
            "agent_analysis": json.loads(self.agent_analysis_json) if self.agent_analysis_json else None,
            "incident_summary": self.incident_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ── IoC ───────────────────────────────────────────────────────────────────────

class IoC(Base):
    """Indicator of Compromise linked to an incident."""

    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    ioc_type: Mapped[str] = mapped_column(String(32), index=True)  # ip/domain/hash/url/process
    value: Mapped[str] = mapped_column(String(512), index=True)
    context: Mapped[Optional[str]] = mapped_column(String(256))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)

    # Threat intel enrichment (filled by async lookup)
    vt_score: Mapped[Optional[str]] = mapped_column(String(16))    # e.g. "45/72"
    abuse_score: Mapped[Optional[int]] = mapped_column(Integer)    # AbuseIPDB 0-100
    ti_tags: Mapped[Optional[str]] = mapped_column(String(512))    # JSON list of tags
    ti_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    incident: Mapped["Incident"] = relationship("Incident", back_populates="iocs")

    __table_args__ = (
        Index("ix_iocs_type_value", "ioc_type", "value"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "type": self.ioc_type,
            "value": self.value,
            "context": self.context,
            "confidence": self.confidence,
            "is_malicious": self.is_malicious,
            "vt_score": self.vt_score,
            "abuse_score": self.abuse_score,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
        }
