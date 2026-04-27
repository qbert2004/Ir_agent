"""
Persistent Event Store — заменяет in-memory list в AgentService и IncidentManager.

Предоставляет:
    - async сохранение событий в БД
    - запрос событий по hostname / time range / incident_id
    - forensic replay (все события сохраняются, не теряются при рестарте)
    - совместимость с прежним API (to_dict() → dict)
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import SecurityEvent, Incident, IoC

logger = logging.getLogger("ir-agent")


# ── Event Store ───────────────────────────────────────────────────────────────

class EventStore:
    """
    Async-safe persistent event store.

    Полностью заменяет self._event_store: list в AgentService.
    Поддерживает cap через LIFO-очередь (newest-first queries).
    """

    async def save_event(
        self,
        event: Dict[str, Any],
        ml_confidence: float = 0.0,
        ml_label: str = "",
        ml_reason: str = "",
        processing_path: str = "",
        incident_id: Optional[str] = None,
        threat_score: Optional[float] = None,
        threat_severity: Optional[str] = None,
        assessment_json: Optional[str] = None,
    ) -> str:
        """Persist a raw event. Returns event DB id."""
        async with get_db() as session:
            db_event = SecurityEvent(
                id=uuid.uuid4().hex,
                timestamp=str(event.get("timestamp", "")),
                event_id=str(event.get("event_id", "")),
                event_type=event.get("event_type", ""),
                hostname=event.get("hostname", event.get("host", "")),
                user=event.get("user", ""),
                channel=event.get("channel", ""),
                process_name=event.get("process_name", ""),
                process_id=event.get("process_id"),
                command_line=event.get("command_line", ""),
                parent_process=event.get("parent_process", event.get("parent_image", "")),
                source_ip=event.get("source_ip", ""),
                destination_ip=event.get("destination_ip", ""),
                destination_port=event.get("destination_port"),
                script_block_text=event.get("script_block_text", ""),
                ml_confidence=ml_confidence,
                ml_label=ml_label,
                ml_reason=ml_reason,
                processing_path=processing_path,
                incident_id=incident_id,
                threat_score=threat_score,
                threat_severity=threat_severity,
                assessment_json=assessment_json,
            )
            session.add(db_event)
        return db_event.id

    async def get_recent(self, limit: int = 500) -> List[Dict[str, Any]]:
        """Return most recent events as dicts (newest first)."""
        async with get_db() as session:
            result = await session.execute(
                select(SecurityEvent)
                .order_by(desc(SecurityEvent.received_at))
                .limit(limit)
            )
            return [row.to_dict() for row in result.scalars().all()]

    async def get_by_hostname(
        self, hostname: str, limit: int = 200
    ) -> List[Dict[str, Any]]:
        """Return events for a specific host."""
        async with get_db() as session:
            result = await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.hostname == hostname)
                .order_by(desc(SecurityEvent.received_at))
                .limit(limit)
            )
            return [row.to_dict() for row in result.scalars().all()]

    async def get_by_incident(self, incident_id: str) -> List[Dict[str, Any]]:
        """Return all events linked to an incident (chronological order)."""
        async with get_db() as session:
            result = await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.incident_id == incident_id)
                .order_by(SecurityEvent.timestamp)
            )
            return [row.to_dict() for row in result.scalars().all()]

    async def count(self) -> int:
        """Total stored events."""
        from sqlalchemy import func
        async with get_db() as session:
            result = await session.execute(
                select(func.count()).select_from(SecurityEvent)
            )
            return result.scalar() or 0

    async def link_to_incident(
        self, event_ids: List[str], incident_id: str
    ) -> None:
        """Bulk-link events to an incident."""
        from sqlalchemy import update
        async with get_db() as session:
            await session.execute(
                update(SecurityEvent)
                .where(SecurityEvent.id.in_(event_ids))
                .values(incident_id=incident_id)
            )


# ── Incident Repository ────────────────────────────────────────────────────────

class IncidentRepository:
    """
    CRUD для Incident + IoC.

    Заменяет self._incidents: Dict в IncidentManager.
    """

    async def save_incident(self, incident_data: Dict[str, Any]) -> str:
        """Create or update an incident. Returns incident id."""
        async with get_db() as session:
            existing = await session.get(Incident, incident_data["id"])
            if existing:
                self._apply_update(existing, incident_data)
            else:
                _assessment = incident_data.get("assessment")
                _agent = incident_data.get("agent_analysis")
                incident = Incident(
                    id=incident_data["id"],
                    host=incident_data.get("host", ""),
                    status=incident_data.get("status", "open"),
                    severity=incident_data.get("severity", "info"),
                    confidence=incident_data.get("confidence", 0.0),
                    classification=incident_data.get("classification", ""),
                    root_cause=incident_data.get("root_cause", ""),
                    impact_assessment=incident_data.get("impact_assessment", ""),
                    timeline_json=json.dumps(incident_data.get("timeline", [])),
                    mitre_techniques_json=json.dumps(incident_data.get("mitre_techniques", [])),
                    key_findings_json=json.dumps(incident_data.get("key_findings", [])),
                    recommendations_json=json.dumps(incident_data.get("recommendations", [])),
                    affected_hosts_json=json.dumps(incident_data.get("affected_hosts", [])),
                    affected_users_json=json.dumps(incident_data.get("affected_users", [])),
                    threat_score=incident_data.get("threat_score"),
                    assessment_json=json.dumps(_assessment) if _assessment else None,
                    agent_analysis_json=json.dumps(_agent) if _agent else None,
                    incident_summary=incident_data.get("incident_summary", ""),
                )
                session.add(incident)
        return incident_data["id"]

    def _apply_update(self, existing: Incident, data: Dict[str, Any]) -> None:
        """Apply updates to existing Incident ORM object."""
        for field in ("status", "severity", "classification", "root_cause",
                      "impact_assessment", "incident_summary"):
            if field in data:
                setattr(existing, field, data[field])

        for field, key in [
            ("timeline_json", "timeline"),
            ("mitre_techniques_json", "mitre_techniques"),
            ("key_findings_json", "key_findings"),
            ("recommendations_json", "recommendations"),
            ("affected_hosts_json", "affected_hosts"),
            ("affected_users_json", "affected_users"),
        ]:
            if key in data:
                setattr(existing, field, json.dumps(data[key]))

        if "confidence" in data:
            existing.confidence = data["confidence"]

        if "threat_score" in data:
            existing.threat_score = data["threat_score"]

        if "assessment" in data and data["assessment"] is not None:
            existing.assessment_json = json.dumps(data["assessment"])

        if "agent_analysis" in data and data["agent_analysis"] is not None:
            existing.agent_analysis_json = json.dumps(data["agent_analysis"])

    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetch incident by ID."""
        async with get_db() as session:
            incident = await session.get(Incident, incident_id)
            return incident.to_dict() if incident else None

    async def list_incidents(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List incidents, optionally filtered by status."""
        async with get_db() as session:
            q = select(Incident).order_by(desc(Incident.created_at)).limit(limit)
            if status:
                q = q.where(Incident.status == status)
            result = await session.execute(q)
            return [row.to_dict() for row in result.scalars().all()]

    async def update_status(self, incident_id: str, status: str) -> None:
        """Update incident status."""
        from sqlalchemy import update as sa_update
        async with get_db() as session:
            await session.execute(
                sa_update(Incident)
                .where(Incident.id == incident_id)
                .values(status=status, updated_at=datetime.now(timezone.utc))
            )

    async def save_iocs(self, incident_id: str, iocs: List[Dict[str, Any]]) -> int:
        """Bulk-save IoCs for an incident. Returns count saved."""
        async with get_db() as session:
            count = 0
            for ioc_data in iocs:
                ioc = IoC(
                    id=uuid.uuid4().hex,
                    incident_id=incident_id,
                    ioc_type=ioc_data.get("type", "unknown"),
                    value=ioc_data.get("value", ""),
                    context=ioc_data.get("context", ""),
                    confidence=ioc_data.get("confidence", 0.5),
                )
                session.add(ioc)
                count += 1
        return count

    async def get_iocs(
        self,
        incident_id: Optional[str] = None,
        ioc_type: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Query IoCs with optional filters."""
        async with get_db() as session:
            q = select(IoC).limit(limit)
            if incident_id:
                q = q.where(IoC.incident_id == incident_id)
            if ioc_type:
                q = q.where(IoC.ioc_type == ioc_type)
            result = await session.execute(q)
            return [row.to_dict() for row in result.scalars().all()]


# ── Singletons ────────────────────────────────────────────────────────────────

event_store = EventStore()
incident_repo = IncidentRepository()
