"""Agent API endpoints."""

import uuid
from typing import List, Optional

from fastapi import APIRouter, HTTPException

from app.agent.schemas import (
    AgentQueryRequest,
    AgentQueryResponse,
    IngestRequest,
    KnowledgeStats,
    ToolInfo,
)

router = APIRouter(prefix="/agent", tags=["agent"])


def _get_service():
    """Lazy import to avoid circular imports and heavy init at import time."""
    from app.services.agent_service import agent_service
    return agent_service


@router.post("/query", response_model=AgentQueryResponse)
async def agent_query(request: AgentQueryRequest):
    """Send a query to the CyberAgent and get a reasoned answer.

    The agent uses ReAct reasoning with tools including knowledge search,
    MITRE ATT&CK lookup, IoC checking, ML anomaly detection, and more.
    """
    service = _get_service()

    session_id = request.session_id or uuid.uuid4().hex[:12]

    try:
        response = service.query(request.query, session_id)
        return AgentQueryResponse(
            answer=response.answer,
            session_id=response.session_id,
            steps=response.steps,
            tools_used=response.tools_used,
            total_steps=response.total_steps,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@router.get("/tools", response_model=List[ToolInfo])
async def list_tools():
    """List all available agent tools."""
    service = _get_service()
    tools = service.get_tools()
    return [ToolInfo(**t) for t in tools]


@router.get("/sessions/{session_id}/history")
async def get_session_history(session_id: str):
    """Get conversation history for a session."""
    service = _get_service()
    history = service.get_session_history(session_id)
    return {"session_id": session_id, "history": history}


@router.delete("/sessions/{session_id}")
async def clear_session(session_id: str):
    """Clear a session's memory."""
    service = _get_service()
    service.clear_session(session_id)
    return {"status": "cleared", "session_id": session_id}


@router.post("/ingest")
async def ingest_document(request: IngestRequest):
    """Ingest a knowledge document into the vector database."""
    service = _get_service()

    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty")

    chunks_added = service.ingest_document(
        title=request.title,
        content=request.content,
        source=request.source,
    )

    return {
        "status": "ingested",
        "title": request.title,
        "chunks_added": chunks_added,
    }


@router.get("/knowledge/stats", response_model=KnowledgeStats)
async def knowledge_stats():
    """Get knowledge base and memory statistics."""
    service = _get_service()
    stats = service.get_knowledge_stats()
    return KnowledgeStats(**stats)
