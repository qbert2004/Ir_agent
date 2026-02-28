"""Agent API endpoints."""

import json
import uuid
from typing import AsyncIterator, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

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
    """Send a query to the CyberAgent (non-streaming, waits for full answer).

    The agent uses ReAct reasoning with tools including knowledge search,
    MITRE ATT&CK lookup, IoC checking, ML anomaly detection, and more.
    """
    service = _get_service()
    session_id = request.session_id or uuid.uuid4().hex[:12]

    try:
        response = await service.aquery(request.query, session_id)
        return AgentQueryResponse(
            answer=response.answer,
            session_id=response.session_id,
            steps=response.steps,
            tools_used=response.tools_used,
            total_steps=response.total_steps,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@router.post("/query/stream")
async def agent_query_stream(request: AgentQueryRequest):
    """
    Streaming agent query — returns NDJSON (newline-delimited JSON) events.

    Each line is a JSON object:
        {"type": "step",   "step": 1, "thought": "...", "action": "...", "observation": "..."}
        {"type": "answer", "answer": "...", "tools_used": [...], "total_steps": N}
        {"type": "error",  "error": "..."}

    Suitable for progressive UI updates during long investigations.
    """
    service = _get_service()
    session_id = request.session_id or uuid.uuid4().hex[:12]

    async def _stream() -> AsyncIterator[str]:
        try:
            # Run agent in thread pool (ReAct loop is synchronous)
            import asyncio
            response = await service.aquery(request.query, session_id)

            # Emit each reasoning step
            for step in (response.steps or []):
                yield json.dumps({
                    "type": "step",
                    "step": getattr(step, "step_number", 0),
                    "thought": getattr(step, "thought", ""),
                    "action": getattr(step, "action", ""),
                    "observation": str(getattr(step, "observation", ""))[:500],
                }) + "\n"

            # Emit final answer
            yield json.dumps({
                "type": "answer",
                "answer": response.answer,
                "tools_used": response.tools_used,
                "total_steps": response.total_steps,
                "session_id": response.session_id,
            }) + "\n"

        except Exception as e:
            yield json.dumps({"type": "error", "error": str(e)}) + "\n"

    return StreamingResponse(
        _stream(),
        media_type="application/x-ndjson",
        headers={"X-Session-ID": session_id},
    )


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
