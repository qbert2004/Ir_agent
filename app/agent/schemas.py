"""Pydantic models for the agent system."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ThoughtAction(BaseModel):
    """Parsed thought and action from LLM output."""
    thought: str = ""
    action: Optional[str] = None
    action_input: Dict[str, str] = Field(default_factory=dict)
    final_answer: Optional[str] = None
    raw_output: str = ""


class AgentStep(BaseModel):
    """A single step in the agent's reasoning chain."""
    step_number: int
    thought: str = ""
    action: Optional[str] = None
    action_input: Dict[str, str] = Field(default_factory=dict)
    observation: Optional[str] = None
    is_final: bool = False


class AgentResponse(BaseModel):
    """Complete agent response including reasoning chain."""
    answer: str
    steps: List[AgentStep] = Field(default_factory=list)
    tools_used: List[str] = Field(default_factory=list)
    total_steps: int = 0
    session_id: str = ""


class AgentQueryRequest(BaseModel):
    """Request model for agent query endpoint."""
    query: str = Field(..., min_length=1, description="User question or task")
    session_id: Optional[str] = Field(None, description="Session ID for conversation continuity")


class AgentQueryResponse(BaseModel):
    """Response model for agent query endpoint."""
    answer: str
    session_id: str
    steps: List[AgentStep] = Field(default_factory=list)
    tools_used: List[str] = Field(default_factory=list)
    total_steps: int = 0


class ToolInfo(BaseModel):
    """Tool information for the tools listing endpoint."""
    name: str
    description: str
    parameters: str


class IngestRequest(BaseModel):
    """Request model for knowledge ingestion."""
    title: str = Field(..., description="Document title")
    content: str = Field(..., description="Document text content")
    source: str = Field("", description="Source identifier")


class KnowledgeStats(BaseModel):
    """Knowledge base statistics."""
    total_vectors: int = 0
    dimension: int = 384
    index_path: str = ""
    long_term_memories: int = 0
    active_sessions: int = 0
    events_in_store: int = 0
