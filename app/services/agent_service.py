"""Singleton agent service that initializes and manages the CyberAgent."""

import logging
from typing import Optional

from app.agent.core.agent import CyberAgent
from app.agent.memory.memory_manager import MemoryManager
from app.agent.rag.retriever import Retriever
from app.agent.rag.vector_store import VectorStore
from app.agent.rag.ingestion import IngestionPipeline
from app.agent.tools.base import ToolRegistry
from app.agent.tools.knowledge_search import KnowledgeSearchTool
from app.agent.tools.search_logs import SearchLogsTool
from app.agent.tools.classify_event import ClassifyEventTool
from app.agent.tools.analyze_event import AnalyzeEventTool
from app.agent.tools.mitre_lookup import MitreLookupTool
from app.agent.tools.lookup_ioc import LookupIoCTool
from app.agent.tools.query_siem import QuerySIEMTool
from app.agent.tools.investigate import InvestigateTool
from app.agent.tools.ml_classify import MLClassifyTool
from app.agent.schemas import AgentResponse

logger = logging.getLogger(__name__)

KNOWLEDGE_INDEX_PATH = "vector_db/knowledge_index"


class AgentService:
    """Singleton service managing the CyberAgent lifecycle."""

    _instance: Optional["AgentService"] = None

    def __new__(cls) -> "AgentService":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._agent: Optional[CyberAgent] = None
        self._memory: Optional[MemoryManager] = None
        self._knowledge_store: Optional[VectorStore] = None
        self._ingestion: Optional[IngestionPipeline] = None
        self._tool_registry: Optional[ToolRegistry] = None
        self._event_store: list = []
        self._setup()

    def _setup(self):
        """Initialize all agent components."""
        logger.info("Initializing AgentService...")

        # Knowledge vector store
        self._knowledge_store = VectorStore(index_path=KNOWLEDGE_INDEX_PATH)
        retriever = Retriever(self._knowledge_store)

        # Ingestion pipeline
        self._ingestion = IngestionPipeline(self._knowledge_store)

        # Memory manager
        self._memory = MemoryManager()

        # Tool registry
        self._tool_registry = ToolRegistry()
        self._tool_registry.register(KnowledgeSearchTool(retriever))
        self._tool_registry.register(SearchLogsTool(self._event_store))
        self._tool_registry.register(ClassifyEventTool())
        self._tool_registry.register(AnalyzeEventTool())
        self._tool_registry.register(MitreLookupTool())
        self._tool_registry.register(LookupIoCTool())
        self._tool_registry.register(QuerySIEMTool())
        self._tool_registry.register(InvestigateTool())
        self._tool_registry.register(MLClassifyTool())  # ML Engine as a ReAct tool

        # Agent
        self._agent = CyberAgent(self._tool_registry, self._memory)
        logger.info(f"AgentService initialized with {len(self._tool_registry.list_tools())} tools")

    def query(self, query: str, session_id: str = None) -> AgentResponse:
        """Synchronous query (kept for backwards-compatibility and tests)."""
        return self._agent.run(query, session_id)

    async def aquery(self, query: str, session_id: str = None) -> AgentResponse:
        """Async query — non-blocking, safe to call from FastAPI handlers."""
        return await self._agent.arun(query, session_id)

    def ingest_document(self, title: str, content: str, source: str = "") -> int:
        """Ingest a document into the knowledge base.

        Returns:
            Number of chunks added.
        """
        added = self._ingestion.ingest_text(title, content, source)
        self._knowledge_store.save()
        return added

    def add_event(self, event: dict):
        """Add an event to the in-memory event store for log search."""
        self._event_store.append(event)
        # Keep max 10000 events in memory
        if len(self._event_store) > 10000:
            self._event_store.pop(0)

    def get_tools(self) -> list:
        """List all available tools."""
        return [tool.get_schema() for tool in self._tool_registry.list_tools()]

    def get_session_history(self, session_id: str) -> list:
        """Get conversation history for a session."""
        return self._memory.get_session_history(session_id)

    def clear_session(self, session_id: str):
        """Clear a session's memory."""
        self._memory.clear_session(session_id)

    def get_knowledge_stats(self) -> dict:
        """Get knowledge base statistics."""
        stats = self._knowledge_store.stats()
        stats["long_term_memories"] = self._memory.long_term_size
        stats["active_sessions"] = self._memory.active_sessions
        stats["events_in_store"] = len(self._event_store)
        return stats

    def save(self):
        """Persist all state to disk."""
        self._knowledge_store.save()
        self._memory.save()


agent_service = AgentService()
