"""Singleton agent service that initializes and manages the CyberAgent."""

import asyncio
import logging
import queue
from collections import deque
from typing import AsyncIterator, Optional

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
from app.agent.tools.get_incident import GetIncidentTool
from app.agent.tools.get_incident_events import GetIncidentEventsTool
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
        # deque with a fixed maxlen gives O(1) append *and* automatic LRU eviction,
        # unlike a plain list where pop(0) costs O(n) per event when over the cap.
        self._event_store: deque = deque(maxlen=10_000)
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

        # Incident-level tools: give the agent access to full correlated incident data
        from app.services.incident_manager import get_incident_manager
        _im = get_incident_manager()
        self._tool_registry.register(GetIncidentTool(_im))
        self._tool_registry.register(GetIncidentEventsTool(_im))

        # Agent
        self._agent = CyberAgent(self._tool_registry, self._memory)
        logger.info(f"AgentService initialized with {len(self._tool_registry.list_tools())} tools")

    def query(self, query: str, session_id: str = None) -> AgentResponse:
        """Synchronous query (kept for backwards-compatibility and tests)."""
        return self._agent.run(query, session_id)

    async def aquery(self, query: str, session_id: str = None) -> AgentResponse:
        """Async query — non-blocking, safe to call from FastAPI handlers."""
        return await self._agent.arun(query, session_id)

    async def astream(self, query: str, session_id: str = None) -> AsyncIterator[dict]:
        """True streaming query — yields each ReAct step as it completes.

        The agent's synchronous run_streaming() generator is executed in a
        thread-pool worker so the event loop stays responsive.  Steps are
        passed back to the async caller via a thread-safe queue so the client
        starts receiving JSON events before the ReAct loop finishes.
        """
        step_queue: queue.Queue = queue.Queue()
        loop = asyncio.get_event_loop()

        def _run_in_thread():
            try:
                for step_dict in self._agent.run_streaming(query, session_id):
                    step_queue.put(("step", step_dict))
                step_queue.put(("done", None))
            except Exception as exc:
                step_queue.put(("error", str(exc)))

        future = loop.run_in_executor(None, _run_in_thread)

        while True:
            kind, data = await loop.run_in_executor(None, step_queue.get)
            if kind == "done":
                break
            elif kind == "error":
                yield {"type": "error", "error": data}
                break
            else:
                yield data

        await future

    def ingest_document(self, title: str, content: str, source: str = "") -> int:
        """Ingest a document into the knowledge base.

        Returns:
            Number of chunks added.
        """
        added = self._ingestion.ingest_text(title, content, source)
        self._knowledge_store.save()
        return added

    def add_event(self, event: dict):
        """Add an event to the in-memory event store for log search.

        The deque has maxlen=10_000 so Python automatically discards the oldest
        entry when the store is full — no explicit eviction code needed.
        """
        self._event_store.append(event)

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
