"""Long-term memory: FAISS-backed persistent memory for past investigations."""

from datetime import datetime
from typing import Dict, List

from app.agent.rag.vector_store import VectorStore


class LongTermMemory:
    """Persistent memory using FAISS for past investigations and findings."""

    def __init__(self, index_path: str = "vector_db/investigations_index"):
        self._store = VectorStore(index_path=index_path)

    def store(self, content: str, metadata: Dict = None):
        """Store a memory entry.

        Args:
            content: Text content to remember.
            metadata: Additional context (session_id, timestamp, etc.).
        """
        if metadata is None:
            metadata = {}

        metadata.setdefault("timestamp", datetime.utcnow().isoformat())
        metadata.setdefault("type", "investigation")

        self._store.add([content], [metadata])

    def recall(self, query: str, top_k: int = 3) -> List[Dict]:
        """Recall relevant past memories.

        Args:
            query: Query to search for related memories.
            top_k: Number of results.

        Returns:
            List of dicts with 'content', 'score', 'metadata'.
        """
        results = self._store.search(query, top_k=top_k)

        memories = []
        for text, score, metadata in results:
            if score < 0.25:
                continue
            memories.append({
                "content": text,
                "score": round(score, 4),
                "metadata": metadata,
            })

        return memories

    def recall_formatted(self, query: str, top_k: int = 3) -> str:
        """Recall and format as context string."""
        memories = self.recall(query, top_k)

        if not memories:
            return ""

        lines = ["Relevant past investigations/findings:"]
        for i, mem in enumerate(memories, 1):
            ts = mem["metadata"].get("timestamp", "?")
            lines.append(f"[{i}] (score={mem['score']}, time={ts})")
            lines.append(f"  {mem['content'][:300]}")

        return "\n".join(lines)

    def save(self):
        """Persist memory to disk."""
        self._store.save()

    @property
    def size(self) -> int:
        return self._store.size
