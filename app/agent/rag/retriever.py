"""Semantic search interface over the vector store."""

from typing import Dict, List

from app.agent.rag.vector_store import VectorStore


class Retriever:
    """Semantic retriever that searches a VectorStore and formats results."""

    def __init__(self, vector_store: VectorStore, top_k: int = 5, score_threshold: float = 0.3):
        self.vector_store = vector_store
        self.top_k = top_k
        self.score_threshold = score_threshold

    def retrieve(self, query: str, top_k: int = None) -> List[Dict]:
        """Retrieve relevant documents for a query.

        Args:
            query: User query string.
            top_k: Override default number of results.

        Returns:
            List of dicts with 'text', 'score', 'metadata' keys.
        """
        k = top_k or self.top_k
        raw_results = self.vector_store.search(query, top_k=k)

        results = []
        for text, score, metadata in raw_results:
            if score < self.score_threshold:
                continue
            results.append({
                "text": text,
                "score": round(score, 4),
                "metadata": metadata,
            })

        return results

    def retrieve_formatted(self, query: str, top_k: int = None, max_chars: int = 2000) -> str:
        """Retrieve and format as a single context string.

        Args:
            query: User query.
            top_k: Number of results.
            max_chars: Max total characters in output.

        Returns:
            Formatted string with numbered results.
        """
        results = self.retrieve(query, top_k)

        if not results:
            return "No relevant knowledge found."

        parts = []
        total_chars = 0

        for i, r in enumerate(results, 1):
            source = r["metadata"].get("source", "unknown")
            title = r["metadata"].get("title", "")
            entry = f"[{i}] (score={r['score']}, source={source})\n"
            if title:
                entry += f"Title: {title}\n"
            entry += r["text"]

            if total_chars + len(entry) > max_chars:
                remaining = max_chars - total_chars
                if remaining > 100:
                    parts.append(entry[:remaining] + "...")
                break

            parts.append(entry)
            total_chars += len(entry)

        return "\n\n".join(parts)
