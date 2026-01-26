"""FAISS-based vector store with persistence."""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from app.agent.rag.embeddings import embedding_model


class VectorStore:
    """FAISS vector store with metadata and disk persistence."""

    def __init__(self, index_path: str, dimension: int = 384):
        self.index_path = Path(index_path)
        self.dimension = dimension
        self._index = None
        self._metadata: List[Dict] = []
        self._texts: List[str] = []
        self._load_or_create()

    def _load_or_create(self):
        """Load existing index from disk or create a new one."""
        import faiss

        index_file = self.index_path / "index.faiss"
        meta_file = self.index_path / "metadata.json"

        if index_file.exists() and meta_file.exists():
            self._index = faiss.read_index(str(index_file))
            with open(meta_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._metadata = data.get("metadata", [])
                self._texts = data.get("texts", [])
        else:
            self._index = faiss.IndexFlatIP(self.dimension)
            self._metadata = []
            self._texts = []

    def add(self, texts: List[str], metadatas: Optional[List[Dict]] = None) -> int:
        """Add texts to the vector store.

        Args:
            texts: List of text chunks to add.
            metadatas: Optional list of metadata dicts for each text.

        Returns:
            Number of vectors added.
        """
        if not texts:
            return 0

        embeddings = embedding_model.embed(texts)

        if metadatas is None:
            metadatas = [{} for _ in texts]

        self._index.add(embeddings)
        self._texts.extend(texts)
        self._metadata.extend(metadatas)

        return len(texts)

    def search(self, query: str, top_k: int = 5) -> List[Tuple[str, float, Dict]]:
        """Search for similar texts.

        Args:
            query: Query string.
            top_k: Number of results to return.

        Returns:
            List of (text, score, metadata) tuples, sorted by relevance.
        """
        if self._index.ntotal == 0:
            return []

        query_vector = embedding_model.embed_query(query)
        query_vector = np.array([query_vector], dtype=np.float32)

        k = min(top_k, self._index.ntotal)
        scores, indices = self._index.search(query_vector, k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue
            results.append((
                self._texts[idx],
                float(score),
                self._metadata[idx],
            ))

        return results

    def save(self):
        """Persist index and metadata to disk."""
        import faiss

        self.index_path.mkdir(parents=True, exist_ok=True)

        index_file = self.index_path / "index.faiss"
        meta_file = self.index_path / "metadata.json"

        faiss.write_index(self._index, str(index_file))

        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump({
                "metadata": self._metadata,
                "texts": self._texts,
            }, f, ensure_ascii=False)

    def clear(self):
        """Clear all data from the store."""
        import faiss

        self._index = faiss.IndexFlatIP(self.dimension)
        self._metadata = []
        self._texts = []

    @property
    def size(self) -> int:
        """Number of vectors in the store."""
        return self._index.ntotal

    def stats(self) -> Dict:
        """Return store statistics."""
        return {
            "total_vectors": self._index.ntotal,
            "dimension": self.dimension,
            "index_path": str(self.index_path),
        }
