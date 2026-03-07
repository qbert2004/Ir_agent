"""Singleton wrapper for sentence-transformers embedding model."""

import numpy as np
from typing import List, Optional
import threading


class EmbeddingModel:
    """Singleton embedding model using sentence-transformers (all-MiniLM-L6-v2)."""

    _instance: Optional["EmbeddingModel"] = None
    _lock = threading.Lock()

    MODEL_NAME = "all-MiniLM-L6-v2"
    EMBEDDING_DIM = 384

    def __new__(cls) -> "EmbeddingModel":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._model = None
        self._initialized = True

    def _load_model(self):
        """Lazy-load the model on first use (thread-safe).

        Uses double-checked locking so that:
          1. Once the model is loaded the fast-path (no lock) is taken on every
             subsequent call.
          2. If two threads race on the very first call, only one loads the
             model — the second waits on the lock and then skips loading because
             self._model is already set.
        """
        if self._model is not None:
            return  # fast path — no lock overhead after first load
        with self.__class__._lock:
            if self._model is None:  # double-checked: re-test inside the lock
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(self.MODEL_NAME)

    def embed(self, texts: List[str]) -> np.ndarray:
        """Embed a list of texts into vectors.

        Args:
            texts: List of text strings to embed.

        Returns:
            numpy array of shape (len(texts), EMBEDDING_DIM).
        """
        self._load_model()
        embeddings = self._model.encode(
            texts,
            show_progress_bar=False,
            normalize_embeddings=True,
            batch_size=32,
        )
        return np.array(embeddings, dtype=np.float32)

    def embed_query(self, query: str) -> np.ndarray:
        """Embed a single query string.

        Args:
            query: Query text to embed.

        Returns:
            numpy array of shape (EMBEDDING_DIM,).
        """
        result = self.embed([query])
        return result[0]

    @property
    def dimension(self) -> int:
        return self.EMBEDDING_DIM


embedding_model = EmbeddingModel()
