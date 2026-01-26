"""Knowledge ingestion pipeline for processing documents into vector store."""

import os
from pathlib import Path
from typing import Dict, List

from app.agent.rag.chunker import chunker
from app.agent.rag.vector_store import VectorStore


class IngestionPipeline:
    """Ingest documents into a vector store."""

    SUPPORTED_EXTENSIONS = {".txt", ".md"}

    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store

    def ingest_text(self, title: str, content: str, source: str = "") -> int:
        """Ingest a single text document.

        Args:
            title: Document title.
            content: Full text content.
            source: Source identifier.

        Returns:
            Number of chunks added.
        """
        chunks = chunker.chunk_document(title, content, source)
        if not chunks:
            return 0

        texts = [c["text"] for c in chunks]
        metadatas = [c["metadata"] for c in chunks]

        added = self.vector_store.add(texts, metadatas)
        return added

    def ingest_file(self, file_path: str) -> int:
        """Ingest a single file.

        Args:
            file_path: Path to the file.

        Returns:
            Number of chunks added.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if path.suffix not in self.SUPPORTED_EXTENSIONS:
            raise ValueError(f"Unsupported file type: {path.suffix}")

        content = path.read_text(encoding="utf-8", errors="ignore")
        title = path.stem.replace("_", " ").replace("-", " ").title()

        return self.ingest_text(title, content, source=str(path))

    def ingest_directory(self, dir_path: str, recursive: bool = True) -> Dict:
        """Ingest all supported files from a directory.

        Args:
            dir_path: Directory path.
            recursive: Whether to recurse into subdirectories.

        Returns:
            Dict with ingestion stats.
        """
        path = Path(dir_path)
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path}")

        stats = {"files_processed": 0, "chunks_added": 0, "errors": []}

        pattern = "**/*" if recursive else "*"
        for file_path in path.glob(pattern):
            if not file_path.is_file():
                continue
            if file_path.suffix not in self.SUPPORTED_EXTENSIONS:
                continue

            try:
                added = self.ingest_file(str(file_path))
                stats["files_processed"] += 1
                stats["chunks_added"] += added
            except Exception as e:
                stats["errors"].append({"file": str(file_path), "error": str(e)})

        self.vector_store.save()
        return stats

    def ingest_entries(self, entries: List[Dict]) -> int:
        """Ingest pre-structured entries.

        Args:
            entries: List of dicts with 'title', 'content', and optional 'source'.

        Returns:
            Total chunks added.
        """
        total = 0
        for entry in entries:
            title = entry.get("title", "Untitled")
            content = entry.get("content", "")
            source = entry.get("source", "")
            total += self.ingest_text(title, content, source)

        self.vector_store.save()
        return total
