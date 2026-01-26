"""Document chunking with overlap for RAG ingestion."""

from typing import Dict, List


class TextChunker:
    """Split text into overlapping chunks for embedding."""

    def __init__(self, chunk_size: int = 512, overlap: int = 64):
        self.chunk_size = chunk_size
        self.overlap = overlap

    def chunk_text(self, text: str, metadata: Dict = None) -> List[Dict]:
        """Split text into chunks with metadata.

        Args:
            text: Full text to chunk.
            metadata: Base metadata to attach to each chunk.

        Returns:
            List of dicts with 'text' and 'metadata' keys.
        """
        if metadata is None:
            metadata = {}

        text = text.strip()
        if not text:
            return []

        chunks = []
        start = 0
        chunk_idx = 0

        while start < len(text):
            end = start + self.chunk_size

            # Try to break at sentence/paragraph boundary
            if end < len(text):
                # Look for paragraph break first
                break_pos = text.rfind("\n\n", start, end)
                if break_pos == -1 or break_pos <= start:
                    # Look for sentence break
                    break_pos = text.rfind(". ", start, end)
                if break_pos == -1 or break_pos <= start:
                    # Look for any newline
                    break_pos = text.rfind("\n", start, end)
                if break_pos > start:
                    end = break_pos + 1

            chunk_text = text[start:end].strip()
            if chunk_text:
                chunk_meta = {
                    **metadata,
                    "chunk_index": chunk_idx,
                    "char_start": start,
                    "char_end": end,
                }
                chunks.append({
                    "text": chunk_text,
                    "metadata": chunk_meta,
                })
                chunk_idx += 1

            start = end - self.overlap
            if start >= len(text):
                break

        return chunks

    def chunk_document(self, title: str, content: str, source: str = "") -> List[Dict]:
        """Chunk a full document with source tracking.

        Args:
            title: Document title.
            content: Full document text.
            source: Source file path or URL.

        Returns:
            List of chunk dicts.
        """
        metadata = {
            "title": title,
            "source": source,
        }
        return self.chunk_text(content, metadata)


chunker = TextChunker()
