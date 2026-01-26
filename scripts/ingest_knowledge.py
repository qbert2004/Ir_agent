"""Ingest all knowledge base documents into the FAISS vector store."""

import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

KNOWLEDGE_DIR = ROOT / "knowledge_base"
INDEX_PATH = ROOT / "vector_db" / "knowledge_index"


def ingest_all():
    """Ingest all knowledge base documents."""
    from app.agent.rag.vector_store import VectorStore
    from app.agent.rag.ingestion import IngestionPipeline

    print("=" * 60)
    print("Knowledge Base Ingestion")
    print("=" * 60)

    # Create fresh vector store
    store = VectorStore(index_path=str(INDEX_PATH))
    pipeline = IngestionPipeline(store)

    total_files = 0
    total_chunks = 0

    # Ingest each subdirectory
    for subdir in KNOWLEDGE_DIR.iterdir():
        if not subdir.is_dir():
            continue

        print(f"\nProcessing: {subdir.name}/")
        stats = pipeline.ingest_directory(str(subdir), recursive=True)
        total_files += stats["files_processed"]
        total_chunks += stats["chunks_added"]
        print(f"  Files: {stats['files_processed']}, Chunks: {stats['chunks_added']}")
        if stats["errors"]:
            for err in stats["errors"]:
                print(f"  ERROR: {err['file']}: {err['error']}")

    # Also ingest any top-level files in knowledge_base/
    for file in KNOWLEDGE_DIR.glob("*.txt"):
        try:
            added = pipeline.ingest_file(str(file))
            total_files += 1
            total_chunks += added
            print(f"  Ingested: {file.name} ({added} chunks)")
        except Exception as e:
            print(f"  ERROR: {file.name}: {e}")

    for file in KNOWLEDGE_DIR.glob("*.md"):
        try:
            added = pipeline.ingest_file(str(file))
            total_files += 1
            total_chunks += added
            print(f"  Ingested: {file.name} ({added} chunks)")
        except Exception as e:
            print(f"  ERROR: {file.name}: {e}")

    # Save the index
    store.save()

    print(f"\n{'=' * 60}")
    print(f"Ingestion Complete!")
    print(f"  Total files processed: {total_files}")
    print(f"  Total chunks indexed: {total_chunks}")
    print(f"  Vector store size: {store.size} vectors")
    print(f"  Index saved to: {INDEX_PATH}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    ingest_all()
