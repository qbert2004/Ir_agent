"""Unified memory interface combining short-term and long-term memory."""

from typing import Dict, Optional

from app.agent.memory.short_term import ShortTermMemory
from app.agent.memory.long_term import LongTermMemory


class MemoryManager:
    """Unified memory interface managing per-session short-term and global long-term memory."""

    def __init__(self):
        self._sessions: Dict[str, ShortTermMemory] = {}
        self._long_term = LongTermMemory()

    def get_session(self, session_id: str) -> ShortTermMemory:
        """Get or create a short-term memory for a session."""
        if session_id not in self._sessions:
            self._sessions[session_id] = ShortTermMemory()
        return self._sessions[session_id]

    def add_user_message(self, session_id: str, message: str):
        """Record a user message in session memory."""
        self.get_session(session_id).add_user_message(message)

    def add_assistant_message(self, session_id: str, message: str):
        """Record an assistant response in session memory."""
        self.get_session(session_id).add_assistant_message(message)

    def get_context(self, session_id: str, query: str) -> str:
        """Build full context from short-term history and relevant long-term memories.

        Args:
            session_id: Current session ID.
            query: Current user query for long-term memory retrieval.

        Returns:
            Combined context string.
        """
        parts = []

        # Short-term: recent conversation
        short_term = self.get_session(session_id).get_context_string()
        if short_term:
            parts.append(short_term)

        # Long-term: relevant past investigations
        long_term = self._long_term.recall_formatted(query, top_k=2)
        if long_term:
            parts.append(long_term)

        return "\n\n".join(parts)

    def store_investigation(self, content: str, session_id: str = "", metadata: Dict = None):
        """Store an investigation result in long-term memory."""
        if metadata is None:
            metadata = {}
        metadata["session_id"] = session_id
        self._long_term.store(content, metadata)

    def clear_session(self, session_id: str):
        """Clear a session's short-term memory."""
        if session_id in self._sessions:
            self._sessions[session_id].clear()
            del self._sessions[session_id]

    def save(self):
        """Persist long-term memory to disk."""
        self._long_term.save()

    def get_session_history(self, session_id: str):
        """Get raw history for a session."""
        return self.get_session(session_id).get_history()

    @property
    def active_sessions(self) -> int:
        return len(self._sessions)

    @property
    def long_term_size(self) -> int:
        return self._long_term.size
