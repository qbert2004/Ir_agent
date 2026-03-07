"""Unified memory interface combining short-term and long-term memory.

Session eviction policy (prevents memory leak):
    - LRU cap: at most SESSION_MAX_SIZE sessions are kept in memory.
      When the cap is reached the least-recently-used session is evicted.
    - TTL: sessions that have not been accessed for SESSION_TTL_SECONDS are
      evicted lazily on the next access to any session.

Both limits are configurable via environment variables:
    AGENT_SESSION_MAX_SIZE   (default 1000)
    AGENT_SESSION_TTL_SECONDS (default 3600 = 1 hour)
"""

import os
import time
import threading
from collections import OrderedDict
from typing import Dict, Optional

from app.agent.memory.short_term import ShortTermMemory
from app.agent.memory.long_term import LongTermMemory

SESSION_MAX_SIZE = int(os.getenv("AGENT_SESSION_MAX_SIZE", "1000"))
SESSION_TTL_SECONDS = float(os.getenv("AGENT_SESSION_TTL_SECONDS", str(60 * 60)))  # 1 h


class MemoryManager:
    """Unified memory interface managing per-session short-term and global long-term memory."""

    def __init__(self):
        # OrderedDict preserves insertion/access order so we can do O(1) LRU eviction.
        # Values are (ShortTermMemory, last_access_monotonic_timestamp).
        self._sessions: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._long_term = LongTermMemory()

    # ── Internal session management ────────────────────────────────────────────

    def _evict_expired(self) -> None:
        """Remove sessions whose TTL has elapsed.  Must be called under self._lock."""
        now = time.monotonic()
        expired = [
            sid for sid, (_, ts) in self._sessions.items()
            if now - ts > SESSION_TTL_SECONDS
        ]
        for sid in expired:
            del self._sessions[sid]

    def _touch(self, session_id: str) -> None:
        """Mark session as recently used (LRU bookkeeping).  Must be called under self._lock."""
        mem, _ = self._sessions[session_id]
        self._sessions.move_to_end(session_id)
        self._sessions[session_id] = (mem, time.monotonic())

    def _get_or_create(self, session_id: str) -> ShortTermMemory:
        """Return the ShortTermMemory for *session_id*, creating it if necessary.

        Called under self._lock.  Applies TTL eviction then LRU cap eviction.
        """
        self._evict_expired()

        if session_id in self._sessions:
            self._touch(session_id)
            return self._sessions[session_id][0]

        # Create new session
        mem = ShortTermMemory()
        self._sessions[session_id] = (mem, time.monotonic())
        self._sessions.move_to_end(session_id)

        # Evict least-recently-used entries when over cap
        while len(self._sessions) > SESSION_MAX_SIZE:
            self._sessions.popitem(last=False)

        return mem

    # ── Public API ────────────────────────────────────────────────────────────

    def get_session(self, session_id: str) -> ShortTermMemory:
        """Get or create a short-term memory for a session."""
        with self._lock:
            return self._get_or_create(session_id)

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
        """Clear a session's short-term memory and remove it from the registry."""
        with self._lock:
            if session_id in self._sessions:
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
