"""Short-term memory: sliding window of recent conversation exchanges."""

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Exchange:
    """A single user-agent exchange."""
    role: str  # "user" or "assistant"
    content: str


class ShortTermMemory:
    """Sliding window memory for recent conversation context."""

    def __init__(self, max_exchanges: int = 10):
        self.max_exchanges = max_exchanges
        self._history: deque = deque(maxlen=max_exchanges * 2)

    def add_user_message(self, message: str):
        """Add a user message to history."""
        self._history.append(Exchange(role="user", content=message))

    def add_assistant_message(self, message: str):
        """Add an assistant response to history."""
        self._history.append(Exchange(role="assistant", content=message))

    def get_history(self) -> List[Dict[str, str]]:
        """Get conversation history as list of role/content dicts."""
        return [{"role": ex.role, "content": ex.content} for ex in self._history]

    def get_context_string(self) -> str:
        """Get history formatted as a context string for the prompt."""
        if not self._history:
            return ""

        lines = ["Previous conversation:"]
        for ex in self._history:
            prefix = "User" if ex.role == "user" else "Assistant"
            lines.append(f"{prefix}: {ex.content[:500]}")

        return "\n".join(lines)

    def clear(self):
        """Clear all history."""
        self._history.clear()

    @property
    def size(self) -> int:
        """Number of exchanges in memory."""
        return len(self._history)
