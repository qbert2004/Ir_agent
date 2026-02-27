"""
Shared Groq LLM client with retry, timeout, and connection reuse.
"""

from __future__ import annotations

import time
import logging
from typing import Dict, List, Optional

from groq import Groq
from app.core.config import settings

logger = logging.getLogger("ir-agent")

MAX_RETRIES = 3
RETRY_BACKOFF = (1.0, 2.0, 4.0)
DEFAULT_TIMEOUT = 30.0  # seconds


class LLMClient:
    """Singleton Groq client with retry logic."""

    _instance: Optional["LLMClient"] = None

    def __new__(cls) -> "LLMClient":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._client: Optional[Groq] = None
        if settings.groq_api_key:
            self._client = Groq(
                api_key=settings.groq_api_key,
                timeout=DEFAULT_TIMEOUT,
            )
            logger.info("LLMClient initialized (model=%s)", settings.ai_model)
        else:
            logger.warning("LLMClient: no API key, LLM calls will fail")

    @property
    def available(self) -> bool:
        return self._client is not None

    def chat(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> str:
        """Send a chat completion request with retry."""
        if not self._client:
            raise RuntimeError("LLM API key not configured")

        model = model or settings.ai_model

        for attempt in range(MAX_RETRIES):
            try:
                response = self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                wait = RETRY_BACKOFF[attempt] if attempt < len(RETRY_BACKOFF) else RETRY_BACKOFF[-1]
                logger.warning(
                    "LLM call failed (attempt %d/%d): %s — retrying in %.1fs",
                    attempt + 1, MAX_RETRIES, e, wait,
                )
                if attempt == MAX_RETRIES - 1:
                    raise
                time.sleep(wait)

        raise RuntimeError("LLM call failed after retries")  # unreachable

    def chat_stream(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.2,
    ):
        """Streaming chat completion (no retry — streams are not retryable)."""
        if not self._client:
            raise RuntimeError("LLM API key not configured")

        model = model or settings.ai_model
        response = self._client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            stream=True,
        )
        for chunk in response:
            text = chunk.choices[0].delta.content or ""
            if text:
                yield text


def get_llm_client() -> LLMClient:
    return LLMClient()
