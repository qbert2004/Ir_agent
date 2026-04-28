"""
LLM client with multi-provider support and automatic fallback.

Provider priority (based on available API keys in .env):
    1. Google  — GOOGLE_API_KEY      (Gemma 4 via AI Studio OpenAI-compat endpoint)
    2. Groq    — LLM_API_KEY         (fast, free tier)
    3. OpenAI  — OPENAI_API_KEY      (reliable, paid)
    4. Ollama  — OLLAMA_BASE_URL     (local, offline)

If a provider fails during a request, the next available provider is tried.
"""

from __future__ import annotations

import time
import logging
from typing import Iterator, Optional

from app.core.config import settings

logger = logging.getLogger("ir-agent")

MAX_RETRIES = 3
RETRY_BACKOFF = (1.0, 2.0, 4.0)
DEFAULT_TIMEOUT = 30.0


# ── Provider base ─────────────────────────────────────────────────────────────

class _BaseProvider:
    name: str = "base"

    def is_available(self) -> bool:
        return False

    def chat(self, messages: list[dict], model: str, temperature: float, max_tokens: int) -> str:
        raise NotImplementedError

    def chat_stream(self, messages: list[dict], model: str, temperature: float) -> Iterator[str]:
        raise NotImplementedError


# ── Google AI provider (Gemma 4 via OpenAI-compatible endpoint) ───────────────

class _GoogleProvider(_BaseProvider):
    """
    Google AI Studio — Gemma 4 via the OpenAI-compatible REST endpoint.

    Endpoint: https://generativelanguage.googleapis.com/v1beta/openai/
    Model:    models/gemma-4-31b-it  (set via GOOGLE_AI_MODEL or LLM_ANALYZER_MODEL)
    Key:      GOOGLE_API_KEY  (get at https://aistudio.google.com/apikey)

    No extra SDK required — uses the standard openai package with a custom base_url.
    """
    name = "google"
    _ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/openai/"
    _DEFAULT_MODEL = "models/gemma-4-31b-it"

    def __init__(self):
        self._client = None
        api_key = settings.google_api_key
        if api_key:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    base_url=self._ENDPOINT,
                    api_key=api_key,
                    timeout=DEFAULT_TIMEOUT,
                )
                model = settings.google_ai_model or self._DEFAULT_MODEL
                logger.info("LLM provider: Google AI Studio (model=%s)", model)
            except ImportError:
                logger.warning("openai package not installed — cannot use Google provider")

    def is_available(self) -> bool:
        return self._client is not None

    def _model(self, override: str | None) -> str:
        return override or settings.google_ai_model or self._DEFAULT_MODEL

    def chat(self, messages, model, temperature, max_tokens) -> str:
        resp = self._client.chat.completions.create(
            model=self._model(model),
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    def chat_stream(self, messages, model, temperature) -> Iterator[str]:
        resp = self._client.chat.completions.create(
            model=self._model(model),
            messages=messages,
            temperature=temperature,
            stream=True,
        )
        for chunk in resp:
            text = chunk.choices[0].delta.content or ""
            if text:
                yield text


# ── Groq provider ─────────────────────────────────────────────────────────────

class _GroqProvider(_BaseProvider):
    name = "groq"

    def __init__(self):
        self._client = None
        if settings.groq_api_key:
            try:
                from groq import Groq
                self._client = Groq(api_key=settings.groq_api_key, timeout=DEFAULT_TIMEOUT)
                logger.info("LLM provider: Groq (model=%s)", settings.ai_model)
            except ImportError:
                logger.warning("groq package not installed")

    def is_available(self) -> bool:
        return self._client is not None

    def chat(self, messages, model, temperature, max_tokens) -> str:
        resp = self._client.chat.completions.create(
            model=model or settings.ai_model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    def chat_stream(self, messages, model, temperature) -> Iterator[str]:
        resp = self._client.chat.completions.create(
            model=model or settings.ai_model,
            messages=messages,
            temperature=temperature,
            stream=True,
        )
        for chunk in resp:
            text = chunk.choices[0].delta.content or ""
            if text:
                yield text


# ── OpenAI provider ────────────────────────────────────────────────────────────

class _OpenAIProvider(_BaseProvider):
    name = "openai"
    _DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self):
        self._client = None
        api_key = settings.openai_api_key
        if api_key:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=api_key, timeout=DEFAULT_TIMEOUT)
                logger.info("LLM provider: OpenAI available as fallback")
            except ImportError:
                logger.debug("openai package not installed — skipping OpenAI fallback")

    def is_available(self) -> bool:
        return self._client is not None

    def chat(self, messages, model, temperature, max_tokens) -> str:
        resp = self._client.chat.completions.create(
            model=model or self._DEFAULT_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    def chat_stream(self, messages, model, temperature) -> Iterator[str]:
        resp = self._client.chat.completions.create(
            model=model or self._DEFAULT_MODEL,
            messages=messages,
            temperature=temperature,
            stream=True,
        )
        for chunk in resp:
            text = chunk.choices[0].delta.content or ""
            if text:
                yield text


# ── Ollama provider ────────────────────────────────────────────────────────────

class _OllamaProvider(_BaseProvider):
    name = "ollama"
    _DEFAULT_MODEL = "llama3.2"

    def __init__(self):
        self._base_url = settings.ollama_base_url
        self._client = None
        if self._base_url:
            try:
                from openai import OpenAI  # Ollama uses OpenAI-compatible API
                self._client = OpenAI(
                    base_url=f"{self._base_url.rstrip('/')}/v1",
                    api_key="ollama",  # required but ignored by Ollama
                    timeout=DEFAULT_TIMEOUT,
                )
                logger.info("LLM provider: Ollama available as fallback (%s)", self._base_url)
            except ImportError:
                pass

    def is_available(self) -> bool:
        return self._client is not None

    def chat(self, messages, model, temperature, max_tokens) -> str:
        resp = self._client.chat.completions.create(
            model=model or self._DEFAULT_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    def chat_stream(self, messages, model, temperature) -> Iterator[str]:
        resp = self._client.chat.completions.create(
            model=model or self._DEFAULT_MODEL,
            messages=messages,
            temperature=temperature,
            stream=True,
        )
        for chunk in resp:
            text = chunk.choices[0].delta.content or ""
            if text:
                yield text


# ── LLMClient with fallback ────────────────────────────────────────────────────

class LLMClient:
    """
    Multi-provider LLM client with automatic fallback.

    Tries providers in order: Groq → OpenAI → Ollama.
    If a provider fails, the next available provider is used automatically.
    """

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
        self._providers: list[_BaseProvider] = [
            _GoogleProvider(),
            _GroqProvider(),
            _OpenAIProvider(),
            _OllamaProvider(),
        ]
        available = [p.name for p in self._providers if p.is_available()]
        if available:
            logger.info("LLM providers available: %s", available)
        else:
            logger.warning("LLMClient: no providers configured — LLM calls will fail")

    @property
    def available(self) -> bool:
        return any(p.is_available() for p in self._providers)

    def _active_providers(self) -> list[_BaseProvider]:
        return [p for p in self._providers if p.is_available()]

    def chat(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> str:
        """Send a chat completion with retry and cross-provider fallback."""
        providers = self._active_providers()
        if not providers:
            raise RuntimeError("No LLM providers configured (set LLM_API_KEY, OPENAI_API_KEY, or OLLAMA_BASE_URL)")

        last_error: Exception = RuntimeError("unknown")

        for provider in providers:
            for attempt in range(MAX_RETRIES):
                try:
                    result = provider.chat(messages, model, temperature, max_tokens)
                    if provider.name != self._providers[0].name:
                        logger.info("LLM request served by fallback provider: %s", provider.name)
                    return result
                except Exception as e:
                    last_error = e
                    wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                    logger.warning(
                        "[%s] LLM call failed (attempt %d/%d): %s",
                        provider.name, attempt + 1, MAX_RETRIES, e,
                    )
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(wait)
            logger.warning("Provider %s exhausted, trying next...", provider.name)

        raise RuntimeError(f"All LLM providers failed. Last error: {last_error}")

    def chat_stream(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.2,
    ) -> Iterator[str]:
        """Streaming chat (uses first available provider, no cross-provider fallback)."""
        providers = self._active_providers()
        if not providers:
            raise RuntimeError("No LLM providers configured")
        yield from providers[0].chat_stream(messages, model, temperature)


def get_llm_client() -> LLMClient:
    return LLMClient()
