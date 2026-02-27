"""
Groq AI helpers — thin wrappers around the shared LLMClient.
"""
from app.core.llm_client import get_llm_client


def ask(prompt: str, temperature: float = 0.2, max_tokens: int = 512) -> str:
    client = get_llm_client()
    return client.chat(
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        max_tokens=max_tokens,
    )


def stream(prompt: str, temperature: float = 0.2):
    client = get_llm_client()
    yield from client.chat_stream(
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
    )
