import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

_API_KEY = os.getenv("GROQ_API_KEY") or os.getenv("LLM_API_KEY")
_MODEL   = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
_client  = Groq(api_key=_API_KEY)

def ask(prompt: str, temperature: float = 0.2, max_tokens: int = 512) -> str:
    if not _API_KEY:
        raise RuntimeError("GROQ_API_KEY не задан")
    r = _client.chat.completions.create(
        model=_MODEL,
        messages=[{"role":"user","content": prompt}],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return r.choices[0].message.content.strip()

def stream(prompt: str, temperature: float = 0.2):
    r = _client.chat.completions.create(
        model=_MODEL,
        messages=[{"role":"user","content": prompt}],
        temperature=temperature,
        stream=True,
    )
    for ch in r:
        chunk = ch.choices[0].delta.content or ""
        if chunk:
            yield chunk
