"""Tests for configuration."""

from app.core.config import Settings


def test_defaults():
    s = Settings(
        _env_file=None,
        LLM_API_KEY="",
        BETTER_STACK_SOURCE_TOKEN="",
    )
    assert s.app_name == "IR-Agent"
    assert s.api_port == 9000
    assert s.ai_enabled is False
    assert s.betterstack_enabled is False


def test_ai_enabled():
    s = Settings(
        _env_file=None,
        LLM_API_KEY="test-key-123",
        BETTER_STACK_SOURCE_TOKEN="",
    )
    assert s.ai_enabled is True
    assert s.groq_api_key == "test-key-123"


def test_cors_origins_list():
    s = Settings(
        _env_file=None,
        CORS_ORIGINS="http://a.com, http://b.com",
        LLM_API_KEY="",
        BETTER_STACK_SOURCE_TOKEN="",
    )
    assert s.cors_origins_list == ["http://a.com", "http://b.com"]


def test_rate_limit_default():
    s = Settings(
        _env_file=None,
        LLM_API_KEY="",
        BETTER_STACK_SOURCE_TOKEN="",
    )
    assert s.rate_limit_per_minute == 60


def test_ai_enabled_openai_fallback():
    """ai_enabled must be True when only OPENAI_API_KEY is set (no Groq key)."""
    s = Settings(
        _env_file=None,
        LLM_API_KEY="",
        OPENAI_API_KEY="sk-test-openai",
        BETTER_STACK_SOURCE_TOKEN="",
    )
    assert s.ai_enabled is True


def test_ai_enabled_ollama_fallback():
    """ai_enabled must be True when only OLLAMA_BASE_URL is set."""
    s = Settings(
        _env_file=None,
        LLM_API_KEY="",
        OPENAI_API_KEY="",
        OLLAMA_BASE_URL="http://localhost:11434",
        BETTER_STACK_SOURCE_TOKEN="",
    )
    assert s.ai_enabled is True


def test_ai_disabled_when_no_provider():
    """ai_enabled must be False when no provider is configured."""
    s = Settings(
        _env_file=None,
        LLM_API_KEY="",
        OPENAI_API_KEY="",
        OLLAMA_BASE_URL="",
        BETTER_STACK_SOURCE_TOKEN="",
    )
    assert s.ai_enabled is False
