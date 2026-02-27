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
