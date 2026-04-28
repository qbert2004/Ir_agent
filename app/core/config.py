"""
Configuration Settings
Centralized application configuration with validation
"""
import os
from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings with environment variable validation."""

    # App info
    app_name: str = "IR-Agent"
    app_version: str = "1.0.0"
    environment: str = Field(default="production", alias="ENVIRONMENT")

    # API
    api_port: int = Field(default=9000, alias="API_PORT")
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_token: str = Field(default="", alias="MY_API_TOKEN")

    # AI Configuration
    ai_provider: str = Field(default="google", alias="LLM_PROVIDER")

    # Google AI Studio — Gemma 4 (first priority)
    google_api_key: str = Field(default="", alias="GOOGLE_API_KEY")
    google_ai_model: str = Field(default="gemma-4-27b-it", alias="GOOGLE_AI_MODEL")

    # Groq fallback
    groq_api_key: str = Field(default="", alias="LLM_API_KEY")
    # OpenAI fallback
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    # Ollama local fallback
    ollama_base_url: str = Field(default="", alias="OLLAMA_BASE_URL")

    ai_model: str = Field(default="gemma-4-27b-it", alias="LLM_ANALYZER_MODEL")
    ai_report_model: str = Field(default="gemma-4-27b-it", alias="LLM_REPORT_MODEL")
    ai_threat_threshold: int = Field(default=60, alias="AI_SUSPICIOUS_THRESHOLD")

    # Better Stack
    betterstack_token: str = Field(default="", alias="BETTER_STACK_SOURCE_TOKEN")
    send_all_to_betterstack: bool = Field(default=False, alias="SEND_ALL_TO_BETTERSTACK")

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./ir_agent.db",
        alias="DATABASE_URL",
    )

    # Security
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:9000",
        alias="CORS_ORIGINS",
    )
    rate_limit_per_minute: int = Field(default=60, alias="RATE_LIMIT_PER_MINUTE")

    @property
    def ai_enabled(self) -> bool:
        """True when at least one LLM provider is configured.

        Provider priority mirrors LLM client fallback chain:
            Google (GOOGLE_API_KEY) → Groq (LLM_API_KEY) → OpenAI → Ollama
        """
        return bool(
            self.google_api_key or self.groq_api_key
            or self.openai_api_key or self.ollama_base_url
        )

    @property
    def betterstack_enabled(self) -> bool:
        return bool(self.betterstack_token)

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "populate_by_name": True,
    }


settings = Settings()
