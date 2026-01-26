"""
Configuration Settings
Centralized application configuration
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings"""

    # App info
    app_name: str = "IR-Agent"
    app_version: str = "1.0.0"
    environment: str = os.getenv("ENVIRONMENT", "production")

    # API
    api_port: int = int(os.getenv("API_PORT", "9000"))
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    my_api_token: str = os.getenv("MY_API_TOKEN", "")

    # AI Configuration
    ai_provider: str = os.getenv("LLM_PROVIDER", "groq")
    groq_api_key: str = os.getenv("LLM_API_KEY", "")
    ai_model: str = os.getenv("LLM_ANALYZER_MODEL", "llama-3.3-70b-versatile")
    ai_enabled: bool = bool(groq_api_key)
    ai_threat_threshold: int = int(os.getenv("AI_SUSPICIOUS_THRESHOLD", "60"))

    # Better Stack
    betterstack_token: str = os.getenv("BETTER_STACK_SOURCE_TOKEN", "")
    betterstack_enabled: bool = bool(betterstack_token)
    send_all_to_betterstack: bool = os.getenv("SEND_ALL_TO_BETTERSTACK", "false").lower() == "true"


settings = Settings()