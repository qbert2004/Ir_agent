"""
IR-Agent FastAPI Application
Main entry point for the API server
"""

import os
import sys
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from dotenv import load_dotenv

# Add project root to path
ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))

load_dotenv()

# Imports
try:
    from app.common.ai_groq import ask, stream
    from app.routers import health, ingest, report, investigation, agent
    from app.routers import ml_investigation
    from app.routers import assessment
    from app.core.config import settings
    from app.core.middleware import (
        RequestIDMiddleware,
        AuthMiddleware,
        RateLimitMiddleware,
        RequestLoggingMiddleware,
    )
except ImportError as e:
    print(f"ERROR Import error: {e}")
    print(f"Current dir: {os.getcwd()}")
    print(f"Python path: {sys.path}")
    sys.exit(1)

# ── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ir-agent")

# Better Stack handler (optional)
try:
    from logtail import LogtailHandler

    if settings.betterstack_token:
        _handler = LogtailHandler(source_token=settings.betterstack_token)
        _handler.setLevel(logging.INFO)
        for _name in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi", "ir-agent"):
            _log = logging.getLogger(_name)
            _log.setLevel(logging.INFO)
            _log.addHandler(_handler)
            _log.propagate = False
        logger.info("Better Stack logging enabled")
except ImportError:
    logger.warning("logtail-python not installed — Better Stack logging disabled")

# ── UI files ─────────────────────────────────────────────────────────────
UI_FILE        = Path(__file__).with_name("report_ui.html")
DASHBOARD_FILE = Path(__file__).with_name("dashboard.html")


# ── Lifespan (replaces deprecated on_event) ─────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── STARTUP ──
    logger.info("=" * 60)
    logger.info("IR-Agent API Started")
    logger.info("=" * 60)

    if settings.ai_enabled:
        logger.info("AI Provider: %s  Model: %s", settings.ai_provider, settings.ai_model)
    else:
        logger.warning("AI Analyzer: DISABLED (no LLM_API_KEY)")

    if settings.betterstack_enabled:
        logger.info("Better Stack: Enabled")
    else:
        logger.warning("Better Stack: Disabled")

    if settings.api_token:
        logger.info("Auth: Enabled (API token)")
    elif settings.environment == "production":
        logger.critical(
            "SECURITY WARNING: MY_API_TOKEN is not set in production! "
            "All API endpoints are publicly accessible. Set MY_API_TOKEN in .env immediately."
        )
    else:
        logger.warning("Auth: Disabled (dev mode — set MY_API_TOKEN for production)")
    if not os.getenv("REDIS_URL"):
        logger.warning(
            "Rate limiter: in-memory backend. Set REDIS_URL for multi-worker deployments."
        )
    logger.info("CORS origins: %s", settings.cors_origins_list)
    logger.info("Rate limit: %d req/min", settings.rate_limit_per_minute)
    logger.info("Threshold: %d  Port: %d", settings.ai_threat_threshold, settings.api_port)
    logger.info(
        "Docs UI: %s",
        "DISABLED (production)" if settings.environment == "production" else "/docs (dev mode)",
    )

    # Database
    try:
        from app.db.database import init_db, _safe_db_url
        await init_db()
        logger.info("Database: %s", _safe_db_url(settings.database_url))
    except Exception as e:
        logger.error("Database init failed: %s", e)

    # Agent
    try:
        from app.services.agent_service import agent_service
        stats = agent_service.get_knowledge_stats()
        logger.info(
            "CyberAgent: %d tools, %d knowledge vectors",
            len(agent_service.get_tools()),
            stats["total_vectors"],
        )
    except Exception as e:
        logger.error("CyberAgent init failed: %s", e)

    # ML Engine
    try:
        from app.ml.cyber_ml_engine import get_ml_engine
        ml_engine = get_ml_engine()
        info = ml_engine.get_model_info()
        status = "LOADED" if info["event_classifier_loaded"] else "HEURISTIC"
        logger.info("ML Engine: %s (%d MITRE patterns)", status, info["mitre_techniques_count"])
    except Exception as e:
        logger.error("ML Engine init failed: %s", e)

    logger.info("=" * 60)

    yield  # ← app is running

    # ── SHUTDOWN ──
    logger.info("IR-Agent API shutting down...")
    try:
        from app.services.agent_service import agent_service
        agent_service.save()
        logger.info("Agent state saved")
    except Exception as e:
        logger.warning("Failed to save agent state: %s", e)

    try:
        from app.db.database import close_db
        await close_db()
    except Exception as e:
        logger.warning("DB close error: %s", e)


# ── FastAPI app ──────────────────────────────────────────────────────────
# In production hide Swagger UI to avoid API surface exposure.
_docs_url = None if settings.environment == "production" else "/docs"
_redoc_url = None if settings.environment == "production" else "/redoc"

app = FastAPI(
    title="IR-Agent API",
    description="AI-powered Incident Response Agent",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
)

# ── Middleware (order matters: outermost first) ──────────────────────────
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=settings.rate_limit_per_minute)
app.add_middleware(AuthMiddleware)
app.add_middleware(RequestIDMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# ── Routers ──────────────────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(report.router)
app.include_router(investigation.router)
app.include_router(agent.router)
app.include_router(ml_investigation.router)
app.include_router(assessment.router)


# ── Extra endpoints ──────────────────────────────────────────────────────
@app.get("/report_ui", response_class=HTMLResponse, include_in_schema=False)
async def report_ui():
    """Report UI — protected by AuthMiddleware (same as all non-public endpoints)."""
    return UI_FILE.read_text(encoding="utf-8")


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    """Agent Platform Dashboard — architecture, live query, tools, metrics, comparison."""
    return DASHBOARD_FILE.read_text(encoding="utf-8")


# Debug endpoints — exposed only outside production to avoid unnecessary attack surface
if settings.environment != "production":
    @app.get("/ai/test", tags=["Debug"])
    def ai_test():
        """Test Groq API connection. Disabled in production."""
        try:
            reply = ask("Say 'Groq API works!' and nothing else.", max_tokens=16)
            return {"status": "success", "reply": reply}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @app.get("/ai/stream", tags=["Debug"])
    def ai_stream(q: str = "Hello"):
        """Test streaming response from Groq. Disabled in production."""
        return StreamingResponse(stream(q), media_type="text/plain")


# ── Entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    logger.info("Starting IR-Agent on %s:%d ...", settings.api_host, settings.api_port)
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
    )
