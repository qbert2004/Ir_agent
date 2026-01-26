"""
IR-Agent FastAPI Application
Main entry point for the API server
"""
import os
import sys
import logging
from pathlib import Path
from pathlib import Path
from fastapi.responses import HTMLResponse
UI_FILE = Path(__file__).with_name("report_ui.html")
# Добавляем корневую папку в PYTHONPATH
ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv

# Загружаем .env
load_dotenv()

# Импорты из app
try:
    from app.common.ai_groq import ask, stream
    from app.routers import health, ingest, report, investigation, agent
except ImportError as e:
    print(f"ERROR Import error: {e}")
    print(f"Current dir: {os.getcwd()}")
    print(f"Root dir: {ROOT_DIR}")
    print(f"Python path: {sys.path}")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="IR-Agent API",
    description="AI-powered Incident Response Agent",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Better Stack logging
try:
    from logtail import LogtailHandler

    betterstack_token = os.getenv("BETTER_STACK_SOURCE_TOKEN")
    if betterstack_token:
        handler = LogtailHandler(source_token=betterstack_token)
        handler.setLevel(logging.INFO)

        for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi", "ir-agent"):
            log = logging.getLogger(logger_name)
            log.setLevel(logging.INFO)
            log.addHandler(handler)
            log.propagate = False

        logger.info("OK Better Stack logging enabled")
    else:
        logger.warning("WARNING  Better Stack token not found")
except ImportError:
    logger.warning("WARNING  logtail-python not installed - Better Stack logging disabled")


# Request logging middleware
@app.middleware("http")
async def log_requests(request, call_next):
    logger.info(f"→ {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"← {request.url.path} - {response.status_code}")
    return response


# Include routers
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(report.router)
app.include_router(investigation.router)
app.include_router(agent.router)

from fastapi.responses import HTMLResponse

@app.get("/report_ui", response_class=HTMLResponse)
async def report_ui():
    # Надёжное чтение файла рядом с main.py
    return UI_FILE.read_text(encoding="utf-8")

# Test endpoints for Groq AI
@app.get("/ai/test")
def ai_test():
    """Test Groq API connection"""
    try:
        reply = ask("Say 'Groq API works!' and nothing else.", max_tokens=16)
        return {"status": "success", "reply": reply}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/ai/stream")
def ai_stream(q: str = "Hello"):
    """Test streaming response from Groq"""
    return StreamingResponse(stream(q), media_type="text/plain")


@app.on_event("startup")
async def startup_event():
    """Print configuration on startup"""
    print("\n" + "=" * 60)
    print("IR-Agent API Started")
    print("=" * 60)

    # Check AI configuration
    api_key = os.getenv("LLM_API_KEY")
    if api_key:
        print(f"OK AI Provider: {os.getenv('LLM_PROVIDER', 'groq')}")
        print(f"OK AI Model: {os.getenv('LLM_ANALYZER_MODEL', 'llama-3.3-70b-versatile')}")
    else:
        print("X AI Analyzer: DISABLED (no LLM_API_KEY)")

    # Check Better Stack
    bs_token = os.getenv("BETTER_STACK_SOURCE_TOKEN")
    if bs_token:
        print(f"OK Better Stack: Enabled")
    else:
        print("X Better Stack: Disabled")

    print(f"OK Threshold: {os.getenv('AI_SUSPICIOUS_THRESHOLD', '60')}")
    print(f"OK Port: {os.getenv('API_PORT', '9000')}")

    # Initialize Agent Service
    try:
        from app.services.agent_service import agent_service
        stats = agent_service.get_knowledge_stats()
        print(f"OK CyberAgent: {len(agent_service.get_tools())} tools, {stats['total_vectors']} knowledge vectors")
    except Exception as e:
        print(f"X CyberAgent: Failed to initialize ({e})")

    print("=" * 60 + "\n")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("IR-Agent API shutting down...")
    try:
        from app.services.agent_service import agent_service
        agent_service.save()
        logger.info("Agent state saved successfully")
    except Exception as e:
        logger.warning(f"Failed to save agent state: {e}")


# Entry point
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("API_PORT", "9000"))
    host = os.getenv("API_HOST", "0.0.0.0")

    print(f"\nStarting IR-Agent on {host}:{port}...\n")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )
