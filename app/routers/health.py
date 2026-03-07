"""
Health Check Routes
System status and health endpoints
"""
from fastapi import APIRouter, status
from datetime import datetime
from app.core.config import settings
from app.services.ai_analyzer import ai_analyzer
from app.services.betterstack import betterstack_service

router = APIRouter(tags=["Health"])


@router.get("/", status_code=status.HTTP_200_OK)
@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """
    Health check endpoint

    Returns the current status of the API and its dependencies.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "components": {
            "ai_analyzer": "enabled" if ai_analyzer.enabled else "disabled",
            "better_stack": "enabled" if betterstack_service.enabled else "disabled"
        },
        "config": {
            "ai_model": settings.ai_model if ai_analyzer.enabled else "N/A",
            "ai_threshold": settings.ai_threat_threshold,
        }
    }


@router.get("/health/live", status_code=status.HTTP_200_OK)
async def liveness():
    """
    Liveness probe

    Simple endpoint to check if the service is running.
    Used by orchestrators like Kubernetes.
    """
    return {"status": "alive"}


@router.get("/health/ready", status_code=status.HTTP_200_OK)
async def readiness():
    """
    Readiness probe

    Checks if the service is ready to accept traffic.
    Verifies that critical dependencies are available.
    """
    components = {}

    # Check ML model (critical — without it event processing falls back to heuristics only)
    try:
        from app.services.ml_detector import get_detector
        detector = get_detector()
        components["ml_model"] = detector.is_ready
    except Exception:
        components["ml_model"] = False

    # Check database connectivity
    try:
        from sqlalchemy import text
        from app.db.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        components["database"] = True
    except Exception:
        components["database"] = False

    # Check AI analyzer (optional — system works without LLM)
    components["ai_analyzer"] = ai_analyzer.enabled

    # Check Better Stack (optional)
    components["better_stack"] = betterstack_service.enabled

    # Ready only when critical components are up
    critical_ok = components["database"]
    ready = critical_ok

    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "ready" if ready else "not_ready",
            "components": components,
        },
    )


@router.get("/health/ml", tags=["ML"], status_code=status.HTTP_200_OK)
async def ml_health():
    """
    ML pipeline health: model status, drift detection, recent metrics.
    """
    try:
        from app.services.ml_detector import get_detector
        detector = get_detector()
        ml_stats = detector.get_stats()
    except Exception as e:
        ml_stats = {"error": str(e)}

    try:
        from app.services.drift_detector import get_drift_detector
        drift = get_drift_detector()
        drift_status = drift.get_status()
    except Exception as e:
        drift_status = {"error": str(e)}

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ml_model": ml_stats,
        "drift": drift_status,
    }


@router.get("/metrics", tags=["Observability"])
async def prometheus_metrics():
    """
    Prometheus-compatible metrics endpoint.

    Returns text/plain in Prometheus exposition format.
    Scrape with: prometheus.yml job target pointing to /metrics
    """
    from fastapi.responses import PlainTextResponse
    from app.services.metrics import metrics_service
    from app.services.event_processor import get_event_processor

    proc = get_event_processor()
    m = proc.get_metrics()

    lines = [
        "# HELP ir_agent_events_total Total events processed",
        "# TYPE ir_agent_events_total counter",
        f'ir_agent_events_total {m.get("total_processed", 0)}',
        "",
        "# HELP ir_agent_benign_filtered_total Benign events filtered",
        "# TYPE ir_agent_benign_filtered_total counter",
        f'ir_agent_benign_filtered_total {m.get("benign_filtered", 0)}',
        "",
        "# HELP ir_agent_malicious_detected_total Malicious events detected",
        "# TYPE ir_agent_malicious_detected_total counter",
        f'ir_agent_malicious_detected_total {m.get("malicious_detected", 0)}',
        "",
        "# HELP ir_agent_agent_invocations_total Deep-path agent invocations",
        "# TYPE ir_agent_agent_invocations_total counter",
        f'ir_agent_agent_invocations_total {m.get("agent_invocations", 0)}',
        "",
        "# HELP ir_agent_fast_path_total Fast-path (high confidence) events",
        "# TYPE ir_agent_fast_path_total counter",
        f'ir_agent_fast_path_total {m.get("fast_path_count", 0)}',
        "",
        "# HELP ir_agent_deep_path_total Deep-path (uncertain) events",
        "# TYPE ir_agent_deep_path_total counter",
        f'ir_agent_deep_path_total {m.get("deep_path_count", 0)}',
        "",
        "# HELP ir_agent_betterstack_sent_total Events forwarded to Better Stack",
        "# TYPE ir_agent_betterstack_sent_total counter",
        f'ir_agent_betterstack_sent_total {m.get("betterstack", {}).get("sent", 0)}',
        "",
    ]

    return PlainTextResponse("\n".join(lines), media_type="text/plain; version=0.0.4")