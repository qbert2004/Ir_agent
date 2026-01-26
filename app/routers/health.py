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
    ready = True
    components = {}

    # Check AI analyzer
    components["ai_analyzer"] = ai_analyzer.enabled

    # Check Better Stack
    components["better_stack"] = betterstack_service.enabled

    # Service is ready if at least one component is available
    ready = any(components.values())

    return {
        "status": "ready" if ready else "not_ready",
        "components": components
    }