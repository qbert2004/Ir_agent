"""
Telemetry Ingest Routes with Hybrid ML + Agent Processing

Architecture:
    1. Fast-path (ML only, ~5ms): High confidence filtering
    2. Deep-path (CyberAgent, ~1-2s): Uncertain cases (50-80% confidence)

Flow:
    Event → EventProcessor.classify_and_forward()
        → BENIGN: discard
        → HIGH CONFIDENCE: fast-forward to Better Stack
        → UNCERTAIN: Agent analysis → forward
"""
from fastapi import APIRouter, BackgroundTasks, Request
from datetime import datetime
from typing import Dict, Any
import logging

from app.services.event_processor import get_event_processor
from app.services.incident_manager import get_incident_manager

router = APIRouter(prefix="/ingest", tags=["Ingest"])
logger = logging.getLogger("ir-agent")

# Get singletons
event_processor = get_event_processor()
incident_manager = get_incident_manager()


async def process_event(event: Dict[str, Any]):
    """
    Process event through hybrid ML + Agent pipeline.

    - BENIGN → filtered (discarded)
    - HIGH CONFIDENCE MALICIOUS → fast-path to Better Stack
    - UNCERTAIN (50-80%) → deep-path with CyberAgent analysis
    """
    try:
        result = await event_processor.classify_and_forward(event)

        path = result.get("path", "unknown")
        status = result.get("status", "unknown")
        classification = result.get("classification", "unknown")

        if status == "filtered":
            logger.debug(f"FILTERED: {event.get('process_name', 'unknown')}")
        elif path == "fast":
            logger.info(
                f"FAST-PATH [{result.get('confidence', 0):.0%}]: "
                f"{event.get('process_name', 'unknown')} - {result.get('reason', '')}"
            )
        elif path == "deep":
            logger.info(
                f"DEEP-PATH: {event.get('process_name', 'unknown')} - "
                f"ML: {result.get('ml_confidence', 0):.0%} → Agent: {result.get('agent_verdict', 'N/A')}"
            )
        elif path == "deep-fallback":
            logger.warning(
                f"DEEP-FALLBACK: {event.get('process_name', 'unknown')} - "
                f"Agent failed, using ML result"
            )

    except Exception as e:
        logger.error(f"Event processing error: {e}")


@router.post("/telemetry")
async def ingest_telemetry(request: Request, background_tasks: BackgroundTasks):
    """
    Ingest telemetry events through hybrid ML + Agent pipeline.

    Processing:
        - BENIGN events (<50% confidence) are filtered
        - HIGH CONFIDENCE malicious (≥80%) go fast-path to Better Stack
        - UNCERTAIN (50-80%) trigger CyberAgent deep analysis

    Returns:
        status: success/error
        received: number of events received
        message: processing summary
        processor_ready: whether ML model is loaded
    """
    try:
        data = await request.json()
        events = data if isinstance(data, list) else [data]

        logger.info(f"Received {len(events)} events for hybrid processing")

        for event in events:
            if "timestamp" not in event:
                event["timestamp"] = datetime.utcnow().isoformat() + "Z"

            # Process through hybrid pipeline in background
            background_tasks.add_task(process_event, event)

        return {
            "status": "success",
            "received": len(events),
            "message": f"Processing {len(events)} events through hybrid ML+Agent pipeline",
            "processor_ready": event_processor.is_ready,
        }

    except Exception as e:
        logger.error(f"Ingestion error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/metrics")
async def get_metrics():
    """
    Get event processing metrics.

    Returns metrics for:
        - Total events processed
        - Benign events filtered
        - Malicious detected (fast-path + deep-path)
        - Agent invocations
        - Better Stack forwarding stats
    """
    metrics = event_processor.get_metrics()

    return {
        "status": "success",
        "processing": {
            "total_processed": metrics["total_processed"],
            "benign_filtered": metrics["benign_filtered"],
            "malicious_detected": metrics["malicious_detected"],
            "filter_rate": metrics["filter_rate"],
        },
        "paths": {
            "fast_path_count": metrics["fast_path_count"],
            "deep_path_count": metrics["deep_path_count"],
            "deep_path_rate": metrics["deep_path_rate"],
            "agent_invocations": metrics["agent_invocations"],
        },
        "betterstack": metrics["betterstack"],
        "ml_model": metrics["ml_model"],
        "last_event": metrics["last_event"],
    }


@router.post("/metrics/reset")
async def reset_metrics():
    """Reset all processing metrics."""
    event_processor.reset_metrics()
    return {"status": "success", "message": "Metrics reset"}


@router.get("/ml/status")
async def ml_status():
    """Get ML model and processor status."""
    metrics = event_processor.get_metrics()

    return {
        "status": "ready" if event_processor.is_ready else "not_loaded",
        "model": metrics["ml_model"],
        "thresholds": {
            "benign": event_processor.THRESHOLD_BENIGN,
            "certain": event_processor.THRESHOLD_CERTAIN,
        },
        "processing_modes": {
            "fast_path": "ML only, ~5ms, confidence ≥80%",
            "deep_path": "CyberAgent analysis, ~1-2s, confidence 50-80%",
        },
    }


# ── Incident Investigation Endpoints ──────────────────────────────────

@router.get("/incidents")
async def list_incidents():
    """List all correlated incidents."""
    return {
        "status": "success",
        "incidents": incident_manager.list_incidents(),
        "stats": incident_manager.get_stats(),
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get incident details."""
    incident = incident_manager.get_incident(incident_id)
    if not incident:
        return {"status": "error", "message": f"Incident {incident_id} not found"}
    return {"status": "success", "incident": incident}


@router.post("/incidents/{incident_id}/investigate")
async def investigate_incident(incident_id: str):
    """
    Run full investigation on a correlated incident.

    Performs:
        1. Timeline reconstruction
        2. IoC extraction
        3. MITRE ATT&CK mapping
        4. Incident classification
        5. Root cause analysis
        6. Impact assessment
        7. Response recommendations
    """
    result = incident_manager.investigate(incident_id)
    if not result:
        return {"status": "error", "message": f"Incident {incident_id} not found"}
    return {"status": "success", "investigation": result}


@router.get("/incidents/{incident_id}/report")
async def get_incident_report(incident_id: str):
    """Get human-readable investigation report."""
    report = incident_manager.get_report(incident_id)
    if not report:
        return {"status": "error", "message": f"Incident {incident_id} not found"}
    return {"status": "success", "report": report}
