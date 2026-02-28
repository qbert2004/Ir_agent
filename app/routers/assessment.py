"""
ThreatAssessment API Router

Endpoints for the unified threat scoring engine.

Routes:
    POST /assessment/analyze          — run full assessment from raw signals
    POST /assessment/analyze/event    — analyze a raw security event dict
    GET  /assessment/explain/{score}  — explain a numeric score
    GET  /assessment/schema           — weights, thresholds, arbitration rules info
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.assessment.threat_assessment import (
    AgentSignal,
    ConfidenceLevel,
    IoCSignal,
    MITRESignal,
    MLSignal,
    ThreatAssessment,
    ThreatAssessmentEngine,
    ThreatSeverity,
    get_assessment_engine,
)

logger = logging.getLogger("ir-agent")

router = APIRouter(prefix="/assessment", tags=["ThreatAssessment"])


# ── Request / Response schemas ────────────────────────────────────────────────

class MLSignalRequest(BaseModel):
    """Input from ML Classifier."""
    score: float = Field(..., ge=0.0, le=1.0, description="ML malicious probability (0–1)")
    is_malicious: bool
    reason: str = ""
    model_loaded: bool = True


class IoCSignalRequest(BaseModel):
    """Input from IoC Lookup providers."""
    score: float = Field(..., ge=0.0, le=1.0, description="Aggregated IoC threat score (0–1)")
    is_malicious: bool
    providers_hit: List[str] = Field(default_factory=list, description="e.g. ['VirusTotal', 'AbuseIPDB']")
    indicator_count: int = Field(default=0, ge=0)


class MITRESignalRequest(BaseModel):
    """Input from MITRE ATT&CK mapper."""
    techniques: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of matched MITRE techniques with id, name, confidence fields"
    )
    tactic_coverage: List[str] = Field(default_factory=list)
    max_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    has_lateral_movement: bool = False
    has_credential_access: bool = False
    has_impact: bool = False


class AgentSignalRequest(BaseModel):
    """Input from LLM ReAct agent."""
    verdict: str = Field(..., description="MALICIOUS | SUSPICIOUS | FALSE_POSITIVE | UNKNOWN")
    confidence: float = Field(..., ge=0.0, le=1.0)
    tools_used: List[str] = Field(default_factory=list)
    reasoning_steps: int = Field(default=0, ge=0)


class AssessmentRequest(BaseModel):
    """
    Full assessment request.

    All signals are optional — the engine works with partial data.
    Provide at least one signal for meaningful results.
    """
    ml: Optional[MLSignalRequest] = None
    ioc: Optional[IoCSignalRequest] = None
    mitre: Optional[MITRESignalRequest] = None
    agent: Optional[AgentSignalRequest] = None
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional event context (hostname, user, command_line, etc.)"
    )


class RawEventRequest(BaseModel):
    """
    Analyze a raw security event dict.

    The endpoint extracts available signals from the event and runs assessment.
    Useful when you have an event but haven't pre-computed signals.
    """
    event: Dict[str, Any] = Field(..., description="Raw security event dictionary")
    run_ml: bool = Field(default=True, description="Run ML classifier on event")
    run_mitre: bool = Field(default=True, description="Run MITRE mapper on event")


class AssessmentResponse(BaseModel):
    """Unified assessment result."""
    final_score: float
    severity: str
    confidence_level: str
    score_breakdown: Dict[str, float]
    sources_available: List[str]
    sources_agreeing: List[str]
    arbitration_rules: List[str]
    explanation: str
    explanation_trace: List[str]
    recommended_action: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _req_to_ml(req: Optional[MLSignalRequest]) -> Optional[MLSignal]:
    if req is None:
        return None
    return MLSignal(
        score=req.score,
        is_malicious=req.is_malicious,
        reason=req.reason,
        model_loaded=req.model_loaded,
    )


def _req_to_ioc(req: Optional[IoCSignalRequest]) -> Optional[IoCSignal]:
    if req is None:
        return None
    return IoCSignal(
        score=req.score,
        is_malicious=req.is_malicious,
        providers_hit=req.providers_hit,
        indicator_count=req.indicator_count,
    )


def _req_to_mitre(req: Optional[MITRESignalRequest]) -> Optional[MITRESignal]:
    if req is None:
        return None
    return MITRESignal(
        techniques=req.techniques,
        tactic_coverage=req.tactic_coverage,
        max_confidence=req.max_confidence,
        has_lateral_movement=req.has_lateral_movement,
        has_credential_access=req.has_credential_access,
        has_impact=req.has_impact,
    )


def _req_to_agent(req: Optional[AgentSignalRequest]) -> Optional[AgentSignal]:
    if req is None:
        return None
    return AgentSignal(
        verdict=req.verdict,
        confidence=req.confidence,
        tools_used=req.tools_used,
        reasoning_steps=req.reasoning_steps,
    )


def _assessment_to_response(a: ThreatAssessment) -> AssessmentResponse:
    d = a.to_dict()
    return AssessmentResponse(
        final_score=d["final_score"],
        severity=d["severity"],
        confidence_level=d["confidence_level"],
        score_breakdown=d["score_breakdown"],
        sources_available=d["sources_available"],
        sources_agreeing=d["sources_agreeing"],
        arbitration_rules=d["arbitration_rules"],
        explanation=d["explanation"],
        explanation_trace=d["explanation_trace"],
        recommended_action=d["recommended_action"],
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=AssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Run ThreatAssessment from pre-computed signals",
    description=(
        "Accepts pre-computed signals from ML classifier, IoC lookup, "
        "MITRE mapper, and LLM agent. Returns unified threat assessment "
        "with explainability trace and recommended action. "
        "All signal fields are optional."
    ),
)
async def analyze(request: AssessmentRequest) -> AssessmentResponse:
    """
    Run threat assessment from pre-computed signals.

    Example curl:
    ```
    curl -X POST /assessment/analyze \\
      -H "Content-Type: application/json" \\
      -d '{
        "ml": {"score": 0.87, "is_malicious": true, "reason": "mimikatz pattern"},
        "ioc": {"score": 0.9, "is_malicious": true, "providers_hit": ["VirusTotal"]},
        "mitre": {
          "techniques": [{"id": "T1003", "name": "OS Credential Dumping", "confidence": 0.8}],
          "tactic_coverage": ["credential_access"],
          "max_confidence": 0.8,
          "has_credential_access": true
        }
      }'
    ```
    """
    if not any([request.ml, request.ioc, request.mitre, request.agent]):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one signal (ml, ioc, mitre, or agent) must be provided",
        )

    try:
        engine = get_assessment_engine()
        assessment = engine.assess(
            ml=_req_to_ml(request.ml),
            ioc=_req_to_ioc(request.ioc),
            mitre=_req_to_mitre(request.mitre),
            agent=_req_to_agent(request.agent),
            context=request.context,
        )
        logger.info(
            "assessment.analyze: score=%.1f severity=%s confidence=%s",
            assessment.final_score,
            assessment.severity.value,
            assessment.confidence_level.value,
        )
        return _assessment_to_response(assessment)

    except Exception as e:
        logger.error("assessment.analyze error: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Assessment failed: {str(e)}",
        )


@router.post(
    "/analyze/event",
    response_model=AssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Run ThreatAssessment on a raw security event",
    description=(
        "Accepts a raw security event dict and automatically extracts ML and MITRE signals. "
        "Runs the full assessment pipeline without requiring pre-computed signals."
    ),
)
async def analyze_event(request: RawEventRequest) -> AssessmentResponse:
    """
    Run assessment directly from a raw security event.

    Internally calls:
      1. MLAttackDetector.predict() if run_ml=True
      2. CyberMLEngine.map_to_mitre() if run_mitre=True
      3. ThreatAssessmentEngine.assess()

    Does NOT run the LLM agent (too slow for synchronous API call).
    Use POST /agent/query for agent analysis.
    """
    event = request.event

    ml_signal: Optional[MLSignal] = None
    mitre_signal: Optional[MITRESignal] = None

    # ── ML signal ─────────────────────────────────────────────────────────────
    if request.run_ml:
        try:
            from app.ml.attack_detector import MLAttackDetector
            detector = MLAttackDetector()
            if detector.is_ready:
                result = detector.predict(event)
                ml_signal = MLSignal(
                    score=float(result.get("confidence", 0.5)),
                    is_malicious=result.get("label") == "malicious",
                    reason=result.get("reason", ""),
                    model_loaded=True,
                )
            else:
                # Heuristic fallback
                from app.ml.cyber_ml_engine import get_ml_engine
                ml_engine = get_ml_engine()
                ml_result = ml_engine.analyze_event(event)
                confidence = float(ml_result.get("confidence_score", 0.3))
                is_mal = ml_result.get("is_malicious", False)
                ml_signal = MLSignal(
                    score=confidence,
                    is_malicious=is_mal,
                    reason=ml_result.get("primary_indicator", "heuristic"),
                    model_loaded=False,
                )
        except Exception as e:
            logger.warning("assessment.analyze_event: ML extraction failed: %s", e)

    # ── MITRE signal ──────────────────────────────────────────────────────────
    if request.run_mitre:
        try:
            from app.ml.cyber_ml_engine import get_ml_engine
            ml_engine = get_ml_engine()
            techniques = ml_engine.map_to_mitre(event)

            if techniques:
                tactic_coverage = list({t.get("tactic", "") for t in techniques if t.get("tactic")})
                max_conf = max((t.get("confidence", 0) for t in techniques), default=0.0)
                tactics_lower = [tc.lower() for tc in tactic_coverage]
                mitre_signal = MITRESignal(
                    techniques=techniques,
                    tactic_coverage=tactic_coverage,
                    max_confidence=max_conf,
                    has_lateral_movement="lateral_movement" in tactics_lower,
                    has_credential_access="credential_access" in tactics_lower,
                    has_impact="impact" in tactics_lower,
                )
        except Exception as e:
            logger.warning("assessment.analyze_event: MITRE extraction failed: %s", e)

    # ── Validate: at least one signal ─────────────────────────────────────────
    if ml_signal is None and mitre_signal is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not extract any signals from the event. Check that ML engine is available.",
        )

    # ── Run assessment ────────────────────────────────────────────────────────
    try:
        engine = get_assessment_engine()
        assessment = engine.assess(
            ml=ml_signal,
            mitre=mitre_signal,
            context=event,
        )
        logger.info(
            "assessment.analyze_event: score=%.1f severity=%s",
            assessment.final_score,
            assessment.severity.value,
        )
        return _assessment_to_response(assessment)

    except Exception as e:
        logger.error("assessment.analyze_event error: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Assessment failed: {str(e)}",
        )


@router.get(
    "/explain/{score}",
    status_code=status.HTTP_200_OK,
    summary="Explain what a numeric threat score means",
)
async def explain_score(score: float) -> Dict[str, Any]:
    """
    Returns severity label, confidence bands, and recommended action
    for a given numeric score (0–100).

    Useful for UI tooltips and documentation.
    """
    if not (0 <= score <= 100):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Score must be between 0 and 100",
        )

    severity = ThreatSeverity.from_score(score)

    # Map to description
    descriptions = {
        ThreatSeverity.CRITICAL: "Immediate threat requiring emergency response",
        ThreatSeverity.HIGH:     "Significant threat requiring analyst attention within 1 hour",
        ThreatSeverity.MEDIUM:   "Suspicious activity warranting investigation within business hours",
        ThreatSeverity.LOW:      "Low-confidence indicator, monitor for recurrence",
        ThreatSeverity.INFO:     "Informational event, likely benign",
    }

    # Score ranges
    ranges = {
        ThreatSeverity.CRITICAL: "85–100",
        ThreatSeverity.HIGH:     "65–84",
        ThreatSeverity.MEDIUM:   "45–64",
        ThreatSeverity.LOW:      "25–44",
        ThreatSeverity.INFO:     "0–24",
    }

    engine = get_assessment_engine()

    return {
        "score": round(score, 1),
        "severity": severity.value,
        "severity_range": ranges[severity],
        "description": descriptions[severity],
        "actions": {
            "high_confidence":   engine._recommend_action(severity, ConfidenceLevel.HIGH),
            "medium_confidence": engine._recommend_action(severity, ConfidenceLevel.MEDIUM),
            "low_confidence":    engine._recommend_action(severity, ConfidenceLevel.LOW),
        },
    }


@router.get(
    "/schema",
    status_code=status.HTTP_200_OK,
    summary="ThreatAssessment Engine configuration and schema",
    tags=["ThreatAssessment", "Observability"],
)
async def assessment_schema() -> Dict[str, Any]:
    """
    Returns the engine's weights, severity thresholds, arbitration rules,
    and supported verdict types.

    Use this endpoint to understand how scores are computed.
    """
    return {
        "version": "1.0",
        "signal_weights": {
            "ml":    {"weight": 0.35, "description": "GradientBoosting ML classifier score"},
            "ioc":   {"weight": 0.30, "description": "IoC lookup aggregated score (VirusTotal + AbuseIPDB)"},
            "mitre": {"weight": 0.20, "description": "MITRE ATT&CK technique density and tactic coverage"},
            "agent": {"weight": 0.15, "description": "LLM ReAct agent verdict (lowest weight — LLM can hallucinate)"},
        },
        "severity_thresholds": {
            "critical": {"min": 85, "max": 100, "response": "Immediate"},
            "high":     {"min": 65, "max": 84,  "response": "Within 1 hour"},
            "medium":   {"min": 45, "max": 64,  "response": "Within business hours"},
            "low":      {"min": 25, "max": 44,  "response": "Monitor"},
            "info":     {"min": 0,  "max": 24,  "response": "No action"},
        },
        "arbitration_rules": [
            {
                "id":          "R1",
                "type":        "escalation",
                "description": "≥2 IoC providers confirmed malicious → score forced ≥85 (CRITICAL)",
                "trigger":     "ioc.providers_hit >= 2 AND ioc.is_malicious",
            },
            {
                "id":          "R2",
                "type":        "escalation",
                "description": "Credential dump pattern in ML reason → score ≥80",
                "trigger":     "ml.reason contains [lsass, sekurlsa, credential, dump]",
            },
            {
                "id":          "R3",
                "type":        "escalation",
                "description": "MITRE lateral_movement + credential_access combo → score ≥65 (HIGH)",
                "trigger":     "mitre.has_lateral_movement AND mitre.has_credential_access",
            },
            {
                "id":          "R4",
                "type":        "escalation",
                "description": "MITRE impact tactic detected → score ≥65",
                "trigger":     "mitre.has_impact",
            },
            {
                "id":          "R5",
                "type":        "bonus",
                "description": "All 3+ sources agree on malicious → +10% bonus",
                "trigger":     "ml.is_malicious AND ioc.is_malicious AND agent.verdict == MALICIOUS",
            },
            {
                "id":          "R6",
                "type":        "downgrade",
                "description": "Agent HIGH_CONFIDENCE FALSE_POSITIVE + ML < 0.6 → score capped at 25",
                "trigger":     "agent.verdict == FALSE_POSITIVE AND agent.confidence >= 0.7 AND ml.score < 0.6",
            },
            {
                "id":          "R7",
                "type":        "downgrade",
                "description": "IoC clean + Agent FALSE_POSITIVE + ML uncertain → score capped at 40",
                "trigger":     "NOT ioc.is_malicious AND agent.verdict == FALSE_POSITIVE AND 0.5 <= ml.score <= 0.7",
            },
        ],
        "confidence_levels": {
            "high":   "≥3 sources available and majority agree",
            "medium": "≥2 sources with partial agreement OR arbitration rule fired",
            "low":    "Single source or strong disagreement between sources",
        },
        "agent_verdicts": ["MALICIOUS", "SUSPICIOUS", "FALSE_POSITIVE", "UNKNOWN"],
        "note": "Weights are redistributed proportionally when sources are unavailable.",
    }
