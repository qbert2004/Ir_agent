"""
ML Investigation API Router

Endpoints for ML-first investigation.
All analysis is done by ML engine, LLM only for report generation.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import logging

from app.ml.investigator import get_investigator, MLInvestigator
from app.ml.cyber_ml_engine import get_ml_engine

logger = logging.getLogger("ml-router")
router = APIRouter(prefix="/ml", tags=["ML Investigation"])


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class SecurityEvent(BaseModel):
    """Security event for analysis."""
    timestamp: Optional[str] = None
    event_id: Optional[int] = None
    hostname: Optional[str] = None
    event_type: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_image: Optional[str] = None
    user: Optional[str] = None
    logon_type: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    source_ip: Optional[str] = None
    channel: Optional[str] = "Security"


class InvestigationRequest(BaseModel):
    """Request to start ML investigation."""
    incident_id: str = Field(..., description="Unique incident identifier")
    events: List[Dict[str, Any]] = Field(..., description="List of security events")


class ClassifyEventRequest(BaseModel):
    """Request to classify a single event."""
    event: Dict[str, Any]


class InvestigationSummary(BaseModel):
    """Summary of investigation result."""
    incident_id: str
    incident_type: str
    incident_type_confidence: float
    threat_level: str
    threat_score: float
    total_events: int
    malicious_events: int
    techniques_count: int
    iocs_count: int
    affected_hosts: List[str]
    key_findings: List[str]
    recommended_actions: List[str]


class ClassificationResult(BaseModel):
    """Event classification result."""
    label: str
    confidence: float
    probabilities: Dict[str, float]
    explanation: str


class MITRETechniqueResult(BaseModel):
    """MITRE technique mapping result."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: List[str]


class IoCResult(BaseModel):
    """IoC extraction result."""
    type: str
    value: str
    confidence: float
    context: str


class ExplainRequest(BaseModel):
    """Request for ML explainability via LIME."""
    event: Dict[str, Any] = Field(..., description="Security event to explain")
    num_features: int = Field(default=10, ge=1, le=41, description="Top features to show")
    num_samples: int = Field(default=500, ge=100, le=2000, description="LIME sample count")


# ============================================================================
# ENDPOINTS
# ============================================================================

@router.post("/investigate", response_model=InvestigationSummary)
async def ml_investigate(request: InvestigationRequest):
    """
    Perform ML-based incident investigation.

    All analysis is done by ML engine:
    - Event classification
    - Incident type detection
    - MITRE ATT&CK mapping
    - IoC extraction
    - Timeline building
    - Threat scoring

    NO LLM is used in this endpoint.
    """
    investigator = get_investigator(use_llm=False)

    try:
        result = investigator.investigate(request.incident_id, request.events)

        return InvestigationSummary(
            incident_id=result.incident_id,
            incident_type=result.incident_type.value,
            incident_type_confidence=result.incident_type_confidence,
            threat_level=result.threat_level.value,
            threat_score=result.threat_score,
            total_events=result.total_events,
            malicious_events=result.malicious_events,
            techniques_count=len(result.mitre_techniques),
            iocs_count=len(result.iocs),
            affected_hosts=result.affected_hosts,
            key_findings=result.key_findings,
            recommended_actions=result.recommended_actions,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigate/{incident_id}/report")
async def get_ml_report(incident_id: str, format: str = "text", use_llm: bool = False):
    """
    Get investigation report.

    Args:
        incident_id: Incident identifier
        format: "text" or "json"
        use_llm: If True, use LLM for prose generation (default: False)

    LLM is used ONLY for:
    - Executive summary prose
    - Narrative descriptions
    - Detailed remediation text

    All analysis data comes from ML engine.
    """
    investigator = get_investigator()

    result = investigator.get_investigation(incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Investigation {incident_id} not found")

    report = investigator.get_report(incident_id, format=format, use_llm=use_llm)
    return {"incident_id": incident_id, "format": format, "report": report}


@router.post("/classify", response_model=ClassificationResult)
async def classify_event(request: ClassifyEventRequest):
    """
    Classify a single security event using ML model.

    Returns malicious/benign classification with confidence score.
    NO LLM is used - pure ML classification.
    """
    engine = get_ml_engine()

    try:
        result = engine.classify_event(request.event)

        return ClassificationResult(
            label=result.label,
            confidence=result.confidence,
            probabilities=result.probabilities,
            explanation=result.explanation,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mitre-map", response_model=List[MITRETechniqueResult])
async def map_to_mitre(request: ClassifyEventRequest):
    """
    Map security event to MITRE ATT&CK techniques.

    Uses rule-based pattern matching - NO LLM.
    """
    engine = get_ml_engine()

    try:
        techniques = engine.map_to_mitre(request.event)

        return [
            MITRETechniqueResult(
                technique_id=t.technique_id,
                technique_name=t.technique_name,
                tactic=t.tactic,
                confidence=t.confidence,
                evidence=t.evidence,
            )
            for t in techniques
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract-iocs", response_model=List[IoCResult])
async def extract_iocs(request: ClassifyEventRequest):
    """
    Extract Indicators of Compromise from event.

    Uses regex-based extraction - NO LLM.
    """
    engine = get_ml_engine()

    try:
        iocs = engine.extract_iocs(request.event)

        return [
            IoCResult(
                type=i.type,
                value=i.value,
                confidence=i.confidence,
                context=i.context,
            )
            for i in iocs
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigations")
async def list_investigations():
    """List all ML investigations."""
    investigator = get_investigator()
    return {"investigations": investigator.list_investigations()}


@router.get("/engine-info")
async def get_engine_info():
    """Get ML engine information."""
    engine = get_ml_engine()
    return engine.get_model_info()


@router.post("/explain")
async def explain_prediction(request: ExplainRequest):
    """
    Explain ML model prediction using LIME (Local Interpretable Model-agnostic Explanations).

    Returns top feature contributions that led to the prediction for this event.
    Useful for understanding WHY the model classified an event as malicious/benign.

    Example response:
    {
      "prediction": "malicious",
      "confidence": 0.87,
      "top_features": [
        {"feature": "base64_encoded", "value": 1.0, "contribution": 0.31, "direction": "malicious"},
        {"feature": "susp_process_partial", "value": 1.0, "contribution": 0.18, "direction": "malicious"},
        {"feature": "eid_1", "value": 0.0, "contribution": -0.05, "direction": "benign"}
      ]
    }
    """
    try:
        import numpy as np
        import pickle
        import os
        from pathlib import Path
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Import error: {e}")

    try:
        from lime.lime_tabular import LimeTabularExplainer
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="LIME not installed. Run: pip install lime"
        )

    # Load model and feature extractor
    ROOT = Path(__file__).parent.parent.parent
    model_path = ROOT / "models" / "gradient_boosting_production.pkl"
    if not model_path.exists():
        raise HTTPException(status_code=503, detail="Production ML model not found")

    try:
        with open(model_path, "rb") as f:
            payload = pickle.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model: {e}")

    model = payload["model"]
    scaler = payload["scaler"]
    feature_names = payload.get("feature_names", [f"f{i}" for i in range(41)])
    threshold = payload.get("threshold", 0.6)

    # Import feature extractor
    try:
        import sys
        sys.path.insert(0, str(ROOT))
        from scripts.retrain_source_split import extract_features_v3, FEATURE_NAMES_V3
        feature_names = FEATURE_NAMES_V3
    except ImportError:
        pass

    # Extract features for the event
    try:
        event_vector = np.array(extract_features_v3(request.event), dtype=np.float32)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Feature extraction failed: {e}")

    event_scaled = scaler.transform(event_vector.reshape(1, -1))

    # Current prediction
    prob = float(model.predict_proba(event_scaled)[0, 1])
    prediction = "malicious" if prob >= threshold else "benign"

    # Load training data sample for LIME background distribution
    train_path = ROOT / "training" / "data" / "train_events.json"
    try:
        import json
        with open(train_path, encoding="utf-8") as f:
            train_events_sample = json.load(f)
        # Use a random sample for LIME background
        import random
        rng = random.Random(42)
        sample_size = min(200, len(train_events_sample))
        bg_events = rng.sample(train_events_sample, sample_size)
        X_bg = np.array([extract_features_v3(e) for e in bg_events], dtype=np.float32)
        X_bg_scaled = scaler.transform(X_bg)
    except Exception as e:
        logger.warning(f"Could not load background data: {e}, using zeros")
        X_bg_scaled = np.zeros((100, len(feature_names)), dtype=np.float32)

    # Run LIME
    try:
        explainer = LimeTabularExplainer(
            training_data=X_bg_scaled,
            feature_names=feature_names,
            class_names=["benign", "malicious"],
            mode="classification",
            discretize_continuous=False,
            random_state=42,
        )

        explanation = explainer.explain_instance(
            data_row=event_scaled[0],
            predict_fn=model.predict_proba,
            num_features=request.num_features,
            num_samples=request.num_samples,
        )

        # Extract feature contributions
        lime_list = explanation.as_list(label=1)  # contributions toward "malicious"
        top_features = []
        for feat_name, weight in lime_list:
            # Find original feature value
            feat_idx = None
            for i, fn in enumerate(feature_names):
                if fn in feat_name or feat_name in fn:
                    feat_idx = i
                    break
            feat_val = float(event_vector[feat_idx]) if feat_idx is not None else None

            top_features.append({
                "feature": feat_name,
                "value": feat_val,
                "contribution": round(float(weight), 4),
                "direction": "malicious" if weight > 0 else "benign",
            })

    except Exception as e:
        logger.error(f"LIME explanation failed: {e}")
        raise HTTPException(status_code=500, detail=f"LIME failed: {e}")

    return {
        "prediction": prediction,
        "confidence": round(prob, 4),
        "threshold": threshold,
        "num_features_shown": len(top_features),
        "top_features": top_features,
        "interpretation": (
            f"Model classified this event as '{prediction}' with {prob*100:.1f}% confidence. "
            f"The top contributing feature is '{top_features[0]['feature'] if top_features else 'N/A'}' "
            f"which pushes toward '{top_features[0]['direction'] if top_features else 'N/A'}'."
        ),
        "event_summary": {
            "event_id": request.event.get("event_id"),
            "process_name": request.event.get("process_name", ""),
            "command_line": (request.event.get("command_line", "") or "")[:80],
        },
    }


@router.post("/investigate/example")
async def example_investigation():
    """
    Run example ransomware investigation.

    Demonstrates ML-based analysis without LLM.
    """
    events = [
        {
            "timestamp": "2024-01-15T08:30:00Z",
            "event_id": 4624,
            "hostname": "WS-USER01",
            "event_type": "logon",
            "user": "john.doe",
            "logon_type": 2,
        },
        {
            "timestamp": "2024-01-15T08:37:00Z",
            "event_id": 4688,
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "invoice_2024.exe",
            "parent_image": "outlook.exe",
            "user": "john.doe",
        },
        {
            "timestamp": "2024-01-15T08:38:00Z",
            "event_id": 3,
            "hostname": "WS-USER01",
            "event_type": "network",
            "destination_ip": "185.220.101.45",
            "destination_port": 443,
        },
        {
            "timestamp": "2024-01-15T08:40:00Z",
            "event_id": 4688,
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
        },
        {
            "timestamp": "2024-01-15T08:42:00Z",
            "event_id": 4688,
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
        },
        {
            "timestamp": "2024-01-15T08:45:00Z",
            "event_id": 11,
            "hostname": "WS-USER01",
            "event_type": "file_created",
            "file_path": "C:\\Users\\john.doe\\Desktop\\README_DECRYPT.txt",
        },
    ]

    investigator = get_investigator(use_llm=False)
    result = investigator.investigate("ML-EXAMPLE-001", events)

    return {
        "message": "Example ML investigation completed",
        "incident_id": result.incident_id,
        "incident_type": result.incident_type.value,
        "threat_level": result.threat_level.value,
        "threat_score": result.threat_score,
        "malicious_events": result.malicious_events,
        "techniques": [
            {"id": t.technique_id, "name": t.technique_name}
            for t in result.mitre_techniques
        ],
        "iocs_count": len(result.iocs),
        "key_findings": result.key_findings,
        "note": "All analysis performed by ML engine. Use /ml/investigate/{id}/report?use_llm=true for LLM-enhanced report."
    }
