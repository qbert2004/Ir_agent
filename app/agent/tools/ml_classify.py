"""
ML Classification Tool for CyberAgent ReAct loop.

Bridges the gap between CyberMLEngine (event-level classification) and
the ReAct agent — making ML predictions available as an agent tool.

This resolves the main architectural debt:
    Before: ML Engine and Agent ran as two independent pipelines
    After:  Agent can call ML classification as a tool step, then
            reason about the results with LLM + other tools

Usage in ReAct:
    Thought: I should check what the ML model thinks about this event.
    Action: ml_classify
    Action Input:
        event_type = process_creation
        process_name = powershell.exe
        command_line = powershell -enc SGVsbG8=
        event_id = 4688
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult

logger = logging.getLogger("ir-agent")


class MLClassifyTool(BaseTool):
    """
    Run the GradientBoosting ML classifier on a security event.

    Returns:
        - ML prediction: malicious / benign
        - Confidence score (0.0–1.0)
        - Triggered detection rules / features
        - Suggested MITRE techniques (from CyberMLEngine)
    """

    name = "ml_classify"
    description = (
        "Run the ML threat classifier on a security event to get a fast, "
        "data-driven verdict before applying deeper reasoning. "
        "Input the event fields (event_type, process_name, command_line, etc.). "
        "Returns: malicious/benign prediction, confidence score, and triggered indicators."
    )
    parameters = [
        ToolParameter(
            name="event_type",
            description="Event type (e.g. process_creation, network_connection, logon)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="process_name",
            description="Process name (e.g. powershell.exe, cmd.exe)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="command_line",
            description="Full command line string",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="event_id",
            description="Windows Event ID (e.g. 4688, 4624, 7045)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="parent_process",
            description="Parent process name",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="script_block_text",
            description="PowerShell script block content",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="source_ip",
            description="Source IP address (for network events)",
            type="string",
            required=False,
        ),
    ]

    def __init__(self):
        self._ml_detector = None
        self._ml_engine = None

    def _get_ml_detector(self):
        if self._ml_detector is None:
            try:
                from app.services.ml_detector import get_detector
                self._ml_detector = get_detector()
            except Exception as e:
                logger.warning("ML Detector not available: %s", e)
        return self._ml_detector

    def _get_ml_engine(self):
        if self._ml_engine is None:
            try:
                from app.ml.cyber_ml_engine import get_ml_engine
                self._ml_engine = get_ml_engine()
            except Exception as e:
                logger.warning("ML Engine not available: %s", e)
        return self._ml_engine

    def execute(self, **kwargs) -> ToolResult:
        # Build event dict from tool parameters
        event: Dict[str, Any] = {
            k: v for k, v in kwargs.items() if v is not None and v != ""
        }

        if not event:
            return ToolResult(
                success=False,
                output="No event data provided.",
                error="At least one event field required",
            )

        results = {}

        # ── Fast ML Detector (GradientBoosting) ──────────────────────────
        detector = self._get_ml_detector()
        if detector and detector.is_ready:
            try:
                is_malicious, confidence, reason = detector.predict(event)
                results["ml_detector"] = {
                    "verdict": "malicious" if is_malicious else "benign",
                    "confidence": round(confidence, 3),
                    "reason": reason,
                    "model": "GradientBoosting",
                }
            except Exception as e:
                results["ml_detector"] = {"error": str(e)}
        else:
            results["ml_detector"] = {"status": "model not loaded, using heuristics"}

        # ── CyberML Engine (MITRE + deep analysis) ────────────────────────
        engine = self._get_ml_engine()
        if engine:
            try:
                analysis = engine.analyze_event(event)
                mitre_hits = analysis.get("mitre_techniques", [])
                results["ml_engine"] = {
                    "threat_score": analysis.get("threat_score", 0),
                    "threat_level": analysis.get("threat_level", "unknown"),
                    "mitre_techniques": mitre_hits[:5],  # top 5
                    "key_indicators": analysis.get("key_indicators", [])[:5],
                }
            except Exception as e:
                results["ml_engine"] = {"error": str(e)}

        # ── Format output ─────────────────────────────────────────────────
        output_lines = [f"ML Analysis for event: {json.dumps(event, default=str)[:200]}"]

        det = results.get("ml_detector", {})
        if "verdict" in det:
            verdict = det["verdict"].upper()
            conf = det["confidence"]
            reason = det.get("reason", "")
            output_lines.append(
                f"\nML Detector: {verdict} (confidence={conf:.0%})"
                f"\n  Reason: {reason}"
            )

        eng = results.get("ml_engine", {})
        if "threat_score" in eng:
            output_lines.append(
                f"\nML Engine: threat_score={eng['threat_score']}/100, "
                f"level={eng['threat_level']}"
            )
            if eng.get("mitre_techniques"):
                techs = ", ".join(
                    f"{t.get('id', '?')} ({t.get('name', '?')})"
                    for t in eng["mitre_techniques"]
                )
                output_lines.append(f"  MITRE: {techs}")
            if eng.get("key_indicators"):
                output_lines.append(f"  Indicators: {', '.join(eng['key_indicators'])}")

        # Aggregate verdict
        is_malicious = det.get("verdict") == "malicious" or (eng.get("threat_score", 0) >= 60)

        output_lines.append(
            f"\nAggregated ML verdict: {'MALICIOUS' if is_malicious else 'BENIGN'}"
        )

        return ToolResult(
            success=True,
            output="\n".join(output_lines),
            data={
                "is_malicious": is_malicious,
                "ml_detector": results.get("ml_detector", {}),
                "ml_engine": results.get("ml_engine", {}),
                "event_processed": event,
            },
        )
