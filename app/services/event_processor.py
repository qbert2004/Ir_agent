"""
Event Processing Orchestrator - Hybrid ML + Agent Architecture

Fast-path (ML only, ~5ms): High-volume filtering
Deep-path (CyberAgent, ~1-2s): Uncertain cases (50-80% confidence)

Flow:
    Event → ML Classification
        → BENIGN (<50%): discard
        → HIGH CONFIDENCE (≥80%): forward to Better Stack
        → UNCERTAIN (50-80%): Agent deep analysis → forward
"""

import json
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

from app.services.ml_detector import get_detector, MLAttackDetector
from app.services.metrics import metrics_service
from app.services.incident_manager import get_incident_manager
from app.common.betterstack_forwarder import BetterStackForwarder
from app.assessment.threat_assessment import (
    ThreatAssessmentEngine, ThreatAssessment,
    MLSignal, IoCSignal, MITRESignal, AgentSignal,
    get_assessment_engine,
)

logger = logging.getLogger("ir-agent")


class EventProcessor:
    """
    Hybrid event processor combining fast ML filtering with deep agent analysis.

    Architecture:
        1. Fast-path: ML model filters obvious benign/malicious events (~5ms)
        2. Deep-path: CyberAgent investigates ONLY anomalous uncertain cases (~1-2s)
    """

    # Confidence thresholds
    THRESHOLD_BENIGN = 0.5       # Below this = benign, discard
    THRESHOLD_CERTAIN = 0.8     # Above this = definitely malicious, fast-forward
    # Between THRESHOLD_BENIGN and THRESHOLD_CERTAIN = uncertain
    # Agent called ONLY for anomalous events in this range

    # Anomaly indicators - only these trigger Agent analysis
    SUSPICIOUS_KEYWORDS = [
        'mimikatz', 'invoke-', 'powershell', 'bypass', 'hidden', 'encoded',
        'downloadstring', 'iex', 'webclient', 'frombase64', 'empire',
        'cobalt', 'meterpreter', 'reverse', 'shell', 'payload', 'exploit',
        'dump', 'lsass', 'sekurlsa', 'psexec', 'nc.exe', 'netcat',
        '-enc', '-e ', 'base64', 'procdump', 'ntds.dit'
    ]

    SUSPICIOUS_PROCESSES = [
        'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta',
        'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'msiexec'
    ]

    HIGH_RISK_EVENT_IDS = [4688, 4624, 4625, 4648, 4672, 7045, 4104, 4103]

    def __init__(self):
        self._ml_detector: Optional[MLAttackDetector] = None
        self._betterstack: Optional[BetterStackForwarder] = None
        self._agent_service = None  # Lazy loaded to avoid circular imports
        self._incident_manager = get_incident_manager()
        self._assessment_engine: ThreatAssessmentEngine = get_assessment_engine()

        # Metrics
        self.metrics = {
            "total_events": 0,
            "benign_filtered": 0,
            "malicious_fast_path": 0,
            "malicious_deep_path": 0,
            "agent_invocations": 0,
            "sent_to_betterstack": 0,
            "failed": 0,
            "last_event_time": None,
        }

        self._initialize()

    def _initialize(self):
        """Initialize components."""
        # ML Detector
        self._ml_detector = get_detector(threshold=self.THRESHOLD_BENIGN)

        # Better Stack
        token = os.getenv("BETTER_STACK_SOURCE_TOKEN")
        if token:
            self._betterstack = BetterStackForwarder(token)
            logger.info("EventProcessor: Better Stack forwarder initialized")
        else:
            logger.warning("EventProcessor: No BETTER_STACK_SOURCE_TOKEN - events won't be forwarded")

    def _get_agent_service(self):
        """Lazy load agent service to avoid circular imports."""
        if self._agent_service is None:
            from app.services.agent_service import agent_service
            self._agent_service = agent_service
        return self._agent_service

    async def classify_and_forward(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point: classify event, assess threat, and forward if malicious.

        Flow:
            1. Fast ML classification (GradientBoosting)
            2. ThreatAssessment (ML signal → unified score)
            3. BENIGN (<50%) → discard
            4. HIGH CONFIDENCE (≥80%) → fast-path + ThreatAssessment
            5. UNCERTAIN (50-80%) + anomalous → deep-path Agent → ThreatAssessment fusion
        """
        self.metrics["total_events"] += 1
        self.metrics["last_event_time"] = datetime.utcnow().isoformat()

        event_id = event.get("event_id", str(uuid.uuid4())[:8])

        try:
            # Step 1: Fast-path ML classification
            is_malicious, confidence, reason = self._ml_detector.predict(event)

            # BENIGN - discard
            if not is_malicious:
                self.metrics["benign_filtered"] += 1
                logger.debug(f"BENIGN [{confidence:.0%}]: {event.get('process_name', 'unknown')}")
                return {
                    "status": "filtered",
                    "classification": "benign",
                    "confidence": confidence,
                    "path": "fast",
                }

            # Step 1.5: Correlate into incident
            incident_id = self._incident_manager.correlate_event(
                event, ml_confidence=confidence, ml_reason=reason
            )

            # Step 1.6: Quick ThreatAssessment with ML signal only (fast-path)
            ml_signal = MLSignal(
                score=confidence,
                is_malicious=is_malicious,
                reason=reason,
                model_loaded=self._ml_detector.is_ready,
            )

            # Step 2: Determine processing path
            if confidence >= self.THRESHOLD_CERTAIN:
                # HIGH CONFIDENCE — fast forward with ML-only assessment
                assessment = self._assessment_engine.assess(ml=ml_signal)
                result = await self._fast_path_forward(
                    event, confidence, reason, assessment=assessment
                )
                self.metrics["malicious_fast_path"] += 1
            else:
                # UNCERTAIN (50-80%) — check if truly anomalous
                if self._is_anomalous(event):
                    # ANOMALOUS — deep Agent analysis + full ThreatAssessment fusion
                    result = await self._deep_path_analyze(
                        event, confidence, reason, event_id, ml_signal=ml_signal
                    )
                    self.metrics["malicious_deep_path"] += 1
                else:
                    # NOT ANOMALOUS — fast forward with ML-only assessment
                    assessment = self._assessment_engine.assess(ml=ml_signal)
                    result = await self._fast_path_forward(
                        event, confidence, reason, assessment=assessment
                    )
                    self.metrics["malicious_fast_path"] += 1

            return result

        except Exception as e:
            logger.error(f"Event processing error: {e}")
            self.metrics["failed"] += 1
            return {
                "status": "error",
                "error": str(e),
            }

    async def _fast_path_forward(
        self,
        event: Dict[str, Any],
        confidence: float,
        reason: str,
        assessment: Optional["ThreatAssessment"] = None,
    ) -> Dict[str, Any]:
        """
        Fast-path: High-confidence malicious events go directly to Better Stack.
        Includes ThreatAssessment in enriched event payload.
        """
        enriched = self._enrich_event(
            event, confidence, reason, path="fast", assessment=assessment
        )
        success = await self._forward_to_betterstack(enriched)

        severity = assessment.severity.value if assessment else "unknown"
        logger.info(
            f"FAST-PATH [{confidence:.0%}] severity={severity}: "
            f"{event.get('process_name', 'unknown')} - {reason}"
        )

        # ── Persist to DB ────────────────────────────────────────────────────
        try:
            from app.db.event_store import event_store
            await event_store.save_event(
                event=event,
                ml_confidence=confidence,
                ml_label="malicious",
                ml_reason=reason,
                processing_path="fast",
                threat_score=assessment.final_score if assessment else None,
                threat_severity=assessment.severity.value if assessment else None,
                assessment_json=json.dumps(assessment.to_dict()) if assessment else None,
            )
        except Exception as db_err:
            logger.warning("EventProcessor: DB save failed (fast-path): %s", db_err)

        result = {
            "status": "forwarded" if success else "forward_failed",
            "classification": "malicious",
            "confidence": confidence,
            "reason": reason,
            "path": "fast",
            "betterstack_sent": success,
        }
        if assessment:
            result["threat_assessment"] = assessment.to_dict()
        return result

    async def _deep_path_analyze(
        self,
        event: Dict[str, Any],
        ml_confidence: float,
        ml_reason: str,
        event_id: str,
        ml_signal: Optional["MLSignal"] = None,
    ) -> Dict[str, Any]:
        """
        Deep-path: CyberAgent analysis + full ThreatAssessment fusion.

        Combines ML signal, Agent verdict, and MITRE data into
        a unified ThreatAssessment via the assessment engine.
        """
        self.metrics["agent_invocations"] += 1

        try:
            agent = self._get_agent_service()

            event_summary = self._build_event_summary(event)
            prompt = (
                f"Investigate this security event that has {ml_confidence:.0%} ML confidence:\n\n"
                f"{event_summary}\n\n"
                f"ML Initial Assessment: {ml_reason}\n\n"
                f"Use ml_classify, lookup_ioc, mitre_lookup and other tools to determine "
                f"if this is truly malicious. "
                f"Provide your final verdict: MALICIOUS, SUSPICIOUS, or FALSE_POSITIVE."
            )

            session_id = f"event-{event_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            response = await agent.aquery(prompt, session_id=session_id)

            agent_verdict, agent_confidence = self._parse_agent_response(response.answer)

            # ── Build full ThreatAssessment with all available signals ──────
            agent_sig = AgentSignal(
                verdict=agent_verdict,
                confidence=agent_confidence,
                tools_used=response.tools_used,
                reasoning_steps=response.total_steps,
            )

            # Try to extract MITRE signal from ML engine
            mitre_sig = self._extract_mitre_signal(event)

            assessment = self._assessment_engine.assess(
                ml=ml_signal,
                agent=agent_sig,
                mitre=mitre_sig,
            )
            # ───────────────────────────────────────────────────────────────

            should_forward = assessment.severity.value in ("critical", "high", "medium")

            if should_forward:
                enriched = self._enrich_event(
                    event,
                    ml_confidence,
                    ml_reason,
                    path="deep",
                    agent_analysis={
                        "verdict": agent_verdict,
                        "confidence": agent_confidence,
                        "summary": response.answer[:500],
                        "tools_used": response.tools_used,
                        "steps": response.total_steps,
                    },
                    assessment=assessment,
                )
                success = await self._forward_to_betterstack(enriched)
            else:
                success = False

            logger.info(
                f"DEEP-PATH [{ml_confidence:.0%}→{agent_verdict}] "
                f"assessment={assessment.severity.value} "
                f"(score={assessment.final_score:.0f}): "
                f"{event.get('process_name', 'unknown')} - Tools: {response.tools_used}"
            )

            # ── Persist to DB ────────────────────────────────────────────────
            try:
                from app.db.event_store import event_store
                await event_store.save_event(
                    event=event,
                    ml_confidence=ml_confidence,
                    ml_label=agent_verdict.lower(),
                    ml_reason=ml_reason,
                    processing_path="deep",
                    threat_score=assessment.final_score,
                    threat_severity=assessment.severity.value,
                    assessment_json=json.dumps(assessment.to_dict()),
                )
            except Exception as db_err:
                logger.warning("EventProcessor: DB save failed (deep-path): %s", db_err)

            result = {
                "status": "forwarded" if should_forward and success else "analyzed",
                "classification": agent_verdict.lower(),
                "ml_confidence": ml_confidence,
                "ml_reason": ml_reason,
                "agent_verdict": agent_verdict,
                "agent_confidence": agent_confidence,
                "path": "deep",
                "tools_used": response.tools_used,
                "betterstack_sent": success if should_forward else False,
                "threat_assessment": assessment.to_dict(),
            }
            return result

        except Exception as e:
            logger.error(f"Deep-path agent error: {e}")
            # Fallback: forward with ML-only assessment
            fallback_assessment = self._assessment_engine.assess(ml=ml_signal)
            enriched = self._enrich_event(
                event, ml_confidence, ml_reason,
                path="deep-fallback", assessment=fallback_assessment
            )
            success = await self._forward_to_betterstack(enriched)
            return {
                "status": "forwarded_fallback" if success else "error",
                "classification": "malicious",
                "confidence": ml_confidence,
                "reason": ml_reason,
                "path": "deep-fallback",
                "error": str(e),
                "threat_assessment": fallback_assessment.to_dict(),
            }

    def _extract_mitre_signal(self, event: Dict[str, Any]) -> Optional["MITRESignal"]:
        """Extract MITRE signal from CyberMLEngine for ThreatAssessment fusion."""
        try:
            from app.ml.cyber_ml_engine import get_ml_engine
            engine = get_ml_engine()
            techniques = engine.map_to_mitre(event)
            if not techniques:
                return None

            tactic_coverage = list({t.tactic for t in techniques})
            return MITRESignal(
                techniques=[
                    {"id": t.technique_id, "name": t.technique_name,
                     "tactic": t.tactic, "confidence": t.confidence}
                    for t in techniques
                ],
                tactic_coverage=tactic_coverage,
                max_confidence=max((t.confidence for t in techniques), default=0.0),
                has_lateral_movement="lateral_movement" in tactic_coverage,
                has_credential_access="credential_access" in tactic_coverage,
                has_impact="impact" in tactic_coverage,
            )
        except Exception as e:
            logger.debug("MITRE signal extraction failed: %s", e)
            return None

    def _enrich_event(
        self,
        event: Dict[str, Any],
        confidence: float,
        reason: str,
        path: str,
        agent_analysis: Optional[Dict] = None,
        assessment: Optional["ThreatAssessment"] = None,
    ) -> Dict[str, Any]:
        """Enrich event with detection metadata and ThreatAssessment."""
        enriched = event.copy()

        enriched["ml_detection"] = {
            "is_malicious": True,
            "confidence": f"{confidence:.1%}",
            "reason": reason,
            "path": path,
        }

        if agent_analysis:
            enriched["agent_analysis"] = agent_analysis

        # Use ThreatAssessment severity for log level (more accurate than raw confidence)
        if assessment:
            severity_to_level = {
                "critical": "error", "high": "error",
                "medium": "warn",    "low": "info", "info": "info",
            }
            enriched["level"] = severity_to_level.get(assessment.severity.value, "warn")
            enriched["threat_score"] = assessment.final_score
            enriched["severity"] = assessment.severity.value
            enriched["threat_assessment"] = assessment.to_dict()
        else:
            enriched["level"] = "error" if confidence >= 0.8 else "warn" if confidence >= 0.6 else "info"

        process = event.get("process_name", "unknown")
        severity_str = f" [{assessment.severity.value.upper()}]" if assessment else ""
        if agent_analysis:
            enriched["message"] = (
                f"THREAT{severity_str} [{confidence:.0%}] {process} - "
                f"Agent: {agent_analysis.get('verdict', 'N/A')} - {reason}"
            )
        else:
            enriched["message"] = f"THREAT{severity_str} [{confidence:.0%}] {process} - {reason}"

        return enriched

    async def _forward_to_betterstack(self, event: Dict[str, Any]) -> bool:
        """Forward event to Better Stack."""
        if not self._betterstack:
            logger.debug("Better Stack not configured, skipping forward")
            return False

        try:
            success = await self._betterstack.send_event(event)
            if success:
                self.metrics["sent_to_betterstack"] += 1
                metrics_service.increment("sent_to_betterstack")
            else:
                self.metrics["failed"] += 1
                metrics_service.increment("failed_betterstack")
            return success
        except Exception as e:
            logger.error(f"Better Stack forward error: {e}")
            self.metrics["failed"] += 1
            return False

    def _is_anomalous(self, event: Dict[str, Any]) -> bool:
        """
        Check if event has anomalous indicators that warrant Agent analysis.
        Only truly suspicious events should trigger the Agent to avoid rate limits.
        """
        # Check command line for suspicious keywords
        cmdline = str(event.get("command_line", "")).lower()
        if any(kw in cmdline for kw in self.SUSPICIOUS_KEYWORDS):
            return True

        # Check script content (PowerShell)
        script = str(event.get("script_block_text", "")).lower()
        if any(kw in script for kw in self.SUSPICIOUS_KEYWORDS):
            return True

        # Check process name
        process = str(event.get("process_name", "")).lower()
        if any(p in process for p in self.SUSPICIOUS_PROCESSES):
            # Process is suspicious, but only if command line also has indicators
            if len(cmdline) > 100 or any(kw in cmdline for kw in ['-', '/', 'http', 'base64']):
                return True

        # Check for high-risk event IDs with suspicious context
        event_id = event.get("event_id", 0)
        try:
            event_id = int(event_id)
        except (ValueError, TypeError):
            event_id = 0

        if event_id in self.HIGH_RISK_EVENT_IDS:
            # Service installation (7045) - always anomalous
            if event_id == 7045:
                return True
            # PowerShell script block (4104) - check content
            if event_id == 4104 and len(script) > 200:
                return True
            # Failed logon (4625) from external IP
            if event_id == 4625:
                source_ip = event.get("source_ip", "")
                if source_ip and not source_ip.startswith(("10.", "192.168.", "172.")):
                    return True

        # Check for remote logon types
        logon_type = event.get("logon_type")
        if logon_type in [3, 10]:  # Network or RemoteInteractive
            source_ip = event.get("source_ip", "")
            if source_ip and not source_ip.startswith(("10.", "192.168.", "172.", "127.")):
                return True

        return False

    def _build_event_summary(self, event: Dict[str, Any]) -> str:
        """Build human-readable event summary for agent prompt."""
        lines = []

        fields = [
            ("Event ID", "event_id"),
            ("Event Type", "event_type"),
            ("Process", "process_name"),
            ("Command Line", "command_line"),
            ("Parent Process", "parent_image"),
            ("User", "user"),
            ("Hostname", "hostname"),
            ("Channel", "channel"),
            ("Logon Type", "logon_type"),
            ("Source IP", "source_ip"),
            ("Destination Port", "destination_port"),
        ]

        for label, key in fields:
            value = event.get(key)
            if value:
                lines.append(f"  {label}: {value}")

        return "\n".join(lines) if lines else "  (minimal event data)"

    def _parse_agent_response(self, answer: str) -> Tuple[str, float]:
        """
        Parse agent response to extract verdict.

        Returns:
            (verdict, confidence) where verdict is MALICIOUS/SUSPICIOUS/FALSE_POSITIVE
        """
        answer_upper = answer.upper()

        # Look for explicit verdicts
        if "MALICIOUS" in answer_upper:
            # Check if it's "NOT MALICIOUS"
            if "NOT MALICIOUS" in answer_upper or "NOT TRULY MALICIOUS" in answer_upper:
                return "FALSE_POSITIVE", 0.7
            return "MALICIOUS", 0.9
        elif "FALSE_POSITIVE" in answer_upper or "FALSE POSITIVE" in answer_upper:
            return "FALSE_POSITIVE", 0.8
        elif "SUSPICIOUS" in answer_upper:
            return "SUSPICIOUS", 0.6
        elif "BENIGN" in answer_upper:
            return "FALSE_POSITIVE", 0.7

        # Default to suspicious if no clear verdict
        return "SUSPICIOUS", 0.5

    def get_metrics(self) -> Dict[str, Any]:
        """Get processing metrics."""
        total = self.metrics["total_events"]
        benign = self.metrics["benign_filtered"]
        fast = self.metrics["malicious_fast_path"]
        deep = self.metrics["malicious_deep_path"]

        return {
            "total_processed": total,
            "benign_filtered": benign,
            "malicious_detected": fast + deep,
            "fast_path_count": fast,
            "deep_path_count": deep,
            "agent_invocations": self.metrics["agent_invocations"],
            "filter_rate": f"{benign/total*100:.1f}%" if total > 0 else "0%",
            "deep_path_rate": f"{deep/(fast+deep)*100:.1f}%" if (fast+deep) > 0 else "0%",
            "betterstack": {
                "enabled": self._betterstack is not None,
                "sent": self.metrics["sent_to_betterstack"],
                "failed": self.metrics["failed"],
            },
            "ml_model": self._ml_detector.get_stats() if self._ml_detector else {},
            "last_event": self.metrics["last_event_time"],
        }

    def reset_metrics(self):
        """Reset all metrics."""
        for key in self.metrics:
            if isinstance(self.metrics[key], int):
                self.metrics[key] = 0
            else:
                self.metrics[key] = None

    @property
    def is_ready(self) -> bool:
        """Check if processor is ready."""
        return self._ml_detector is not None and self._ml_detector.is_ready


# Singleton instance
_processor: Optional[EventProcessor] = None


def get_event_processor() -> EventProcessor:
    """Get singleton event processor."""
    global _processor
    if _processor is None:
        _processor = EventProcessor()
    return _processor
