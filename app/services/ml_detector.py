"""
Unified ML Attack Detector for IR-Agent
Filters incoming events - only malicious go to Better Stack
Trained on EVTX-ATTACK-SAMPLES dataset (4,633 real attack events)
"""

import os
import pickle
import logging
from typing import Tuple, Dict, Any, Optional

logger = logging.getLogger("ir-agent")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "gradient_boosting_model.pkl")


class MLAttackDetector:
    """
    ML-based attack detector for Windows security events.

    Usage:
        detector = get_detector()
        is_malicious, confidence, reason = detector.predict(event)

        if is_malicious:
            # Send to Better Stack
    """

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self.model = None
        self.scaler = None
        self.metrics = {}
        self._loaded = False

        self.suspicious_keywords = [
            'mimikatz', 'invoke-', 'powershell', 'bypass', 'hidden', 'encoded',
            'downloadstring', 'iex', 'webclient', 'frombase64', 'empire',
            'cobalt', 'meterpreter', 'reverse', 'shell', 'payload', 'exploit',
            'dump', 'lsass', 'sekurlsa', 'wmic', 'psexec', 'nc.exe', 'netcat'
        ]

        self.suspicious_processes = [
            'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta',
            'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'msiexec'
        ]

        self.high_risk_event_ids = [
            4688, 4689, 4624, 4625, 4648, 4672,
            4698, 4699, 4700, 4701, 4702, 7045,
            4104, 4103, 1, 3, 7, 8, 10, 11, 12, 13
        ]

        self._load_model()

    def _load_model(self) -> bool:
        """Load trained model."""
        paths = [
            MODEL_PATH,
            "models/gradient_boosting_model.pkl",
            "models/random_forest_model.pkl",
        ]

        for path in paths:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        data = pickle.load(f)
                    self.model = data['model']
                    self.scaler = data['scaler']
                    self.metrics = data.get('metrics', {})
                    self._loaded = True
                    logger.info(f"ML Detector loaded: {path} (F1={self.metrics.get('f1', 'N/A'):.2%})")
                    return True
                except Exception as e:
                    logger.warning(f"Failed to load {path}: {e}")

        logger.warning("No ML model found - using heuristic detection")
        return False

    def _extract_features(self, event: Dict[str, Any]) -> list:
        """Extract features matching training format."""
        event_id = int(event.get('event_id', event.get('EventID', 0)) or 0)
        process = str(event.get('process_name', event.get('ProcessName', event.get('Image', '')))).lower()
        cmdline = str(event.get('command_line', event.get('CommandLine', ''))).lower()
        parent = str(event.get('parent_image', event.get('ParentImage', ''))).lower()
        user = str(event.get('user', event.get('SubjectUserName', event.get('TargetUserName', '')))).upper()
        logon_type = int(event.get('logon_type', event.get('LogonType', 0)) or 0)
        dest_port = int(event.get('destination_port', event.get('DestinationPort', 0)) or 0)
        channel = str(event.get('channel', event.get('Channel', 'Security')))

        return [
            event_id,
            int(event_id in self.high_risk_event_ids),
            hash(channel) % 12,
            int(any(p in process for p in self.suspicious_processes)),
            len(cmdline),
            sum(1 for kw in self.suspicious_keywords if kw in cmdline),
            int(any(x in cmdline for x in ['-enc', '-e ', 'base64', 'frombase64'])),
            int(any(x in cmdline for x in ['download', 'webclient', 'invoke-webrequest'])),
            int(any(x in cmdline for x in ['-w hidden', '-windowstyle h', 'hidden'])),
            int(any(p in parent for p in self.suspicious_processes)),
            logon_type,
            int(logon_type in [3, 10]),
            int(user in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']),
            int('ADMIN' in user),
            dest_port,
            int(dest_port in [443, 8443, 8080, 4444, 5555, 1337]),
        ]

    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Predict if event is malicious.

        Returns:
            (is_malicious, confidence, reason)
        """
        features = self._extract_features(event)

        if self._loaded and self.model is not None:
            try:
                import numpy as np
                X = np.array([features])
                X_scaled = self.scaler.transform(X)
                proba = self.model.predict_proba(X_scaled)[0][1]
                is_malicious = proba >= self.threshold
                reason = self._build_reason(features, proba)
                return is_malicious, float(proba), reason
            except Exception as e:
                logger.error(f"ML prediction failed: {e}")

        return self._heuristic_predict(features)

    def _heuristic_predict(self, features: list) -> Tuple[bool, float, str]:
        """Fallback heuristic detection."""
        score = 0.0
        reasons = []

        if features[5] > 0:  # suspicious_keyword_count
            score += 0.25 * min(features[5], 3)
            reasons.append(f"{features[5]} suspicious keywords")
        if features[3]:  # is_suspicious_process
            score += 0.15
            reasons.append("LOLBin")
        if features[6]:  # has_base64
            score += 0.2
            reasons.append("base64")
        if features[7]:  # has_download
            score += 0.15
            reasons.append("download")
        if features[8]:  # has_hidden
            score += 0.15
            reasons.append("hidden")
        if features[9]:  # parent_is_suspicious
            score += 0.1
            reasons.append("suspicious parent")

        score = min(score, 1.0)
        is_malicious = score >= self.threshold
        reason = f"Heuristic: {', '.join(reasons)}" if reasons else "No indicators"
        return is_malicious, score, reason

    def _build_reason(self, features: list, confidence: float) -> str:
        """Build explanation string."""
        indicators = []
        if features[5] > 0:
            indicators.append(f"{features[5]} malicious keywords")
        if features[3]:
            indicators.append("LOLBin process")
        if features[6]:
            indicators.append("base64 encoded")
        if features[7]:
            indicators.append("download command")
        if features[8]:
            indicators.append("hidden window")
        if features[9]:
            indicators.append("suspicious parent")
        if features[15]:
            indicators.append(f"C2 port {features[14]}")

        if indicators:
            return f"ML ({confidence:.0%}): {', '.join(indicators)}"
        return f"ML ({confidence:.0%}): pattern match"

    @property
    def is_ready(self) -> bool:
        return self._loaded

    def get_stats(self) -> Dict:
        return {
            "model_loaded": self._loaded,
            "threshold": self.threshold,
            "metrics": self.metrics
        }


# Singleton
_detector: Optional[MLAttackDetector] = None


def get_detector(threshold: float = 0.5) -> MLAttackDetector:
    """Get ML detector singleton."""
    global _detector
    if _detector is None:
        _detector = MLAttackDetector(threshold=threshold)
    return _detector
