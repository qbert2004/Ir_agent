"""
Cyber ML Engine - Core ML-based investigation without LLM dependency.

This engine performs ALL classification, analysis, and detection tasks
using trained ML models. LLM (Groq) is only used for final report generation.

Architecture:
    ML Engine (core logic)          →    LLM (text generation only)
    ├── EventClassifier                  ├── Executive Summary
    ├── IncidentTypeClassifier           ├── Recommendations text
    ├── MITRETechniqueMapper             └── Human-readable narrative
    ├── IoC Extractor (rule-based + ML)
    ├── TimelineBuilder
    └── ThreatScorer
"""

import os
import re
import json
import pickle
import logging
import hashlib
from typing import Dict, Any, List, Tuple, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from collections import defaultdict

import numpy as np

logger = logging.getLogger("cyber-ml-engine")


# ============================================================================
# DATA CLASSES
# ============================================================================

class IncidentType(Enum):
    """Incident types that can be classified by ML."""
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMMAND_AND_CONTROL = "command_and_control"
    RECONNAISSANCE = "reconnaissance"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class ClassificationResult:
    """Result of ML classification."""
    label: str
    confidence: float
    probabilities: Dict[str, float] = field(default_factory=dict)
    features_used: List[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class IoC:
    """Indicator of Compromise."""
    type: str  # ip, domain, hash_md5, hash_sha256, url, email, file_path, registry
    value: str
    confidence: float
    source_event_index: int = -1
    context: str = ""


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique mapping."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: List[str] = field(default_factory=list)


@dataclass
class TimelineEntry:
    """Entry in attack timeline."""
    timestamp: str
    hostname: str
    event_type: str
    description: str
    severity: ThreatLevel
    iocs: List[IoC] = field(default_factory=list)
    mitre_techniques: List[MITRETechnique] = field(default_factory=list)
    ml_confidence: float = 0.0
    event_index: int = -1


@dataclass
class MLInvestigationResult:
    """Complete ML-based investigation result."""
    incident_id: str
    incident_type: IncidentType
    incident_type_confidence: float
    threat_level: ThreatLevel
    threat_score: float  # 0-100

    timeline: List[TimelineEntry]
    iocs: List[IoC]
    mitre_techniques: List[MITRETechnique]
    affected_hosts: List[str]
    affected_users: List[str]

    # Statistics
    total_events: int
    malicious_events: int
    analysis_timestamp: str

    # For LLM report generation
    key_findings: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)


# ============================================================================
# MITRE ATT&CK KNOWLEDGE BASE (Rule-based, no LLM needed)
# ============================================================================

MITRE_PATTERNS = {
    # Credential Access
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "credential_access",
        "patterns": ["mimikatz", "sekurlsa", "lsass", "procdump.*lsass", "comsvcs.*minidump"],
        "processes": ["mimikatz.exe", "procdump.exe", "procdump64.exe"],
        "event_ids": [10, 4688],
    },
    "T1003.002": {
        "name": "Security Account Manager",
        "tactic": "credential_access",
        "patterns": ["reg.*save.*sam", "reg.*save.*system", "secretsdump"],
        "event_ids": [4688],
    },
    "T1003.003": {
        "name": "NTDS",
        "tactic": "credential_access",
        "patterns": ["ntdsutil", "vssadmin.*ntds", "ntds.dit"],
        "event_ids": [4688],
    },

    # Execution
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "execution",
        "patterns": ["powershell", "-enc", "-encodedcommand", "invoke-expression", "iex"],
        "processes": ["powershell.exe", "pwsh.exe"],
        "event_ids": [4688, 4104, 4103],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "execution",
        "patterns": ["cmd.*/c", "cmd.*/k"],
        "processes": ["cmd.exe"],
        "event_ids": [4688],
    },
    "T1204.002": {
        "name": "Malicious File",
        "tactic": "execution",
        "patterns": ["\.exe$", "\.dll$", "\.scr$", "\.bat$", "\.ps1$"],
        "parent_processes": ["outlook.exe", "winword.exe", "excel.exe"],
        "event_ids": [4688, 11],
    },

    # Persistence
    "T1547.001": {
        "name": "Registry Run Keys",
        "tactic": "persistence",
        "patterns": ["currentversion.*run", "hklm.*run", "hkcu.*run"],
        "event_ids": [13, 4688],
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "persistence",
        "patterns": ["schtasks", "at.exe"],
        "processes": ["schtasks.exe", "at.exe"],
        "event_ids": [4688, 4698, 4699, 4700, 4701, 4702],
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactic": "persistence",
        "patterns": ["sc.*create", "new-service"],
        "event_ids": [4688, 7045],
    },

    # Defense Evasion
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactic": "defense_evasion",
        "patterns": ["wevtutil.*cl", "clear-eventlog"],
        "event_ids": [1102, 4688],
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "defense_evasion",
        "patterns": ["set-mppreference", "disable.*defender", "tamperprotection"],
        "event_ids": [4688],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "defense_evasion",
        "patterns": ["base64", "-enc", "frombase64string", "gzipstream"],
        "event_ids": [4688, 4104],
    },

    # Lateral Movement
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "lateral_movement",
        "patterns": ["mstsc", "rdp"],
        "logon_types": [10],
        "event_ids": [4624, 4625],
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "lateral_movement",
        "patterns": ["\\\\\\\\.*\\\\c\\$", "\\\\\\\\.*\\\\admin\\$", "psexec", "wmic.*process.*call.*create"],
        "logon_types": [3],
        "event_ids": [4624, 4688],
    },
    "T1021.006": {
        "name": "Windows Remote Management",
        "tactic": "lateral_movement",
        "patterns": ["winrm", "invoke-command", "enter-pssession", "wsmprovhost"],
        "event_ids": [4688],
    },

    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "patterns": ["vssadmin.*delete.*shadows", "wmic.*shadowcopy.*delete", "bcdedit.*recoveryenabled.*no"],
        "file_extensions": [".encrypted", ".locked", ".crypto", ".crypt"],
        "event_ids": [4688],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "impact",
        "patterns": ["vssadmin.*delete", "wbadmin.*delete", "bcdedit.*set.*recoveryenabled"],
        "event_ids": [4688],
    },

    # Command and Control
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "command_and_control",
        "patterns": ["invoke-webrequest", "downloadstring", "webclient", "curl", "wget"],
        "ports": [80, 443, 8080, 8443],
        "event_ids": [3, 4688],
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "command_and_control",
        "ports": [443, 8443, 4444, 5555],
        "event_ids": [3],
    },

    # Discovery
    "T1087.001": {
        "name": "Local Account",
        "tactic": "discovery",
        "patterns": ["net.*user", "whoami", "query.*user"],
        "event_ids": [4688],
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "discovery",
        "patterns": ["systeminfo", "hostname", "ver", "wmic.*os"],
        "event_ids": [4688],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "discovery",
        "patterns": ["dir.*", "tree", "get-childitem"],
        "event_ids": [4688],
    },

    # Exfiltration
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "patterns": ["compress-archive", "out-file", "upload"],
        "event_ids": [3, 4688],
    },

    # Initial Access
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "initial_access",
        "parent_processes": ["outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe"],
        "event_ids": [4688],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial_access",
        "logon_types": [10, 3],
        "event_ids": [4624, 4648],
    },
}

# Incident type patterns for classification
INCIDENT_TYPE_PATTERNS = {
    IncidentType.RANSOMWARE: {
        "techniques": ["T1486", "T1490"],
        "patterns": ["ransom", "encrypt", "decrypt", "bitcoin", "readme.*decrypt", "vssadmin.*delete"],
        "weight": 1.5,
    },
    IncidentType.CREDENTIAL_THEFT: {
        "techniques": ["T1003.001", "T1003.002", "T1003.003"],
        "patterns": ["mimikatz", "sekurlsa", "lsass", "hashdump", "credential"],
        "weight": 1.3,
    },
    IncidentType.LATERAL_MOVEMENT: {
        "techniques": ["T1021.001", "T1021.002", "T1021.006"],
        "patterns": ["psexec", "wmic.*process", "winrm", "mstsc"],
        "multi_host": True,
        "weight": 1.2,
    },
    IncidentType.PERSISTENCE: {
        "techniques": ["T1547.001", "T1053.005", "T1543.003"],
        "patterns": ["schtasks", "sc.*create", "run.*key"],
        "weight": 1.0,
    },
    IncidentType.COMMAND_AND_CONTROL: {
        "techniques": ["T1071.001", "T1573"],
        "patterns": ["beacon", "c2", "callback", "reverse.*shell"],
        "weight": 1.1,
    },
    IncidentType.DATA_EXFILTRATION: {
        "techniques": ["T1041"],
        "patterns": ["exfil", "upload", "compress-archive", "ftp", "scp"],
        "weight": 1.2,
    },
    IncidentType.PRIVILEGE_ESCALATION: {
        "techniques": ["T1548", "T1134"],
        "patterns": ["runas", "privilege", "elevate", "bypass.*uac"],
        "weight": 1.1,
    },
    IncidentType.RECONNAISSANCE: {
        "techniques": ["T1087.001", "T1082", "T1083"],
        "patterns": ["whoami", "systeminfo", "net.*user", "ipconfig"],
        "weight": 0.8,
    },
    IncidentType.PHISHING: {
        "techniques": ["T1566.001"],
        "patterns": ["outlook", "email", "attachment", "macro"],
        "weight": 1.0,
    },
    IncidentType.MALWARE: {
        "techniques": ["T1204.002", "T1059.001"],
        "patterns": ["malware", "trojan", "virus", "backdoor"],
        "weight": 1.0,
    },
}

# IoC patterns (regex)
IOC_PATTERNS = {
    "ip": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|cc|pw|tk|ml|ga|cf|gq)\b",
    "hash_md5": r"\b[a-fA-F0-9]{32}\b",
    "hash_sha1": r"\b[a-fA-F0-9]{40}\b",
    "hash_sha256": r"\b[a-fA-F0-9]{64}\b",
    "url": r"https?://[^\s<>\"']+",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "file_path": r"[A-Za-z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)*[^\\\/:*?\"<>|\r\n]*",
    "registry": r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s]+",
}

# Known malicious indicators
KNOWN_MALICIOUS_IPS = {
    "185.220.101.", "45.33.32.", "192.42.116.", "104.244.72.",
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware", "c2", "evil", "hack", "backdoor", "trojan",
}

KNOWN_C2_PORTS = {4444, 5555, 6666, 7777, 8888, 1337, 31337, 4443, 8443}


# ============================================================================
# CYBER ML ENGINE
# ============================================================================

class CyberMLEngine:
    """
    Core ML Engine for cyber incident investigation.

    Performs all analysis using ML models and rule-based systems.
    LLM is NOT used for classification or detection - only for report generation.
    """

    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.event_classifier = None
        self.scaler = None
        self.model_metrics = {}

        # Load ML models
        self._load_models()

        # Suspicious indicators (for feature extraction)
        self.suspicious_keywords = [
            'mimikatz', 'invoke-', 'powershell', 'bypass', 'hidden', 'encoded',
            'downloadstring', 'iex', 'webclient', 'frombase64', 'empire',
            'cobalt', 'meterpreter', 'reverse', 'shell', 'payload', 'exploit',
            'dump', 'lsass', 'sekurlsa', 'wmic', 'psexec', 'nc.exe', 'netcat',
            'certutil', 'bitsadmin', 'regsvr32', 'rundll32', 'mshta',
        ]

        self.suspicious_processes = [
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
            'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe',
            'msiexec.exe', 'wmic.exe', 'schtasks.exe', 'at.exe', 'net.exe',
            'net1.exe', 'psexec.exe', 'psexesvc.exe',
        ]

        self.high_risk_event_ids = {
            # Process events
            4688, 4689,
            # Logon events
            4624, 4625, 4648, 4672,
            # Scheduled tasks
            4698, 4699, 4700, 4701, 4702,
            # Service events
            7045,
            # PowerShell
            4104, 4103,
            # Sysmon
            1, 3, 7, 8, 10, 11, 12, 13,
            # Log cleared
            1102,
        }

        # Load extended MITRE patterns (498 techniques from enterprise-attack.json)
        self._extended_mitre: dict = {}
        self._load_extended_mitre()

        logger.info("CyberMLEngine initialized")

    def _load_extended_mitre(self):
        """Load extended MITRE ATT&CK patterns built from enterprise-attack.json."""
        candidates = [
            "knowledge_base/mitre_attack/patterns_extended.json",
            os.path.join(os.path.dirname(__file__), "..", "..", "knowledge_base", "mitre_attack", "patterns_extended.json"),
        ]
        for path in candidates:
            if os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        self._extended_mitre = json.load(f)
                    logger.info(
                        "Extended MITRE patterns loaded: %d techniques", len(self._extended_mitre)
                    )
                    return
                except Exception as e:
                    logger.warning("Failed to load extended MITRE patterns: %s", e)
        logger.warning(
            "Extended MITRE patterns not found. Run: py scripts/build_mitre_patterns.py"
        )

    def _map_extended_mitre(self, event: dict) -> list:
        """
        Map event to MITRE techniques using extended patterns_extended.json.
        Returns list of dicts: {id, name, tactic, confidence}.
        """
        if not self._extended_mitre:
            return []

        cmdline = str(event.get("command_line", "")).lower()
        process = str(event.get("process_name", "")).lower()
        script  = str(event.get("script_block_text", "")).lower()
        combined = f"{cmdline} {process} {script}"

        hits = []
        for tech_id, info in self._extended_mitre.items():
            score = 0
            for kw in info.get("keywords", []):
                if kw and len(kw) > 3 and kw in combined:
                    score += 1

            if score >= 2:  # require at least 2 keyword hits
                hits.append({
                    "id": tech_id,
                    "name": info["name"],
                    "tactic": info["tactic"],
                    "confidence": min(score / 5.0, 1.0),
                    "source": "extended_mitre",
                })

        # Sort by confidence desc, cap at 10
        hits.sort(key=lambda x: -x["confidence"])
        return hits[:10]

    def _load_models(self):
        """Load trained ML models."""
        model_paths = [
            os.path.join(self.models_dir, "gradient_boosting_model.pkl"),
            os.path.join(self.models_dir, "random_forest_model.pkl"),
            "models/gradient_boosting_model.pkl",
            "models/random_forest_model.pkl",
        ]

        for path in model_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        data = pickle.load(f)
                    self.event_classifier = data.get('model')
                    self.scaler = data.get('scaler')
                    self.model_metrics = data.get('metrics', {})
                    logger.info(f"Loaded ML model from {path}")
                    logger.info(f"Model metrics: {self.model_metrics}")
                    return
                except Exception as e:
                    logger.warning(f"Failed to load {path}: {e}")

        logger.warning("No ML model found - using heuristic detection only")

    # ========================================================================
    # EVENT CLASSIFICATION
    # ========================================================================

    def classify_event(self, event: Dict[str, Any]) -> ClassificationResult:
        """
        Classify a single event as malicious/benign.

        This is the core ML classification - NO LLM involved.
        """
        features = self._extract_event_features(event)
        feature_names = self._get_feature_names()

        if self.event_classifier is not None and self.scaler is not None:
            try:
                X = np.array([features])
                X_scaled = self.scaler.transform(X)

                proba = self.event_classifier.predict_proba(X_scaled)[0]
                pred = self.event_classifier.predict(X_scaled)[0]

                is_malicious = bool(pred == 1)
                confidence = float(proba[1]) if is_malicious else float(proba[0])

                return ClassificationResult(
                    label="malicious" if is_malicious else "benign",
                    confidence=confidence,
                    probabilities={"malicious": float(proba[1]), "benign": float(proba[0])},
                    features_used=feature_names,
                    explanation=self._explain_classification(features, feature_names, confidence)
                )
            except Exception as e:
                logger.error(f"ML classification failed: {e}")

        # Fallback to heuristic
        return self._heuristic_classify(features, feature_names)

    def _extract_event_features(self, event: Dict[str, Any]) -> List[float]:
        """Extract numerical features from event for ML model."""
        event_id = int(event.get('event_id', event.get('EventID', 0)) or 0)
        process = str(event.get('process_name', event.get('ProcessName', event.get('Image', '')))).lower()
        cmdline = str(event.get('command_line', event.get('CommandLine', ''))).lower()
        parent = str(event.get('parent_image', event.get('ParentImage', ''))).lower()
        user = str(event.get('user', event.get('SubjectUserName', event.get('TargetUserName', '')))).upper()
        logon_type = int(event.get('logon_type', event.get('LogonType', 0)) or 0)
        dest_port = int(event.get('destination_port', event.get('DestinationPort', 0)) or 0)
        channel = str(event.get('channel', event.get('Channel', 'Security')))

        return [
            float(event_id),
            float(event_id in self.high_risk_event_ids),
            float(hash(channel) % 12),
            float(any(p in process for p in self.suspicious_processes)),
            float(len(cmdline)),
            float(sum(1 for kw in self.suspicious_keywords if kw in cmdline)),
            float(any(x in cmdline for x in ['-enc', '-e ', 'base64', 'frombase64'])),
            float(any(x in cmdline for x in ['download', 'webclient', 'invoke-webrequest'])),
            float(any(x in cmdline for x in ['-w hidden', '-windowstyle h', 'hidden'])),
            float(any(p in parent for p in self.suspicious_processes)),
            float(logon_type),
            float(logon_type in [3, 10]),
            float(user in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']),
            float('ADMIN' in user),
            float(dest_port),
            float(dest_port in KNOWN_C2_PORTS),
        ]

    def _get_feature_names(self) -> List[str]:
        """Get human-readable feature names."""
        return [
            "event_id",
            "is_high_risk_event",
            "channel_hash",
            "is_suspicious_process",
            "cmdline_length",
            "suspicious_keyword_count",
            "has_base64_encoding",
            "has_download_command",
            "has_hidden_window",
            "parent_is_suspicious",
            "logon_type",
            "is_network_or_rdp_logon",
            "is_system_user",
            "is_admin_user",
            "destination_port",
            "is_c2_port",
        ]

    def _explain_classification(self, features: List[float], names: List[str], confidence: float) -> str:
        """Generate human-readable explanation for classification."""
        indicators = []

        if features[5] > 0:  # suspicious_keyword_count
            indicators.append(f"{int(features[5])} malicious keywords detected")
        if features[3]:  # is_suspicious_process
            indicators.append("LOLBin process")
        if features[6]:  # has_base64_encoding
            indicators.append("base64 encoded command")
        if features[7]:  # has_download_command
            indicators.append("download activity")
        if features[8]:  # has_hidden_window
            indicators.append("hidden window execution")
        if features[9]:  # parent_is_suspicious
            indicators.append("suspicious parent process")
        if features[15]:  # is_c2_port
            indicators.append(f"C2 port {int(features[14])}")
        if features[1]:  # is_high_risk_event
            indicators.append(f"high-risk event ID {int(features[0])}")

        if indicators:
            return f"ML confidence {confidence:.0%}: {', '.join(indicators)}"
        return f"ML confidence {confidence:.0%}: pattern-based detection"

    def _heuristic_classify(self, features: List[float], names: List[str]) -> ClassificationResult:
        """Fallback heuristic classification when ML model unavailable."""
        score = 0.0
        indicators = []

        if features[5] > 0:
            score += 0.2 * min(features[5], 4)
            indicators.append(f"{int(features[5])} suspicious keywords")
        if features[3]:
            score += 0.15
            indicators.append("LOLBin")
        if features[6]:
            score += 0.2
            indicators.append("base64")
        if features[7]:
            score += 0.15
            indicators.append("download")
        if features[8]:
            score += 0.15
            indicators.append("hidden")
        if features[9]:
            score += 0.1
            indicators.append("suspicious parent")
        if features[15]:
            score += 0.15
            indicators.append("C2 port")

        score = min(score, 1.0)
        is_malicious = score >= 0.5

        return ClassificationResult(
            label="malicious" if is_malicious else "benign",
            confidence=score if is_malicious else (1 - score),
            probabilities={"malicious": score, "benign": 1 - score},
            features_used=names,
            explanation=f"Heuristic: {', '.join(indicators)}" if indicators else "No indicators"
        )

    # ========================================================================
    # INCIDENT TYPE CLASSIFICATION
    # ========================================================================

    def classify_incident_type(self, events: List[Dict], detected_techniques: List[MITRETechnique]) -> Tuple[IncidentType, float]:
        """
        Classify the overall incident type based on events and MITRE techniques.

        This is ML/rule-based - NO LLM involved.
        """
        scores = {incident_type: 0.0 for incident_type in IncidentType}

        # Get unique hosts
        hosts = set()
        for event in events:
            hostname = event.get('hostname', event.get('ComputerName', ''))
            if hostname:
                hosts.add(hostname.lower())

        # Combine all text for pattern matching
        all_text = ""
        for event in events:
            all_text += " " + str(event.get('command_line', event.get('CommandLine', ''))).lower()
            all_text += " " + str(event.get('process_name', event.get('ProcessName', ''))).lower()

        # Score each incident type
        technique_ids = {t.technique_id for t in detected_techniques}

        for incident_type, config in INCIDENT_TYPE_PATTERNS.items():
            weight = config.get("weight", 1.0)

            # Check techniques
            matching_techniques = set(config.get("techniques", [])) & technique_ids
            if matching_techniques:
                scores[incident_type] += len(matching_techniques) * 0.3 * weight

            # Check patterns
            for pattern in config.get("patterns", []):
                if re.search(pattern, all_text, re.IGNORECASE):
                    scores[incident_type] += 0.2 * weight

            # Check multi-host requirement
            if config.get("multi_host") and len(hosts) > 1:
                scores[incident_type] += 0.3 * weight

        # Normalize and find best match
        total_score = sum(scores.values())
        if total_score > 0:
            for k in scores:
                scores[k] /= total_score

        best_type = max(scores, key=scores.get)
        confidence = scores[best_type]

        # If confidence is too low, return UNKNOWN
        if confidence < 0.2:
            return IncidentType.UNKNOWN, confidence

        return best_type, confidence

    # ========================================================================
    # MITRE ATT&CK MAPPING
    # ========================================================================

    def map_to_mitre(self, event: Dict[str, Any]) -> List[MITRETechnique]:
        """
        Map event to MITRE ATT&CK techniques.

        This is rule-based pattern matching - NO LLM involved.
        """
        techniques = []

        cmdline = str(event.get('command_line', event.get('CommandLine', ''))).lower()
        process = str(event.get('process_name', event.get('ProcessName', event.get('Image', '')))).lower()
        parent = str(event.get('parent_image', event.get('ParentImage', ''))).lower()
        event_id = int(event.get('event_id', event.get('EventID', 0)) or 0)
        logon_type = int(event.get('logon_type', event.get('LogonType', 0)) or 0)
        dest_port = int(event.get('destination_port', event.get('DestinationPort', 0)) or 0)

        for tech_id, config in MITRE_PATTERNS.items():
            confidence = 0.0
            evidence = []

            # Check event ID
            if event_id in config.get("event_ids", []):
                confidence += 0.1

            # Check patterns
            for pattern in config.get("patterns", []):
                if re.search(pattern, cmdline, re.IGNORECASE):
                    confidence += 0.3
                    evidence.append(f"Pattern match: {pattern}")

            # Check process
            for proc in config.get("processes", []):
                if proc.lower() in process:
                    confidence += 0.25
                    evidence.append(f"Process: {proc}")

            # Check parent process
            for parent_proc in config.get("parent_processes", []):
                if parent_proc.lower() in parent:
                    confidence += 0.2
                    evidence.append(f"Parent: {parent_proc}")

            # Check logon type
            if logon_type in config.get("logon_types", []):
                confidence += 0.3
                evidence.append(f"Logon type: {logon_type}")

            # Check ports
            if dest_port in config.get("ports", []):
                confidence += 0.2
                evidence.append(f"Port: {dest_port}")

            if confidence >= 0.3:
                techniques.append(MITRETechnique(
                    technique_id=tech_id,
                    technique_name=config["name"],
                    tactic=config["tactic"],
                    confidence=min(confidence, 1.0),
                    evidence=evidence
                ))

        # Also add matches from extended MITRE (498 techniques)
        existing_ids = {t.technique_id for t in techniques}
        for hit in self._map_extended_mitre(event):
            if hit["id"] not in existing_ids:
                techniques.append(MITRETechnique(
                    technique_id=hit["id"],
                    technique_name=hit["name"],
                    tactic=hit["tactic"],
                    confidence=hit["confidence"],
                    evidence=[f"keyword match (extended MITRE)"],
                ))
                existing_ids.add(hit["id"])

        return sorted(techniques, key=lambda x: x.confidence, reverse=True)

    # ========================================================================
    # IoC EXTRACTION
    # ========================================================================

    def extract_iocs(self, event: Dict[str, Any], event_index: int = -1) -> List[IoC]:
        """
        Extract Indicators of Compromise from event.

        This is regex-based - NO LLM involved.
        """
        iocs = []
        seen = set()

        # Combine all text fields
        text_fields = [
            str(event.get('command_line', event.get('CommandLine', ''))),
            str(event.get('destination_ip', event.get('DestinationIp', ''))),
            str(event.get('source_ip', event.get('SourceIp', ''))),
            str(event.get('file_path', event.get('TargetFilename', ''))),
            str(event.get('hash', event.get('Hashes', ''))),
            str(event.get('url', '')),
            str(event.get('domain', '')),
        ]
        combined_text = " ".join(text_fields)

        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            for match in matches:
                # Skip if already seen
                value_hash = hashlib.md5(f"{ioc_type}:{match}".encode()).hexdigest()
                if value_hash in seen:
                    continue
                seen.add(value_hash)

                # Skip private IPs for IP type
                if ioc_type == "ip":
                    if self._is_private_ip(match):
                        continue

                # Calculate confidence
                confidence = self._calculate_ioc_confidence(ioc_type, match)

                iocs.append(IoC(
                    type=ioc_type,
                    value=match,
                    confidence=confidence,
                    source_event_index=event_index,
                    context=self._get_ioc_context(ioc_type, match)
                ))

        return iocs

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        try:
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
        except (ValueError, IndexError, AttributeError):
            pass
        return False

    def _calculate_ioc_confidence(self, ioc_type: str, value: str) -> float:
        """Calculate confidence score for IoC."""
        confidence = 0.5  # Base confidence

        if ioc_type == "ip":
            # Check against known malicious
            for prefix in KNOWN_MALICIOUS_IPS:
                if value.startswith(prefix):
                    confidence = 0.9
                    break

        elif ioc_type == "domain":
            value_lower = value.lower()
            for indicator in KNOWN_MALICIOUS_DOMAINS:
                if indicator in value_lower:
                    confidence = 0.8
                    break
            # Short domains are more suspicious
            if len(value) < 10:
                confidence += 0.1

        elif ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            confidence = 0.7  # Hashes are generally reliable

        elif ioc_type == "url":
            if any(x in value.lower() for x in ['download', 'payload', 'update', 'install']):
                confidence = 0.75

        return min(confidence, 1.0)

    def _get_ioc_context(self, ioc_type: str, value: str) -> str:
        """Get context description for IoC."""
        contexts = {
            "ip": "Network communication endpoint",
            "domain": "Domain name in communication",
            "hash_md5": "MD5 file hash",
            "hash_sha1": "SHA1 file hash",
            "hash_sha256": "SHA256 file hash",
            "url": "URL accessed",
            "email": "Email address",
            "file_path": "File system path",
            "registry": "Registry key",
        }
        return contexts.get(ioc_type, "Indicator")

    # ========================================================================
    # TIMELINE BUILDING
    # ========================================================================

    def build_timeline(self, events: List[Dict[str, Any]]) -> List[TimelineEntry]:
        """
        Build attack timeline from events.

        This is ML-based classification - NO LLM involved.
        """
        timeline = []

        for idx, event in enumerate(events):
            # Classify event
            classification = self.classify_event(event)

            # Skip benign events with low confidence
            if classification.label == "benign" and classification.confidence > 0.7:
                continue

            # Extract data
            timestamp = event.get('timestamp', event.get('TimeCreated', event.get('@timestamp', '')))
            hostname = event.get('hostname', event.get('ComputerName', 'unknown'))
            event_type = event.get('event_type', event.get('EventType', self._infer_event_type(event)))

            # Determine severity
            severity = self._calculate_severity(classification, event)

            # Map to MITRE
            mitre_techniques = self.map_to_mitre(event)

            # Extract IoCs
            iocs = self.extract_iocs(event, idx)

            # Generate description
            description = self._generate_event_description(event, classification, mitre_techniques)

            timeline.append(TimelineEntry(
                timestamp=str(timestamp),
                hostname=hostname,
                event_type=event_type,
                description=description,
                severity=severity,
                iocs=iocs,
                mitre_techniques=mitre_techniques,
                ml_confidence=classification.confidence,
                event_index=idx
            ))

        # Sort by timestamp
        timeline.sort(key=lambda x: x.timestamp)

        return timeline

    def _infer_event_type(self, event: Dict) -> str:
        """Infer event type from event data."""
        event_id = int(event.get('event_id', event.get('EventID', 0)) or 0)

        event_type_map = {
            4688: "process_creation",
            4689: "process_termination",
            4624: "logon_success",
            4625: "logon_failure",
            4648: "explicit_credential",
            4672: "special_privileges",
            4698: "scheduled_task_created",
            7045: "service_installed",
            4104: "powershell_script",
            1: "process_create_sysmon",
            3: "network_connection",
            11: "file_created",
            13: "registry_value",
            1102: "log_cleared",
        }

        return event_type_map.get(event_id, "unknown")

    def _calculate_severity(self, classification: ClassificationResult, event: Dict) -> ThreatLevel:
        """Calculate threat severity level."""
        confidence = classification.confidence

        if classification.label == "benign":
            return ThreatLevel.INFORMATIONAL

        # Check for critical indicators
        cmdline = str(event.get('command_line', event.get('CommandLine', ''))).lower()

        critical_patterns = ['mimikatz', 'sekurlsa', 'vssadmin.*delete', 'bcdedit.*no']
        for pattern in critical_patterns:
            if re.search(pattern, cmdline):
                return ThreatLevel.CRITICAL

        if confidence >= 0.85:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.7:
            return ThreatLevel.HIGH
        elif confidence >= 0.5:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _generate_event_description(
        self,
        event: Dict,
        classification: ClassificationResult,
        techniques: List[MITRETechnique]
    ) -> str:
        """Generate human-readable event description (no LLM)."""
        parts = []

        # Process info
        process = event.get('process_name', event.get('ProcessName', event.get('Image', '')))
        if process:
            parts.append(f"Process: {process}")

        # User info
        user = event.get('user', event.get('SubjectUserName', event.get('TargetUserName', '')))
        if user:
            parts.append(f"User: {user}")

        # MITRE technique
        if techniques:
            tech = techniques[0]
            parts.append(f"[{tech.technique_id}: {tech.technique_name}]")

        # Classification
        parts.append(f"({classification.label}, {classification.confidence:.0%})")

        return " | ".join(parts)

    # ========================================================================
    # THREAT SCORING
    # ========================================================================

    def calculate_threat_score(self, timeline: List[TimelineEntry], techniques: List[MITRETechnique]) -> Tuple[float, ThreatLevel]:
        """
        Calculate overall threat score (0-100).

        This is algorithmic - NO LLM involved.
        """
        if not timeline:
            return 0.0, ThreatLevel.INFORMATIONAL

        score = 0.0

        # Factor 1: Number of malicious events (max 30 points)
        malicious_count = sum(1 for t in timeline if t.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        score += min(malicious_count * 5, 30)

        # Factor 2: Critical severity events (max 25 points)
        critical_count = sum(1 for t in timeline if t.severity == ThreatLevel.CRITICAL)
        score += min(critical_count * 10, 25)

        # Factor 3: Unique MITRE techniques (max 20 points)
        unique_techniques = len(set(t.technique_id for t in techniques))
        score += min(unique_techniques * 4, 20)

        # Factor 4: High-impact techniques (max 15 points)
        high_impact = ['T1486', 'T1490', 'T1003.001', 'T1041']
        for tech in techniques:
            if tech.technique_id in high_impact:
                score += 5
        score = min(score, 90)  # Cap from techniques

        # Factor 5: IoC count (max 10 points)
        total_iocs = sum(len(t.iocs) for t in timeline)
        score += min(total_iocs * 2, 10)

        score = min(score, 100)

        # Determine threat level
        if score >= 80:
            level = ThreatLevel.CRITICAL
        elif score >= 60:
            level = ThreatLevel.HIGH
        elif score >= 40:
            level = ThreatLevel.MEDIUM
        elif score >= 20:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.INFORMATIONAL

        return score, level

    # ========================================================================
    # FULL INVESTIGATION
    # ========================================================================

    def investigate(self, incident_id: str, events: List[Dict[str, Any]]) -> MLInvestigationResult:
        """
        Perform complete ML-based investigation.

        This is the main entry point - ALL analysis is ML/rule-based.
        LLM is NOT called here.
        """
        logger.info(f"Starting ML investigation: {incident_id} ({len(events)} events)")

        # Step 1: Build timeline with classifications
        timeline = self.build_timeline(events)
        logger.info(f"Timeline built: {len(timeline)} entries")

        # Step 2: Aggregate all MITRE techniques
        all_techniques = []
        seen_techniques = set()
        for entry in timeline:
            for tech in entry.mitre_techniques:
                if tech.technique_id not in seen_techniques:
                    all_techniques.append(tech)
                    seen_techniques.add(tech.technique_id)

        all_techniques.sort(key=lambda x: x.confidence, reverse=True)
        logger.info(f"MITRE techniques: {len(all_techniques)}")

        # Step 3: Aggregate all IoCs
        all_iocs = []
        seen_iocs = set()
        for entry in timeline:
            for ioc in entry.iocs:
                ioc_key = f"{ioc.type}:{ioc.value}"
                if ioc_key not in seen_iocs:
                    all_iocs.append(ioc)
                    seen_iocs.add(ioc_key)

        all_iocs.sort(key=lambda x: x.confidence, reverse=True)
        logger.info(f"IoCs extracted: {len(all_iocs)}")

        # Step 4: Classify incident type
        incident_type, type_confidence = self.classify_incident_type(events, all_techniques)
        logger.info(f"Incident type: {incident_type.value} ({type_confidence:.0%})")

        # Step 5: Calculate threat score
        threat_score, threat_level = self.calculate_threat_score(timeline, all_techniques)
        logger.info(f"Threat score: {threat_score:.0f}/100 ({threat_level.value})")

        # Step 6: Extract affected hosts and users
        affected_hosts = list(set(e.hostname for e in timeline if e.hostname))
        affected_users = list(set(
            event.get('user', event.get('SubjectUserName', event.get('TargetUserName', '')))
            for event in events
            if event.get('user') or event.get('SubjectUserName') or event.get('TargetUserName')
        ))

        # Step 7: Generate key findings (rule-based, not LLM)
        key_findings = self._generate_key_findings(timeline, all_techniques, incident_type)

        # Step 8: Generate recommended actions (rule-based, not LLM)
        recommended_actions = self._generate_recommendations(incident_type, all_techniques, all_iocs)

        # Build result
        result = MLInvestigationResult(
            incident_id=incident_id,
            incident_type=incident_type,
            incident_type_confidence=type_confidence,
            threat_level=threat_level,
            threat_score=threat_score,
            timeline=timeline,
            iocs=all_iocs,
            mitre_techniques=all_techniques,
            affected_hosts=affected_hosts,
            affected_users=affected_users,
            total_events=len(events),
            malicious_events=len([t for t in timeline if t.severity != ThreatLevel.INFORMATIONAL]),
            analysis_timestamp=datetime.utcnow().isoformat() + "Z",
            key_findings=key_findings,
            recommended_actions=recommended_actions,
        )

        logger.info(f"ML investigation complete: {incident_id}")
        return result

    def _generate_key_findings(
        self,
        timeline: List[TimelineEntry],
        techniques: List[MITRETechnique],
        incident_type: IncidentType
    ) -> List[str]:
        """Generate key findings (rule-based, no LLM)."""
        findings = []

        # Finding: Incident type
        findings.append(f"Incident classified as {incident_type.value.upper()}")

        # Finding: Critical events
        critical_count = sum(1 for t in timeline if t.severity == ThreatLevel.CRITICAL)
        if critical_count > 0:
            findings.append(f"{critical_count} critical severity events detected")

        # Finding: Top MITRE techniques
        if techniques:
            top_techs = techniques[:3]
            tech_str = ", ".join(f"{t.technique_id}" for t in top_techs)
            findings.append(f"Primary attack techniques: {tech_str}")

        # Finding: Hosts affected
        hosts = set(t.hostname for t in timeline)
        if len(hosts) > 1:
            findings.append(f"Attack spread across {len(hosts)} hosts (lateral movement likely)")

        # Finding: Time span
        if len(timeline) >= 2:
            first = timeline[0].timestamp
            last = timeline[-1].timestamp
            findings.append(f"Attack timeline: {first} to {last}")

        return findings

    def _generate_recommendations(
        self,
        incident_type: IncidentType,
        techniques: List[MITRETechnique],
        iocs: List[IoC]
    ) -> List[str]:
        """Generate recommended actions (rule-based, no LLM)."""
        recommendations = []

        # Universal recommendations
        recommendations.append("Isolate affected systems from network")

        # Type-specific recommendations
        type_recommendations = {
            IncidentType.RANSOMWARE: [
                "Check backup integrity before restoration",
                "Block shadow copy deletion commands",
                "Scan for ransom notes and encrypted files",
            ],
            IncidentType.CREDENTIAL_THEFT: [
                "Reset all potentially compromised credentials",
                "Enable MFA on all accounts",
                "Review privileged account access",
            ],
            IncidentType.LATERAL_MOVEMENT: [
                "Segment network to limit spread",
                "Disable RDP where not required",
                "Review remote access policies",
            ],
            IncidentType.DATA_EXFILTRATION: [
                "Identify exfiltrated data scope",
                "Review data loss prevention policies",
                "Enable egress traffic monitoring",
            ],
            IncidentType.COMMAND_AND_CONTROL: [
                "Block identified C2 indicators",
                "Review DNS logs for beaconing",
                "Implement DNS sinkholing",
            ],
        }

        if incident_type in type_recommendations:
            recommendations.extend(type_recommendations[incident_type])

        # IoC-based recommendations
        ips = [ioc.value for ioc in iocs if ioc.type == "ip"]
        if ips:
            recommendations.append(f"Block IP addresses: {', '.join(ips[:5])}")

        domains = [ioc.value for ioc in iocs if ioc.type == "domain"]
        if domains:
            recommendations.append(f"Block domains: {', '.join(domains[:5])}")

        hashes = [ioc.value for ioc in iocs if ioc.type.startswith("hash_")]
        if hashes:
            recommendations.append("Add file hashes to EDR blocklist")

        return recommendations

    # ========================================================================
    # UTILITY METHODS
    # ========================================================================

    def get_model_info(self) -> Dict:
        """Get information about loaded models."""
        return {
            "event_classifier_loaded": self.event_classifier is not None,
            "scaler_loaded": self.scaler is not None,
            "model_metrics": self.model_metrics,
            "mitre_techniques_count": len(MITRE_PATTERNS),
            "incident_types_count": len(INCIDENT_TYPE_PATTERNS),
            "ioc_patterns_count": len(IOC_PATTERNS),
        }

    def to_dict(self, result: MLInvestigationResult) -> Dict:
        """Convert investigation result to dictionary for JSON serialization."""
        return {
            "incident_id": result.incident_id,
            "incident_type": result.incident_type.value,
            "incident_type_confidence": result.incident_type_confidence,
            "threat_level": result.threat_level.value,
            "threat_score": result.threat_score,
            "timeline": [
                {
                    "timestamp": e.timestamp,
                    "hostname": e.hostname,
                    "event_type": e.event_type,
                    "description": e.description,
                    "severity": e.severity.value,
                    "ml_confidence": e.ml_confidence,
                    "iocs": [{"type": i.type, "value": i.value, "confidence": i.confidence} for i in e.iocs],
                    "mitre_techniques": [{"id": t.technique_id, "name": t.technique_name, "tactic": t.tactic} for t in e.mitre_techniques],
                }
                for e in result.timeline
            ],
            "iocs": [{"type": i.type, "value": i.value, "confidence": i.confidence, "context": i.context} for i in result.iocs],
            "mitre_techniques": [
                {"id": t.technique_id, "name": t.technique_name, "tactic": t.tactic, "confidence": t.confidence}
                for t in result.mitre_techniques
            ],
            "affected_hosts": result.affected_hosts,
            "affected_users": result.affected_users,
            "total_events": result.total_events,
            "malicious_events": result.malicious_events,
            "analysis_timestamp": result.analysis_timestamp,
            "key_findings": result.key_findings,
            "recommended_actions": result.recommended_actions,
        }


# ============================================================================
# SINGLETON
# ============================================================================

_engine: Optional[CyberMLEngine] = None


def get_ml_engine(models_dir: str = "models") -> CyberMLEngine:
    """Get ML engine singleton."""
    global _engine
    if _engine is None:
        _engine = CyberMLEngine(models_dir=models_dir)
    return _engine
