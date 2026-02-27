"""
Incident Correlation Engine for IR-Agent

Groups events into incidents, builds attack timelines,
performs root cause analysis and impact assessment.

Architecture:
    Events → Correlation → Incident Object
        → Timeline Builder
        → IoC Extractor
        → MITRE Mapper
        → Root Cause Analysis
        → Impact Assessment
        → Report Generator
"""

import re
import uuid
import logging
import hashlib
from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("ir-agent")


# ─── Enums ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class AttackPhase(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    COMMAND_AND_CONTROL = "Command and Control"
    IMPACT = "Impact"
    UNKNOWN = "Unknown"


# ─── Data Classes ──────────────────────────────────────────────────────

@dataclass
class IoC:
    type: str           # ip, domain, hash, url, email, file_path, process, registry
    value: str
    context: str = ""
    confidence: float = 0.0
    first_seen: str = ""
    source_event_id: str = ""

    @property
    def uid(self) -> str:
        return hashlib.md5(f"{self.type}:{self.value}".encode()).hexdigest()[:12]


@dataclass
class TimelineEntry:
    timestamp: str
    hostname: str
    event_type: str
    description: str
    severity: Severity
    phase: AttackPhase
    iocs: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    raw_event: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity.value,
            "phase": self.phase.value,
            "iocs": self.iocs,
            "mitre_techniques": self.mitre_techniques,
        }


@dataclass
class Incident:
    id: str
    host: str
    status: IncidentStatus = IncidentStatus.OPEN
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    classification: str = ""
    events: List[Dict] = field(default_factory=list)
    timeline: List[TimelineEntry] = field(default_factory=list)
    iocs: List[IoC] = field(default_factory=list)
    mitre_techniques: List[Dict] = field(default_factory=list)
    key_findings: List[str] = field(default_factory=list)
    root_cause: str = ""
    impact_assessment: str = ""
    recommendations: List[str] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "host": self.host,
            "status": self.status.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "classification": self.classification,
            "event_count": len(self.events),
            "timeline": [t.to_dict() for t in self.timeline],
            "iocs": [{"type": i.type, "value": i.value, "context": i.context,
                       "confidence": i.confidence} for i in self.iocs],
            "mitre_techniques": self.mitre_techniques,
            "key_findings": self.key_findings,
            "root_cause": self.root_cause,
            "impact_assessment": self.impact_assessment,
            "recommendations": self.recommendations,
            "affected_hosts": self.affected_hosts,
            "affected_users": self.affected_users,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_report(self) -> str:
        """Generate human-readable investigation report."""
        lines = []
        lines.append("=" * 70)
        lines.append("INCIDENT INVESTIGATION REPORT")
        lines.append("=" * 70)
        lines.append(f"Incident ID:     {self.id}")
        lines.append(f"Host:            {self.host}")
        lines.append(f"Severity:        {self.severity.value.upper()}")
        lines.append(f"Confidence:      {self.confidence:.0%}")
        lines.append(f"Status:          {self.status.value}")
        lines.append(f"Classification:  {self.classification}")
        lines.append(f"Created:         {self.created_at}")
        lines.append("")

        # Classification
        lines.append("-" * 70)
        lines.append("CLASSIFICATION")
        lines.append("-" * 70)
        lines.append(self.classification)
        lines.append("")

        # Timeline
        lines.append("-" * 70)
        lines.append("ATTACK TIMELINE")
        lines.append("-" * 70)
        for entry in self.timeline:
            sev_icon = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]",
                        "low": "[.]", "info": "[i]"}.get(entry.severity.value, "[?]")
            lines.append(f"  {entry.timestamp}  {sev_icon} [{entry.phase.value}]")
            lines.append(f"    {entry.description}")
            if entry.mitre_techniques:
                lines.append(f"    MITRE: {', '.join(entry.mitre_techniques)}")
            if entry.iocs:
                lines.append(f"    IoCs: {', '.join(entry.iocs[:3])}")
            lines.append("")

        # IoCs
        if self.iocs:
            lines.append("-" * 70)
            lines.append("INDICATORS OF COMPROMISE (IoCs)")
            lines.append("-" * 70)
            by_type = defaultdict(list)
            for ioc in self.iocs:
                by_type[ioc.type].append(ioc)
            for ioc_type, items in by_type.items():
                lines.append(f"  [{ioc_type.upper()}]")
                for item in items[:10]:
                    lines.append(f"    - {item.value} ({item.context})")
            lines.append("")

        # MITRE
        if self.mitre_techniques:
            lines.append("-" * 70)
            lines.append("MITRE ATT&CK MAPPING")
            lines.append("-" * 70)
            for tech in self.mitre_techniques:
                lines.append(f"  {tech['id']} - {tech['name']}")
                if tech.get('tactic'):
                    lines.append(f"    Tactic: {tech['tactic']}")
            lines.append("")

        # Root Cause
        lines.append("-" * 70)
        lines.append("ROOT CAUSE ANALYSIS")
        lines.append("-" * 70)
        lines.append(f"  {self.root_cause}")
        lines.append("")

        # Impact
        lines.append("-" * 70)
        lines.append("IMPACT ASSESSMENT")
        lines.append("-" * 70)
        lines.append(f"  {self.impact_assessment}")
        lines.append(f"  Affected hosts: {', '.join(self.affected_hosts)}")
        lines.append(f"  Affected users: {', '.join(self.affected_users)}")
        lines.append("")

        # Recommendations
        lines.append("-" * 70)
        lines.append("RECOMMENDED RESPONSE")
        lines.append("-" * 70)
        for i, rec in enumerate(self.recommendations, 1):
            lines.append(f"  {i}. {rec}")

        lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)


# ─── MITRE ATT&CK Mapping ─────────────────────────────────────────────

MITRE_MAP = {
    # Execution
    "powershell": {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
    "cmd": {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
    "wscript": {"id": "T1059.005", "name": "Visual Basic", "tactic": "Execution"},
    "cscript": {"id": "T1059.005", "name": "Visual Basic", "tactic": "Execution"},
    "mshta": {"id": "T1218.005", "name": "Mshta", "tactic": "Defense Evasion"},
    "python": {"id": "T1059.006", "name": "Python", "tactic": "Execution"},
    "wmic": {"id": "T1047", "name": "WMI", "tactic": "Execution"},
    "wmiprvse": {"id": "T1047", "name": "WMI", "tactic": "Execution"},

    # Persistence
    "schtasks": {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
    "sc create": {"id": "T1543.003", "name": "Windows Service", "tactic": "Persistence"},
    "reg add": {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
    "7045": {"id": "T1543.003", "name": "Windows Service", "tactic": "Persistence"},
    "4698": {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},

    # Credential Access
    "mimikatz": {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
    "sekurlsa": {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
    "lsass": {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
    "procdump": {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
    "ntds.dit": {"id": "T1003.003", "name": "NTDS", "tactic": "Credential Access"},

    # Lateral Movement
    "psexec": {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    "winrs": {"id": "T1021.006", "name": "Windows Remote Management", "tactic": "Lateral Movement"},

    # Defense Evasion
    "rundll32": {"id": "T1218.011", "name": "Rundll32", "tactic": "Defense Evasion"},
    "regsvr32": {"id": "T1218.010", "name": "Regsvr32", "tactic": "Defense Evasion"},
    "certutil": {"id": "T1140", "name": "Deobfuscate/Decode Files", "tactic": "Defense Evasion"},
    "base64": {"id": "T1027", "name": "Obfuscated Files", "tactic": "Defense Evasion"},
    "-enc": {"id": "T1027", "name": "Obfuscated Files", "tactic": "Defense Evasion"},
    "bypass": {"id": "T1562.001", "name": "Disable Security Tools", "tactic": "Defense Evasion"},
    "amsi": {"id": "T1562.001", "name": "Disable Security Tools", "tactic": "Defense Evasion"},

    # C2
    "cobalt": {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
    "meterpreter": {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
    "beacon": {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
    "reverse": {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},

    # Exfiltration
    "dns_exfil": {"id": "T1048.003", "name": "Exfiltration Over DNS", "tactic": "Exfiltration"},
    "compress": {"id": "T1560.001", "name": "Archive via Utility", "tactic": "Collection"},

    # Discovery
    "whoami": {"id": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery"},
    "systeminfo": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    "ipconfig": {"id": "T1016", "name": "System Network Configuration", "tactic": "Discovery"},
    "netstat": {"id": "T1049", "name": "System Network Connections", "tactic": "Discovery"},
    "tasklist": {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery"},
    "nltest": {"id": "T1482", "name": "Domain Trust Discovery", "tactic": "Discovery"},

    # Initial Access
    "4625": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "logon_failure": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
}


# ─── IoC Extraction Patterns ──────────────────────────────────────────

IOC_PATTERNS = {
    "ip": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "domain": re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "url": re.compile(r'https?://[^\s"<>]+'),
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "file_path": re.compile(r'[A-Z]:\\[\w\\. -]+\.\w{2,4}'),
    "registry": re.compile(r'HK(?:LM|CU|CR|U|CC)\\[\w\\]+'),
}

PRIVATE_IP_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                        '172.19.', '172.2', '172.3', '127.', '0.0.', '169.254.')


# ─── Incident Manager ─────────────────────────────────────────────────

class IncidentManager:
    """
    Correlation Engine: groups events into incidents and performs
    full investigation (timeline, IoCs, MITRE, root cause, impact).
    """

    # Events within this window are grouped into one incident per host
    CORRELATION_WINDOW = timedelta(minutes=30)

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        # host -> active incident id
        self._active_incidents: Dict[str, str] = {}
        self._stats = {"total_incidents": 0, "total_events_correlated": 0}

    # ── Public API ─────────────────────────────────────────────────────

    def correlate_event(self, event: Dict[str, Any],
                        ml_confidence: float = 0.0,
                        ml_reason: str = "") -> Optional[str]:
        """
        Add event to an existing incident or create a new one.
        Returns incident ID.
        """
        host = event.get("hostname", event.get("host", "unknown"))
        now = datetime.utcnow()

        # Check for active incident on this host
        incident_id = self._active_incidents.get(host)
        if incident_id and incident_id in self._incidents:
            incident = self._incidents[incident_id]
            # Check if within correlation window
            try:
                last_update = datetime.fromisoformat(incident.updated_at.replace("Z", ""))
                if now - last_update <= self.CORRELATION_WINDOW:
                    self._add_event_to_incident(incident, event, ml_confidence, ml_reason)
                    return incident_id
            except (ValueError, AttributeError):
                pass

        # Create new incident
        return self._create_incident(host, event, ml_confidence, ml_reason)

    def investigate(self, incident_id: str) -> Optional[Dict]:
        """
        Run full investigation on an incident.
        Returns complete investigation report.
        """
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        incident.status = IncidentStatus.INVESTIGATING

        # 1. Build timeline
        self._build_timeline(incident)

        # 2. Extract IoCs
        self._extract_iocs(incident)

        # 3. Map MITRE techniques
        self._map_mitre(incident)

        # 4. Classify incident
        self._classify_incident(incident)

        # 5. Calculate severity
        self._calculate_severity(incident)

        # 6. Root cause analysis
        self._analyze_root_cause(incident)

        # 7. Impact assessment
        self._assess_impact(incident)

        # 8. Generate recommendations
        self._generate_recommendations(incident)

        # 9. Key findings
        self._generate_key_findings(incident)

        incident.updated_at = datetime.utcnow().isoformat() + "Z"
        logger.info(f"Investigation complete: {incident_id} - {incident.classification} "
                     f"({incident.severity.value}, {incident.confidence:.0%})")

        return incident.to_dict()

    def get_incident(self, incident_id: str) -> Optional[Dict]:
        incident = self._incidents.get(incident_id)
        return incident.to_dict() if incident else None

    def get_report(self, incident_id: str) -> Optional[str]:
        incident = self._incidents.get(incident_id)
        return incident.to_report() if incident else None

    def list_incidents(self) -> List[Dict]:
        return [
            {
                "id": inc.id,
                "host": inc.host,
                "severity": inc.severity.value,
                "classification": inc.classification,
                "event_count": len(inc.events),
                "status": inc.status.value,
                "created_at": inc.created_at,
            }
            for inc in sorted(self._incidents.values(),
                              key=lambda x: x.created_at, reverse=True)
        ]

    def get_stats(self) -> Dict:
        return {
            **self._stats,
            "active_incidents": len(self._active_incidents),
            "total_stored": len(self._incidents),
        }

    # ── Incident Lifecycle ─────────────────────────────────────────────

    def _create_incident(self, host: str, event: Dict,
                         confidence: float, reason: str) -> str:
        now = datetime.utcnow()
        incident_id = f"IR-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        incident = Incident(
            id=incident_id,
            host=host,
            created_at=now.isoformat() + "Z",
            updated_at=now.isoformat() + "Z",
        )
        self._add_event_to_incident(incident, event, confidence, reason)

        self._incidents[incident_id] = incident
        self._active_incidents[host] = incident_id
        self._stats["total_incidents"] += 1

        logger.info(f"New incident created: {incident_id} on {host}")
        return incident_id

    def _add_event_to_incident(self, incident: Incident, event: Dict,
                                confidence: float, reason: str):
        event["_ml_confidence"] = confidence
        event["_ml_reason"] = reason
        incident.events.append(event)
        incident.updated_at = datetime.utcnow().isoformat() + "Z"

        # Track affected hosts/users
        host = event.get("hostname", event.get("host", ""))
        if host and host not in incident.affected_hosts:
            incident.affected_hosts.append(host)

        user = event.get("user", "")
        if user and user not in incident.affected_users:
            incident.affected_users.append(user)

        self._stats["total_events_correlated"] += 1

    # ── Timeline Builder ───────────────────────────────────────────────

    def _build_timeline(self, incident: Incident):
        """Build chronological attack timeline with phase classification."""
        entries = []

        for event in incident.events:
            ts = event.get("timestamp", datetime.utcnow().isoformat() + "Z")
            host = event.get("hostname", incident.host)
            event_id = event.get("event_id", 0)
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                event_id = 0

            # Determine description and phase
            description, phase = self._interpret_event(event)
            severity = self._event_severity(event)

            # Find IoCs in this event
            event_iocs = self._extract_event_iocs(event)

            # Map MITRE techniques for this event
            techniques = self._map_event_mitre(event)

            entry = TimelineEntry(
                timestamp=ts,
                hostname=host,
                event_type=event.get("action", event.get("data_type", f"event_{event_id}")),
                description=description,
                severity=severity,
                phase=phase,
                iocs=[f"{i.type}:{i.value}" for i in event_iocs],
                mitre_techniques=[t["id"] for t in techniques],
                raw_event=event,
            )
            entries.append(entry)

        # Sort by timestamp
        entries.sort(key=lambda e: e.timestamp)
        incident.timeline = entries

    def _interpret_event(self, event: Dict) -> Tuple[str, AttackPhase]:
        """Generate human-readable description and attack phase."""
        event_id = 0
        try:
            event_id = int(event.get("event_id", 0))
        except (ValueError, TypeError):
            pass

        process = event.get("process_name", "")
        cmdline = event.get("command_line", "")
        user = event.get("user", "")
        action = event.get("action", "")

        # Phase detection based on event patterns
        all_text = f"{process} {cmdline} {action}".lower()

        # Credential Access
        if any(kw in all_text for kw in ['mimikatz', 'sekurlsa', 'lsass', 'procdump', 'ntds']):
            desc = f"Credential dumping: {process} executed by {user}"
            if cmdline:
                desc += f" [{cmdline[:80]}]"
            return desc, AttackPhase.CREDENTIAL_ACCESS

        # Execution (PowerShell, cmd, scripts)
        if any(kw in all_text for kw in ['powershell', 'invoke-', 'iex', '-enc']):
            desc = f"PowerShell execution by {user}"
            if '-enc' in all_text or 'base64' in all_text:
                desc += " (encoded command)"
            return desc, AttackPhase.EXECUTION

        # Persistence
        if any(kw in all_text for kw in ['schtasks', 'sc create', 'reg add', 'onstart']):
            desc = f"Persistence mechanism: {cmdline[:80] if cmdline else action}"
            return desc, AttackPhase.PERSISTENCE
        if event_id in [7045, 4698]:
            desc = f"{'Service installed' if event_id == 7045 else 'Scheduled task created'} by {user}"
            return desc, AttackPhase.PERSISTENCE

        # Lateral Movement
        if any(kw in all_text for kw in ['psexec', 'winrs', 'wmic process', 'wmiprvse']):
            desc = f"Lateral movement: {process} → remote execution"
            return desc, AttackPhase.LATERAL_MOVEMENT

        # Defense Evasion
        if any(kw in all_text for kw in ['bypass', 'amsi', 'hidden', 'rundll32', 'regsvr32']):
            desc = f"Defense evasion: {process}"
            return desc, AttackPhase.DEFENSE_EVASION

        # C2
        if any(kw in all_text for kw in ['cobalt', 'beacon', 'meterpreter', 'reverse']):
            desc = f"C2 communication: {process}"
            return desc, AttackPhase.COMMAND_AND_CONTROL

        # Discovery
        if any(kw in all_text for kw in ['whoami', 'systeminfo', 'ipconfig', 'netstat', 'nltest']):
            desc = f"Discovery: {cmdline[:80] if cmdline else process}"
            return desc, AttackPhase.DISCOVERY

        # Exfiltration
        if event.get("query_name", ""):
            query = event["query_name"]
            labels = query.split(".")
            if any(len(l) > 20 for l in labels):
                return f"DNS data exfiltration: {query[:60]}", AttackPhase.EXFILTRATION

        # Logon events
        if event_id == 4624:
            return f"Successful logon: {user} (type {event.get('logon_type', '?')})", AttackPhase.INITIAL_ACCESS
        if event_id == 4625:
            return f"Failed logon attempt: {user}", AttackPhase.INITIAL_ACCESS
        if event_id == 4648:
            return f"Explicit credential use by {user}", AttackPhase.CREDENTIAL_ACCESS

        # DLL loading
        image_loaded = event.get("image_loaded", "")
        if image_loaded:
            return f"DLL loaded: {image_loaded}", AttackPhase.DEFENSE_EVASION

        # Default
        desc = event.get("message", f"Event {event_id}: {process}")
        return desc, AttackPhase.UNKNOWN

    def _event_severity(self, event: Dict) -> Severity:
        confidence = event.get("_ml_confidence", 0)
        if confidence >= 0.8:
            return Severity.CRITICAL
        if confidence >= 0.6:
            return Severity.HIGH
        if confidence >= 0.4:
            return Severity.MEDIUM
        if confidence >= 0.2:
            return Severity.LOW
        return Severity.INFO

    # ── IoC Extraction ─────────────────────────────────────────────────

    def _extract_iocs(self, incident: Incident):
        """Extract all IoCs from incident events."""
        seen = set()
        all_iocs = []

        for event in incident.events:
            for ioc in self._extract_event_iocs(event):
                if ioc.uid not in seen:
                    seen.add(ioc.uid)
                    all_iocs.append(ioc)

        incident.iocs = all_iocs

    def _extract_event_iocs(self, event: Dict) -> List[IoC]:
        """Extract IoCs from a single event."""
        iocs = []
        text_fields = [
            event.get("command_line", ""),
            event.get("script_block_text", ""),
            event.get("message", ""),
            event.get("service_file", ""),
            event.get("source_ip", ""),
            event.get("destination_ip", ""),
            event.get("query_name", ""),
            event.get("image_loaded", ""),
        ]
        combined = " ".join(str(f) for f in text_fields if f)
        ts = event.get("timestamp", "")

        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in pattern.findall(combined):
                value = match.strip()
                if not value:
                    continue

                # Filter private IPs
                if ioc_type == "ip" and value.startswith(PRIVATE_IP_PREFIXES):
                    continue
                # Filter common domains
                if ioc_type == "domain" and value in ("localhost", "example.com"):
                    continue

                iocs.append(IoC(
                    type=ioc_type,
                    value=value,
                    context=f"Found in event {event.get('event_id', '?')}",
                    confidence=0.7,
                    first_seen=ts,
                ))

        # Process-based IoCs
        process = event.get("process_name", "")
        if process and any(s in process.lower() for s in
                           ['mimikatz', 'cobalt', 'meterpreter', 'psexec']):
            iocs.append(IoC(type="process", value=process,
                            context="Suspicious tool", confidence=0.9, first_seen=ts))

        return iocs

    # ── MITRE Mapping ──────────────────────────────────────────────────

    def _map_mitre(self, incident: Incident):
        """Map all incident events to MITRE ATT&CK techniques."""
        seen_ids = set()
        techniques = []

        for event in incident.events:
            for tech in self._map_event_mitre(event):
                if tech["id"] not in seen_ids:
                    seen_ids.add(tech["id"])
                    techniques.append(tech)

        incident.mitre_techniques = techniques

    def _map_event_mitre(self, event: Dict) -> List[Dict]:
        """Map a single event to MITRE techniques."""
        techniques = []
        seen = set()

        # Check all text fields
        all_text = " ".join(str(v) for v in [
            event.get("command_line", ""),
            event.get("process_name", ""),
            event.get("script_block_text", ""),
            event.get("action", ""),
        ] if v).lower()

        # Check event_id
        event_id = str(event.get("event_id", ""))

        for keyword, tech in MITRE_MAP.items():
            if keyword in all_text or keyword == event_id:
                if tech["id"] not in seen:
                    seen.add(tech["id"])
                    techniques.append(tech.copy())

        return techniques

    # ── Classification ─────────────────────────────────────────────────

    def _classify_incident(self, incident: Incident):
        """Determine overall incident classification."""
        phases = [e.phase for e in incident.timeline]
        techniques = [t["id"] for t in incident.mitre_techniques]

        # Count phases
        phase_counts = defaultdict(int)
        for p in phases:
            phase_counts[p] += 1

        # Classification logic
        if AttackPhase.CREDENTIAL_ACCESS in phases:
            if AttackPhase.LATERAL_MOVEMENT in phases:
                incident.classification = "Credential theft with lateral movement"
            else:
                incident.classification = "Credential access / dumping attempt"
        elif AttackPhase.EXFILTRATION in phases:
            incident.classification = "Data exfiltration detected"
        elif AttackPhase.COMMAND_AND_CONTROL in phases:
            incident.classification = "Command & Control communication"
        elif AttackPhase.PERSISTENCE in phases and AttackPhase.EXECUTION in phases:
            incident.classification = "Malware execution with persistence"
        elif AttackPhase.PERSISTENCE in phases:
            incident.classification = "Persistence mechanism established"
        elif AttackPhase.EXECUTION in phases and AttackPhase.DEFENSE_EVASION in phases:
            incident.classification = "Evasive code execution"
        elif AttackPhase.EXECUTION in phases:
            incident.classification = "Suspicious code execution"
        elif any(t.startswith("T1110") for t in techniques):
            incident.classification = "Brute force / credential stuffing"
        else:
            incident.classification = "Suspicious activity detected"

    # ── Severity Calculation ───────────────────────────────────────────

    def _calculate_severity(self, incident: Incident):
        """Calculate overall incident severity and confidence."""
        score = 0.0
        factors = []

        # Event count factor
        n_events = len(incident.events)
        if n_events >= 10:
            score += 0.15
            factors.append(f"{n_events} events")
        elif n_events >= 5:
            score += 0.1

        # Phase diversity (more phases = more advanced attack)
        unique_phases = set(e.phase for e in incident.timeline
                           if e.phase != AttackPhase.UNKNOWN)
        if len(unique_phases) >= 4:
            score += 0.25
            factors.append(f"{len(unique_phases)} attack phases")
        elif len(unique_phases) >= 2:
            score += 0.15

        # Critical phases
        critical_phases = {AttackPhase.CREDENTIAL_ACCESS, AttackPhase.EXFILTRATION,
                           AttackPhase.LATERAL_MOVEMENT, AttackPhase.COMMAND_AND_CONTROL}
        if critical_phases & unique_phases:
            score += 0.2
            factors.append("critical attack phases")

        # MITRE techniques
        n_techniques = len(incident.mitre_techniques)
        if n_techniques >= 5:
            score += 0.15
        elif n_techniques >= 3:
            score += 0.1

        # IoC count
        n_iocs = len(incident.iocs)
        if n_iocs >= 5:
            score += 0.1

        # ML confidence (average of events)
        confidences = [e.get("_ml_confidence", 0) for e in incident.events]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        score += avg_confidence * 0.15

        # Multiple hosts (lateral movement indicator)
        if len(incident.affected_hosts) > 1:
            score += 0.15
            factors.append(f"{len(incident.affected_hosts)} hosts affected")

        score = min(score, 1.0)
        incident.confidence = score

        if score >= 0.8:
            incident.severity = Severity.CRITICAL
        elif score >= 0.6:
            incident.severity = Severity.HIGH
        elif score >= 0.4:
            incident.severity = Severity.MEDIUM
        elif score >= 0.2:
            incident.severity = Severity.LOW
        else:
            incident.severity = Severity.INFO

    # ── Root Cause Analysis ────────────────────────────────────────────

    def _analyze_root_cause(self, incident: Incident):
        """Determine probable root cause based on timeline."""
        if not incident.timeline:
            incident.root_cause = "Insufficient data for root cause analysis."
            return

        first_event = incident.timeline[0]
        phases = [e.phase for e in incident.timeline]

        # Analyze first event for initial vector
        causes = []

        if first_event.phase == AttackPhase.INITIAL_ACCESS:
            if "logon_failure" in first_event.event_type or "4625" in str(first_event.raw_event.get("event_id", "")):
                causes.append("Brute force login attempt detected as initial vector")
            elif "4624" in str(first_event.raw_event.get("event_id", "")):
                logon_type = first_event.raw_event.get("logon_type", "")
                if str(logon_type) == "10":
                    causes.append("Unauthorized RDP access as initial entry point")
                elif str(logon_type) == "3":
                    causes.append("Network logon suggesting lateral movement from another host")
                else:
                    causes.append("Suspicious authentication as initial access")

        if first_event.phase == AttackPhase.EXECUTION:
            process = first_event.raw_event.get("process_name", "")
            if "powershell" in process.lower():
                causes.append("PowerShell-based attack, likely delivered via phishing or exploit")
            elif "python" in process.lower():
                causes.append("Script-based attack using Python runtime")
            elif "mshta" in process.lower():
                causes.append("HTML Application abuse, likely from malicious link/document")
            else:
                causes.append(f"Suspicious execution of {process}")

        # Check for persistence after execution
        if AttackPhase.EXECUTION in phases and AttackPhase.PERSISTENCE in phases:
            causes.append("Attacker established persistence after initial execution")

        # Check for credential theft chain
        if AttackPhase.CREDENTIAL_ACCESS in phases:
            causes.append("Credential harvesting indicates intent for privilege escalation or lateral movement")

        if not causes:
            causes.append(f"Initial suspicious activity detected: {first_event.description[:100]}")

        incident.root_cause = ". ".join(causes) + "."

    # ── Impact Assessment ──────────────────────────────────────────────

    def _assess_impact(self, incident: Incident):
        """Assess potential impact of the incident."""
        impacts = []
        phases = set(e.phase for e in incident.timeline)

        if AttackPhase.CREDENTIAL_ACCESS in phases:
            impacts.append("Credentials may be compromised - password reset required")
        if AttackPhase.LATERAL_MOVEMENT in phases:
            impacts.append(f"Lateral movement to {len(incident.affected_hosts)} hosts detected")
        if AttackPhase.EXFILTRATION in phases:
            impacts.append("Data exfiltration suspected - data loss assessment needed")
        if AttackPhase.PERSISTENCE in phases:
            impacts.append("Persistence established - host may remain compromised after reboot")
        if AttackPhase.COMMAND_AND_CONTROL in phases:
            impacts.append("Active C2 channel - attacker may have ongoing access")

        # Check for privileged user involvement
        priv_users = [u for u in incident.affected_users
                      if any(kw in u.upper() for kw in ['ADMIN', 'SYSTEM', 'ROOT'])]
        if priv_users:
            impacts.append(f"Privileged accounts involved: {', '.join(priv_users)}")

        if not impacts:
            impacts.append("Limited impact detected. Further monitoring recommended.")

        incident.impact_assessment = " | ".join(impacts)

    # ── Recommendations ────────────────────────────────────────────────

    def _generate_recommendations(self, incident: Incident):
        """Generate response recommendations."""
        recs = []
        phases = set(e.phase for e in incident.timeline)

        # Always
        recs.append("Isolate affected host(s) from network")

        if AttackPhase.CREDENTIAL_ACCESS in phases:
            recs.append("Reset all credentials for affected users")
            recs.append("Force password change for all accounts on affected hosts")
            recs.append("Review Active Directory for unauthorized changes")

        if AttackPhase.PERSISTENCE in phases:
            recs.append("Remove all identified persistence mechanisms (scheduled tasks, services, registry keys)")
            recs.append("Perform full malware scan on affected hosts")

        if AttackPhase.LATERAL_MOVEMENT in phases:
            recs.append("Scan all hosts in the network segment for compromise indicators")
            recs.append("Review network segmentation policies")

        if AttackPhase.COMMAND_AND_CONTROL in phases:
            recs.append("Block identified C2 IP addresses and domains at firewall")
            recs.append("Review proxy logs for additional C2 indicators")

        if AttackPhase.EXFILTRATION in phases:
            recs.append("Assess scope of data exposure")
            recs.append("Review DNS and proxy logs for data exfiltration indicators")
            recs.append("Notify data protection officer if PII involved")

        # IoC-based
        external_ips = [i for i in incident.iocs if i.type == "ip"]
        if external_ips:
            recs.append(f"Block external IPs: {', '.join(i.value for i in external_ips[:5])}")

        # Always
        recs.append("Preserve evidence and forensic artifacts")
        recs.append("Document incident timeline for post-incident review")

        incident.recommendations = recs

    # ── Key Findings ───────────────────────────────────────────────────

    def _generate_key_findings(self, incident: Incident):
        """Generate key findings summary."""
        findings = []

        findings.append(f"Incident involves {len(incident.events)} security events "
                        f"across {len(incident.affected_hosts)} host(s)")

        if incident.mitre_techniques:
            tech_names = [t["name"] for t in incident.mitre_techniques[:5]]
            findings.append(f"MITRE ATT&CK techniques identified: {', '.join(tech_names)}")

        phases = set(e.phase.value for e in incident.timeline
                     if e.phase != AttackPhase.UNKNOWN)
        if phases:
            findings.append(f"Attack phases observed: {', '.join(sorted(phases))}")

        if incident.iocs:
            findings.append(f"{len(incident.iocs)} unique Indicators of Compromise extracted")

        critical_events = [e for e in incident.timeline
                           if e.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_events:
            findings.append(f"{len(critical_events)} critical/high severity events detected")

        incident.key_findings = findings


# ── Singleton ──────────────────────────────────────────────────────────

_manager: Optional[IncidentManager] = None


def get_incident_manager() -> IncidentManager:
    global _manager
    if _manager is None:
        _manager = IncidentManager()
    return _manager
