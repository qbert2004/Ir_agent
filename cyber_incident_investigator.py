"""
Cyber Incident Investigation Agent
Специализированный ИИ-агент для расследования кибер-инцидентов

Возможности:
- Реконструкция timeline атаки
- Извлечение IoC (Indicators of Compromise)
- Attribution (определение TTP атакующего по MITRE ATT&CK)
- Root Cause Analysis
- Impact Assessment
- Forensic Analysis
- Генерация детальных отчетов о расследовании
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
from enum import Enum
import groq
from dotenv import load_dotenv

load_dotenv()


class IncidentType(Enum):
    """Типы кибер-инцидентов"""
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_THEFT = "credential_theft"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"
    DDOS = "ddos"
    PHISHING = "phishing"
    UNKNOWN = "unknown"


class InvestigationPhase(Enum):
    """Фазы расследования"""
    DETECTION = "detection"
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT = "post_incident"


@dataclass
class TimelineEvent:
    """Событие в timeline атаки"""
    timestamp: str
    hostname: str
    event_type: str
    description: str
    severity: str
    ioc: List[str]
    mitre_technique: Optional[str] = None
    raw_data: Optional[Dict] = None


@dataclass
class IndicatorOfCompromise:
    """Индикатор компрометации"""
    type: str  # ip, domain, hash, file_path, registry_key, process_name
    value: str
    confidence: float  # 0.0 - 1.0
    first_seen: str
    last_seen: str
    context: str


@dataclass
class TTPAnalysis:
    """Анализ тактик, техник и процедур"""
    tactics: List[str]  # MITRE ATT&CK tactics
    techniques: List[Dict[str, Any]]  # technique_id, name, confidence
    procedures: List[str]  # Конкретные процедуры
    attacker_profile: str
    sophistication_level: str  # low, medium, high, advanced


@dataclass
class InvestigationReport:
    """Отчет о расследовании инцидента"""
    incident_id: str
    incident_type: IncidentType
    title: str
    executive_summary: str
    timeline: List[TimelineEvent]
    iocs: List[IndicatorOfCompromise]
    ttp_analysis: TTPAnalysis
    root_cause: str
    entry_point: str
    affected_systems: List[str]
    data_exfiltrated: Optional[str]
    impact_assessment: Dict[str, Any]
    containment_actions: List[str]
    remediation_steps: List[str]
    lessons_learned: List[str]
    investigation_date: str
    investigator: str = "Cyber Incident Investigation AI Agent"


class CyberIncidentInvestigator:
    """
    ИИ-агент для расследования кибер-инцидентов

    Проводит полное расследование:
    1. Сбор и анализ всех событий инцидента
    2. Построение timeline атаки
    3. Извлечение IoC
    4. Определение TTP (MITRE ATT&CK)
    5. Root cause analysis
    6. Impact assessment
    7. Рекомендации по remediation
    8. Генерация финального отчета
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        if not self.api_key:
            raise ValueError("LLM_API_KEY not found")

        self.client = groq.Groq(api_key=self.api_key)
        self.model = os.getenv("LLM_ANALYZER_MODEL", "llama-3.3-70b-versatile")

        # Хранилище расследований
        self.investigations: Dict[str, InvestigationReport] = {}
        self.current_investigation: Optional[str] = None

        # База знаний MITRE ATT&CK
        self.mitre_knowledge = self._load_mitre_knowledge()

        print("=" * 70)
        print("Cyber Incident Investigation Agent")
        print("=" * 70)
        print(f"AI Model: {self.model}")
        print(f"Ready for incident investigation")
        print("=" * 70)

    def _load_mitre_knowledge(self) -> Dict[str, Any]:
        """Загружает базу знаний MITRE ATT&CK"""
        return {
            "reconnaissance": ["T1595", "T1590", "T1589", "T1598"],
            "resource_development": ["T1583", "T1586", "T1584", "T1587"],
            "initial_access": ["T1566", "T1091", "T1190", "T1078"],
            "execution": ["T1059", "T1053", "T1204", "T1106"],
            "persistence": ["T1547", "T1053", "T1543", "T1098"],
            "privilege_escalation": ["T1548", "T1134", "T1068", "T1055"],
            "defense_evasion": ["T1562", "T1070", "T1027", "T1564"],
            "credential_access": ["T1003", "T1110", "T1555", "T1552"],
            "discovery": ["T1087", "T1083", "T1046", "T1082"],
            "lateral_movement": ["T1021", "T1570", "T1080", "T1534"],
            "collection": ["T1560", "T1005", "T1039", "T1114"],
            "command_and_control": ["T1071", "T1573", "T1132", "T1001"],
            "exfiltration": ["T1041", "T1048", "T1567", "T1537"],
            "impact": ["T1486", "T1490", "T1529", "T1498"]
        }

    async def start_investigation(self, incident_id: str, events: List[Dict[str, Any]]) -> str:
        """
        Начинает новое расследование инцидента

        Args:
            incident_id: Уникальный ID инцидента
            events: Список событий, связанных с инцидентом

        Returns:
            Investigation ID
        """
        print(f"\n[+] Starting investigation: {incident_id}")
        print(f"[+] Events to analyze: {len(events)}")

        self.current_investigation = incident_id

        # Шаг 1: Первичный анализ и классификация
        print("\n[1/8] Initial triage and classification...")
        incident_type = await self._classify_incident(events)
        print(f"    Incident Type: {incident_type.value}")

        # Шаг 2: Построение timeline
        print("\n[2/8] Reconstructing attack timeline...")
        timeline = await self._build_timeline(events)
        print(f"    Timeline events: {len(timeline)}")

        # Шаг 3: Извлечение IoC
        print("\n[3/8] Extracting Indicators of Compromise...")
        iocs = await self._extract_iocs(events, timeline)
        print(f"    IoCs found: {len(iocs)}")

        # Шаг 4: TTP Analysis (MITRE ATT&CK)
        print("\n[4/8] Analyzing attacker TTP (MITRE ATT&CK)...")
        ttp_analysis = await self._analyze_ttp(events, timeline)
        print(f"    Tactics identified: {len(ttp_analysis.tactics)}")
        print(f"    Techniques identified: {len(ttp_analysis.techniques)}")

        # Шаг 5: Root Cause Analysis
        print("\n[5/8] Performing root cause analysis...")
        root_cause, entry_point = await self._root_cause_analysis(events, timeline)
        print(f"    Entry point: {entry_point}")

        # Шаг 6: Impact Assessment
        print("\n[6/8] Assessing impact...")
        impact = await self._assess_impact(events, timeline, iocs)
        print(f"    Affected systems: {len(impact.get('affected_systems', []))}")

        # Шаг 7: Containment & Remediation
        print("\n[7/8] Generating containment and remediation plan...")
        containment, remediation = await self._generate_response_plan(
            incident_type, ttp_analysis, iocs
        )
        print(f"    Containment actions: {len(containment)}")
        print(f"    Remediation steps: {len(remediation)}")

        # Шаг 8: Executive Summary
        print("\n[8/8] Generating executive summary...")
        exec_summary, title = await self._generate_executive_summary(
            incident_type, timeline, ttp_analysis, impact
        )

        # Создаем финальный отчет
        report = InvestigationReport(
            incident_id=incident_id,
            incident_type=incident_type,
            title=title,
            executive_summary=exec_summary,
            timeline=timeline,
            iocs=iocs,
            ttp_analysis=ttp_analysis,
            root_cause=root_cause,
            entry_point=entry_point,
            affected_systems=impact.get('affected_systems', []),
            data_exfiltrated=impact.get('data_exfiltrated'),
            impact_assessment=impact,
            containment_actions=containment,
            remediation_steps=remediation,
            lessons_learned=await self._extract_lessons_learned(timeline, ttp_analysis),
            investigation_date=datetime.utcnow().isoformat() + "Z"
        )

        self.investigations[incident_id] = report

        print(f"\n[OK] Investigation completed: {incident_id}")
        print("=" * 70)

        return incident_id

    def _parse_json_response(self, raw_response: str) -> Any:
        """Парсит JSON из ответа API, убирая markdown блоки"""
        try:
            # Убираем markdown блоки
            if "```json" in raw_response:
                raw_response = raw_response.split("```json")[1].split("```")[0]
            elif "```" in raw_response:
                raw_response = raw_response.split("```")[1].split("```")[0]

            return json.loads(raw_response.strip())
        except:
            return json.loads(raw_response)

    async def _classify_incident(self, events: List[Dict]) -> IncidentType:
        """Классифицирует тип инцидента"""

        prompt = f"""Analyze these security events and classify the incident type.

Events (showing first 10):
{json.dumps(events[:10], indent=2)}

Classify as one of:
- malware: Malware infection
- ransomware: Ransomware attack
- data_breach: Data breach/exfiltration
- lateral_movement: Lateral movement attack
- credential_theft: Credential theft/dumping
- insider_threat: Insider threat
- apt: Advanced Persistent Threat
- ddos: DDoS attack
- phishing: Phishing campaign
- unknown: Cannot determine

Respond ONLY with JSON (no markdown, no explanation):
{{
    "incident_type": "ransomware",
    "confidence": 0.9,
    "reasoning": "Brief explanation"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity incident responder. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=300
            )

            result = self._parse_json_response(response.choices[0].message.content)
            incident_type = result.get("incident_type", "unknown")

            return IncidentType(incident_type)
        except Exception as e:
            print(f"    [!] Classification error: {e}")
            return IncidentType.UNKNOWN

    async def _build_timeline(self, events: List[Dict]) -> List[TimelineEvent]:
        """Строит хронологический timeline атаки"""

        prompt = f"""Analyze these events and build a chronological attack timeline.

Events:
{json.dumps(events, indent=2)}

For each significant event in the attack, provide:
- timestamp
- hostname
- event_type
- description (what happened)
- severity (low/medium/high/critical)
- any IoCs (IPs, domains, hashes, file paths)
- MITRE ATT&CK technique if applicable

Respond ONLY with JSON array (no markdown, no explanation):
[
    {{
        "timestamp": "2024-01-01T10:00:00Z",
        "hostname": "srv-01",
        "event_type": "initial_access",
        "description": "Phishing email opened",
        "severity": "high",
        "ioc": ["malicious.pdf"],
        "mitre_technique": "T1566.001"
    }}
]"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a digital forensics expert. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )

            timeline_data = self._parse_json_response(response.choices[0].message.content)

            timeline = []
            for item in timeline_data:
                timeline.append(TimelineEvent(
                    timestamp=item.get("timestamp", ""),
                    hostname=item.get("hostname", ""),
                    event_type=item.get("event_type", ""),
                    description=item.get("description", ""),
                    severity=item.get("severity", "medium"),
                    ioc=item.get("ioc", []),
                    mitre_technique=item.get("mitre_technique")
                ))

            return sorted(timeline, key=lambda x: x.timestamp)
        except Exception as e:
            print(f"    [!] Timeline construction failed: {e}")
            return []

    async def _extract_iocs(self, events: List[Dict], timeline: List[TimelineEvent]) -> List[IndicatorOfCompromise]:
        """Извлекает все индикаторы компрометации"""

        prompt = f"""Extract all Indicators of Compromise (IoCs) from this incident.

Events:
{json.dumps(events[:20], indent=2)}

Timeline:
{json.dumps([asdict(t) for t in timeline[:10]], indent=2)}

Extract IoCs:
- IP addresses
- Domain names
- File hashes (MD5, SHA256)
- File paths
- Registry keys
- Process names
- URLs
- Email addresses

For each IoC provide:
- type
- value
- confidence (0.0-1.0)
- context (why is this an IoC?)

Respond ONLY with JSON array (no markdown):
[
    {{
        "type": "ip",
        "value": "192.168.1.100",
        "confidence": 0.9,
        "context": "C2 server communication"
    }}
]"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a threat intelligence analyst. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1500
            )

            ioc_data = self._parse_json_response(response.choices[0].message.content)

            now = datetime.utcnow().isoformat() + "Z"
            iocs = []
            for item in ioc_data:
                iocs.append(IndicatorOfCompromise(
                    type=item.get("type", "unknown"),
                    value=item.get("value", ""),
                    confidence=item.get("confidence", 0.5),
                    first_seen=now,
                    last_seen=now,
                    context=item.get("context", "")
                ))

            return iocs
        except Exception as e:
            print(f"    [!] IoC extraction failed: {e}")
            return []

    async def _analyze_ttp(self, events: List[Dict], timeline: List[TimelineEvent]) -> TTPAnalysis:
        """Анализирует TTP (Tactics, Techniques, Procedures) по MITRE ATT&CK"""

        prompt = f"""Analyze the attacker's Tactics, Techniques, and Procedures (TTP) using MITRE ATT&CK framework.

Timeline:
{json.dumps([asdict(t) for t in timeline], indent=2)}

Identify:
1. MITRE ATT&CK Tactics used (e.g., initial_access, execution, persistence)
2. Specific Techniques with IDs (e.g., T1059.001 - PowerShell)
3. Procedures (specific methods used)
4. Attacker profile/sophistication

Respond with JSON:
{{
    "tactics": ["initial_access", "execution", "persistence"],
    "techniques": [
        {{
            "id": "T1566.001",
            "name": "Spearphishing Attachment",
            "confidence": 0.9
        }}
    ],
    "procedures": ["Used macro-enabled document", "Scheduled task for persistence"],
    "attacker_profile": "APT group or sophisticated attacker",
    "sophistication_level": "high"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a MITRE ATT&CK expert and threat hunter. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1200
            )

            result = self._parse_json_response(response.choices[0].message.content)

            return TTPAnalysis(
                tactics=result.get("tactics", []),
                techniques=result.get("techniques", []),
                procedures=result.get("procedures", []),
                attacker_profile=result.get("attacker_profile", "Unknown"),
                sophistication_level=result.get("sophistication_level", "medium")
            )
        except Exception as e:
            print(f"    [!] TTP analysis failed: {e}")
            return TTPAnalysis([], [], [], "Unknown", "unknown")

    async def _root_cause_analysis(self, events: List[Dict], timeline: List[TimelineEvent]) -> Tuple[str, str]:
        """Определяет первопричину инцидента и точку входа"""

        prompt = f"""Perform root cause analysis for this security incident.

Timeline:
{json.dumps([asdict(t) for t in timeline], indent=2)}

Determine:
1. Root cause - fundamental reason the incident occurred
2. Entry point - how did the attacker initially gain access?

Consider:
- Vulnerabilities exploited
- Misconfigurations
- Human error
- Missing security controls

Respond ONLY with JSON (no markdown):
{{
    "root_cause": "Detailed explanation of root cause",
    "entry_point": "How attacker gained initial access"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior incident response analyst. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=600
            )

            result = self._parse_json_response(response.choices[0].message.content)

            return result.get("root_cause", "Unknown"), result.get("entry_point", "Unknown")
        except:
            return "Analysis failed", "Unknown"

    async def _assess_impact(self, events: List[Dict], timeline: List[TimelineEvent], iocs: List[IndicatorOfCompromise]) -> Dict[str, Any]:
        """Оценивает масштаб ущерба от инцидента"""

        # Собираем затронутые системы
        affected_systems = list(set([t.hostname for t in timeline]))

        prompt = f"""Assess the impact of this security incident.

Affected Systems: {affected_systems}
Timeline Events: {len(timeline)}
IoCs Found: {len(iocs)}

Events:
{json.dumps(events[:15], indent=2)}

Assess:
1. Data exfiltrated (if any)
2. Systems compromised
3. Business impact (operations, financial, reputational)
4. Severity (low/medium/high/critical)

Respond ONLY with JSON (no markdown):
{{
    "data_exfiltrated": "Description of data stolen or null",
    "systems_compromised": 5,
    "business_impact": "Detailed impact assessment",
    "severity": "high",
    "estimated_cost": "Estimated financial impact"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cyber risk analyst. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=600
            )

            result = self._parse_json_response(response.choices[0].message.content)
            result["affected_systems"] = affected_systems

            return result
        except:
            return {
                "affected_systems": affected_systems,
                "severity": "medium",
                "business_impact": "Unknown"
            }

    async def _generate_response_plan(self, incident_type: IncidentType, ttp: TTPAnalysis, iocs: List[IndicatorOfCompromise]) -> Tuple[List[str], List[str]]:
        """Генерирует план сдерживания и устранения"""

        prompt = f"""Generate containment and remediation plan for this incident.

Incident Type: {incident_type.value}
Attacker TTP: {ttp.tactics}
IoCs: {len(iocs)}

Provide:
1. Immediate containment actions
2. Step-by-step remediation plan

Respond ONLY with JSON (no markdown):
{{
    "containment": [
        "Isolate affected systems from network",
        "Block IoC IPs at firewall"
    ],
    "remediation": [
        "Remove malware from systems",
        "Reset compromised credentials",
        "Patch vulnerabilities"
    ]
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an incident response team leader. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=800
            )

            result = self._parse_json_response(response.choices[0].message.content)

            return result.get("containment", []), result.get("remediation", [])
        except:
            return [], []

    async def _generate_executive_summary(self, incident_type: IncidentType, timeline: List[TimelineEvent], ttp: TTPAnalysis, impact: Dict) -> Tuple[str, str]:
        """Генерирует executive summary для руководства"""

        prompt = f"""Write an executive summary for this cyber incident.

Incident Type: {incident_type.value}
Timeline Events: {len(timeline)}
Attacker Tactics: {', '.join(ttp.tactics)}
Sophistication: {ttp.sophistication_level}
Impact: {impact.get('severity', 'medium')}

Write in clear business language for executives.
Include:
- What happened
- Impact on business
- Current status
- Next steps

Respond ONLY with JSON (no markdown):
{{
    "title": "Short incident title",
    "summary": "2-3 paragraph executive summary"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a CISO writing to the board. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_tokens=500
            )

            result = self._parse_json_response(response.choices[0].message.content)

            return result.get("summary", ""), result.get("title", "Cyber Security Incident")
        except:
            return "Investigation in progress", "Security Incident"

    async def _extract_lessons_learned(self, timeline: List[TimelineEvent], ttp: TTPAnalysis) -> List[str]:
        """Извлекает уроки из инцидента"""

        prompt = f"""Extract lessons learned from this incident.

Timeline: {len(timeline)} events
Attacker sophistication: {ttp.sophistication_level}

What could have prevented this?
What should be improved?

Provide 3-5 key lessons learned as list.

Respond ONLY with JSON (no markdown):
{{
    "lessons": [
        "Implement MFA for all accounts",
        "Improve email security filtering"
    ]
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security improvement consultant. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_tokens=400
            )

            result = self._parse_json_response(response.choices[0].message.content)
            return result.get("lessons", [])
        except:
            return []

    def get_investigation_report(self, incident_id: str, format: str = "text") -> str:
        """
        Получить отчет о расследовании

        Args:
            incident_id: ID инцидента
            format: "text" или "json"
        """
        if incident_id not in self.investigations:
            return f"Investigation {incident_id} not found"

        report = self.investigations[incident_id]

        if format == "json":
            return json.dumps(asdict(report), indent=2, default=str)

        # Форматированный текстовый отчет
        output = []
        output.append("=" * 80)
        output.append("CYBER INCIDENT INVESTIGATION REPORT")
        output.append("=" * 80)
        output.append(f"\nIncident ID: {report.incident_id}")
        output.append(f"Title: {report.title}")
        output.append(f"Type: {report.incident_type.value.upper()}")
        output.append(f"Investigation Date: {report.investigation_date}")
        output.append(f"Investigator: {report.investigator}")

        output.append("\n" + "=" * 80)
        output.append("EXECUTIVE SUMMARY")
        output.append("=" * 80)
        output.append(f"\n{report.executive_summary}")

        output.append("\n" + "=" * 80)
        output.append("ATTACK TIMELINE")
        output.append("=" * 80)
        for i, event in enumerate(report.timeline, 1):
            output.append(f"\n[{i}] {event.timestamp} | {event.hostname}")
            output.append(f"    Type: {event.event_type} | Severity: {event.severity.upper()}")
            output.append(f"    {event.description}")
            if event.mitre_technique:
                output.append(f"    MITRE: {event.mitre_technique}")
            if event.ioc:
                output.append(f"    IoCs: {', '.join(event.ioc)}")

        output.append("\n" + "=" * 80)
        output.append("INDICATORS OF COMPROMISE (IOCs)")
        output.append("=" * 80)
        for ioc in report.iocs:
            output.append(f"\n{ioc.type.upper()}: {ioc.value}")
            output.append(f"  Confidence: {ioc.confidence:.0%}")
            output.append(f"  Context: {ioc.context}")

        output.append("\n" + "=" * 80)
        output.append("TTP ANALYSIS (MITRE ATT&CK)")
        output.append("=" * 80)
        output.append(f"\nAttacker Profile: {report.ttp_analysis.attacker_profile}")
        output.append(f"Sophistication Level: {report.ttp_analysis.sophistication_level.upper()}")
        output.append(f"\nTactics: {', '.join(report.ttp_analysis.tactics)}")
        output.append("\nTechniques:")
        for tech in report.ttp_analysis.techniques:
            output.append(f"  - {tech.get('id')}: {tech.get('name')} (confidence: {tech.get('confidence', 0):.0%})")

        output.append("\n" + "=" * 80)
        output.append("ROOT CAUSE ANALYSIS")
        output.append("=" * 80)
        output.append(f"\nEntry Point: {report.entry_point}")
        output.append(f"\nRoot Cause: {report.root_cause}")

        output.append("\n" + "=" * 80)
        output.append("IMPACT ASSESSMENT")
        output.append("=" * 80)
        output.append(f"\nAffected Systems: {len(report.affected_systems)}")
        for system in report.affected_systems:
            output.append(f"  - {system}")
        output.append(f"\nSeverity: {report.impact_assessment.get('severity', 'unknown').upper()}")
        output.append(f"\nBusiness Impact: {report.impact_assessment.get('business_impact', 'Unknown')}")
        if report.data_exfiltrated:
            output.append(f"\nData Exfiltrated: {report.data_exfiltrated}")

        output.append("\n" + "=" * 80)
        output.append("CONTAINMENT ACTIONS")
        output.append("=" * 80)
        for i, action in enumerate(report.containment_actions, 1):
            output.append(f"{i}. {action}")

        output.append("\n" + "=" * 80)
        output.append("REMEDIATION STEPS")
        output.append("=" * 80)
        for i, step in enumerate(report.remediation_steps, 1):
            output.append(f"{i}. {step}")

        output.append("\n" + "=" * 80)
        output.append("LESSONS LEARNED")
        output.append("=" * 80)
        for i, lesson in enumerate(report.lessons_learned, 1):
            output.append(f"{i}. {lesson}")

        output.append("\n" + "=" * 80)
        output.append("END OF REPORT")
        output.append("=" * 80)

        return "\n".join(output)

    def list_investigations(self) -> List[str]:
        """Список всех расследований"""
        return list(self.investigations.keys())


# Пример использования
async def example_investigation():
    """Пример расследования ransomware атаки"""

    investigator = CyberIncidentInvestigator()

    # События ransomware инцидента
    events = [
        {
            "timestamp": "2024-01-15T08:30:00Z",
            "event_id": "4624",
            "hostname": "WS-USER01",
            "event_type": "logon",
            "user": "john.doe",
            "logon_type": "2",
            "description": "User logged in"
        },
        {
            "timestamp": "2024-01-15T08:35:00Z",
            "event_id": "4688",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "outlook.exe",
            "user": "john.doe",
            "description": "Outlook opened"
        },
        {
            "timestamp": "2024-01-15T08:37:00Z",
            "event_id": "4688",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "invoice_2024.exe",
            "parent_process": "outlook.exe",
            "user": "john.doe",
            "description": "Suspicious executable launched from email attachment"
        },
        {
            "timestamp": "2024-01-15T08:38:00Z",
            "hostname": "WS-USER01",
            "event_type": "network",
            "destination_ip": "185.220.101.45",
            "destination_port": 443,
            "description": "Outbound connection to suspicious IP"
        },
        {
            "timestamp": "2024-01-15T08:40:00Z",
            "event_id": "4688",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
            "description": "Shadow copies deletion attempt"
        },
        {
            "timestamp": "2024-01-15T08:42:00Z",
            "event_id": "4663",
            "hostname": "WS-USER01",
            "event_type": "file_access",
            "file_path": "C:\\Users\\john.doe\\Documents\\financial_report.xlsx",
            "access_type": "write",
            "description": "File encryption started"
        },
        {
            "timestamp": "2024-01-15T08:45:00Z",
            "hostname": "WS-USER01",
            "event_type": "file_creation",
            "file_path": "C:\\Users\\john.doe\\Desktop\\README_DECRYPT.txt",
            "description": "Ransom note created"
        },
        {
            "timestamp": "2024-01-15T08:50:00Z",
            "event_id": "4624",
            "hostname": "FILE-SRV01",
            "event_type": "logon",
            "logon_type": "3",
            "source_ip": "192.168.1.150",
            "user": "john.doe",
            "description": "Network logon to file server"
        },
        {
            "timestamp": "2024-01-15T08:52:00Z",
            "event_id": "4663",
            "hostname": "FILE-SRV01",
            "event_type": "file_access",
            "file_path": "\\\\FILE-SRV01\\shared\\projects\\",
            "access_type": "write",
            "description": "Shared files encryption"
        }
    ]

    # Запускаем расследование
    incident_id = await investigator.start_investigation("INC-2024-001", events)

    # Получаем отчет
    print("\n\n")
    report = investigator.get_investigation_report(incident_id, format="text")
    print(report)

    # Также можно получить в JSON
    # json_report = investigator.get_investigation_report(incident_id, format="json")
    # print(json_report)


if __name__ == "__main__":
    print("\nCyber Incident Investigation Agent")
    print("Example: Ransomware Attack Investigation\n")

    asyncio.run(example_investigation())
