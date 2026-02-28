"""
ThreatAssessment Engine — единый центр принятия решений IR-Agent.

Архитектура до этого файла:
    ML Engine → score (float)
    IoC lookup → is_malicious (bool)
    MITRE mapper → techniques (list)
    Agent (LLM) → verdict (string)
    IncidentManager → confidence (float)

Проблема: каждый источник генерировал свой "threat state" независимо.
Агент мог сказать FALSE_POSITIVE, а ML вернуть 0.95 confidence —
и система не знала, кому верить.

Решение — ThreatAssessmentEngine:

    Inputs                     Weights
    ──────────────────────     ───────
    ML classifier score        0.35
    IoC provider score         0.30
    MITRE technique density    0.20
    Agent (LLM) verdict        0.15  ← самый низкий: LLM может галлюцинировать

    ↓ Bayesian-inspired weighted fusion
    ↓ Arbitration rules (блокирующие условия)
    ↓
    ThreatAssessment (final_score, severity, confidence_level, explanation)

Arbitration rules (hard overrides):
    - CRITICAL: ≥2 IoC провайдера подтвердили malicious → severity=CRITICAL независимо
    - CRITICAL: lsass dump + credential access technique → severity=CRITICAL
    - DOWN-GRADE: Agent вернул FALSE_POSITIVE при ML < 0.6 → severity=LOW
    - ESCALATE: MITRE lateral_movement + credential_access в одном инциденте → HIGH min

Explainability:
    Каждый вклад логируется в explanation_trace для аудита и отладки.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

logger = logging.getLogger("ir-agent")


# ── Severity levels ───────────────────────────────────────────────────────────

class ThreatSeverity(str, Enum):
    CRITICAL = "critical"      # ≥ 85 — требует немедленного реагирования
    HIGH     = "high"          # 65–84 — эскалировать в течение 1 часа
    MEDIUM   = "medium"        # 45–64 — расследовать в течение рабочего дня
    LOW      = "low"           # 25–44 — мониторить
    INFO     = "info"          # < 25  — информационное

    @classmethod
    def from_score(cls, score: float) -> "ThreatSeverity":
        if score >= 85:  return cls.CRITICAL
        if score >= 65:  return cls.HIGH
        if score >= 45:  return cls.MEDIUM
        if score >= 25:  return cls.LOW
        return cls.INFO


class ConfidenceLevel(str, Enum):
    """Уверенность в оценке (зависит от числа доступных источников)."""
    HIGH   = "high"    # ≥ 3 источников согласны
    MEDIUM = "medium"  # 2 источника согласны
    LOW    = "low"     # 1 источник или сильное расхождение


# ── Input signals ─────────────────────────────────────────────────────────────

@dataclass
class MLSignal:
    """Сигнал от ML-классификатора (GradientBoosting / heuristics)."""
    score: float            # 0.0–1.0 (вероятность malicious)
    is_malicious: bool
    reason: str = ""
    model_loaded: bool = True  # False = только heuristics


@dataclass
class IoCSignal:
    """Сигнал от IoC lookup (VirusTotal + AbuseIPDB + local)."""
    score: float           # 0.0–1.0 (агрегированная уверенность)
    is_malicious: bool
    providers_hit: List[str] = field(default_factory=list)  # VirusTotal, AbuseIPDB, local
    indicator_count: int = 0  # число проверенных индикаторов


@dataclass
class MITRESignal:
    """Сигнал от MITRE ATT&CK маппера."""
    techniques: List[Dict[str, Any]] = field(default_factory=list)
    tactic_coverage: List[str] = field(default_factory=list)  # список задействованных тактик
    max_confidence: float = 0.0
    has_lateral_movement: bool = False
    has_credential_access: bool = False
    has_impact: bool = False


@dataclass
class AgentSignal:
    """Сигнал от LLM-агента (ReAct вердикт)."""
    verdict: str          # MALICIOUS / SUSPICIOUS / FALSE_POSITIVE / UNKNOWN
    confidence: float     # 0.0–1.0 (из парсинга ответа)
    tools_used: List[str] = field(default_factory=list)
    reasoning_steps: int = 0


# ── Assessment result ─────────────────────────────────────────────────────────

@dataclass
class ThreatAssessment:
    """
    Итоговая оценка угрозы — единый объект решения для всей системы.

    Используется как:
    - критерий эскалации в IncidentManager
    - фильтр forwarding в EventProcessor
    - ответ в API endpoint /assessment
    - аудит-запись в БД
    """
    final_score: float                     # 0–100 (нормированный)
    severity: ThreatSeverity
    confidence_level: ConfidenceLevel

    # Декомпозиция по источникам (для explainability)
    ml_contribution: float     = 0.0      # взвешенный вклад ML (0–100)
    ioc_contribution: float    = 0.0      # взвешенный вклад IoC
    mitre_contribution: float  = 0.0      # взвешенный вклад MITRE
    agent_contribution: float  = 0.0      # взвешенный вклад агента

    # Источники, доступные при оценке
    sources_available: List[str]     = field(default_factory=list)
    sources_agreeing: List[str]      = field(default_factory=list)  # проголосовали malicious

    # Активированные арбитражные правила
    arbitration_rules_fired: List[str] = field(default_factory=list)

    # Человекочитаемое объяснение
    explanation: str = ""
    explanation_trace: List[str] = field(default_factory=list)  # пошаговый лог

    # Рекомендуемое действие
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "final_score": round(self.final_score, 1),
            "severity": self.severity.value,
            "confidence_level": self.confidence_level.value,
            "score_breakdown": {
                "ml":    round(self.ml_contribution,    1),
                "ioc":   round(self.ioc_contribution,   1),
                "mitre": round(self.mitre_contribution, 1),
                "agent": round(self.agent_contribution, 1),
            },
            "sources_available": self.sources_available,
            "sources_agreeing":  self.sources_agreeing,
            "arbitration_rules": self.arbitration_rules_fired,
            "explanation": self.explanation,
            "explanation_trace": self.explanation_trace,
            "recommended_action": self.recommended_action,
        }


# ── Engine ────────────────────────────────────────────────────────────────────

# Веса источников. Сумма = 1.0
# Agent получает наименьший вес — LLM нестабилен, может галлюцинировать.
# ML — самый надёжный детерминированный источник.
_WEIGHTS = {
    "ml":    0.35,
    "ioc":   0.30,
    "mitre": 0.20,
    "agent": 0.15,
}

# Если источник недоступен — его вес перераспределяется между остальными
# пропорционально их весам.


def _redistribute_weights(available: List[str]) -> Dict[str, float]:
    """Перераспределить веса для доступных источников."""
    if not available:
        return {}
    total = sum(_WEIGHTS[s] for s in available)
    if total == 0:
        return {s: 1.0 / len(available) for s in available}
    return {s: _WEIGHTS[s] / total for s in available}


class ThreatAssessmentEngine:
    """
    Единый движок оценки угроз.

    Принимает сигналы от всех источников, применяет взвешенную агрегацию
    и арбитражные правила, возвращает ThreatAssessment.

    Использование:
        engine = ThreatAssessmentEngine()
        assessment = engine.assess(
            ml=MLSignal(score=0.85, is_malicious=True, reason="lsass dump"),
            ioc=IoCSignal(score=0.7, is_malicious=True, providers_hit=["VirusTotal"]),
            mitre=MITRESignal(techniques=[...], has_credential_access=True),
            agent=AgentSignal(verdict="MALICIOUS", confidence=0.9),
        )
    """

    def assess(
        self,
        ml:    Optional[MLSignal]    = None,
        ioc:   Optional[IoCSignal]   = None,
        mitre: Optional[MITRESignal] = None,
        agent: Optional[AgentSignal] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ThreatAssessment:
        """
        Главный метод. Все параметры опциональны —
        система работает даже при отсутствии части источников.
        """
        trace: List[str] = []
        available: List[str] = []
        agreeing: List[str] = []
        rules_fired: List[str] = []

        # ── 1. Нормализованные сигналы (0.0–1.0) ─────────────────────────────
        ml_raw    = self._normalize_ml(ml,    trace, available, agreeing)
        ioc_raw   = self._normalize_ioc(ioc,  trace, available, agreeing)
        mitre_raw = self._normalize_mitre(mitre, trace, available, agreeing)
        agent_raw = self._normalize_agent(agent, trace, available, agreeing)

        # ── 2. Взвешенная агрегация ───────────────────────────────────────────
        weights = _redistribute_weights(available)
        trace.append(f"Weights (redistributed): { {k: f'{v:.2f}' for k, v in weights.items()} }")

        weighted_score = (
            weights.get("ml",    0) * ml_raw    +
            weights.get("ioc",   0) * ioc_raw   +
            weights.get("mitre", 0) * mitre_raw +
            weights.get("agent", 0) * agent_raw
        )
        base_score = weighted_score * 100  # перевод в 0–100

        trace.append(
            f"Base weighted score: {base_score:.1f} / 100  "
            f"(ml={ml_raw:.2f}, ioc={ioc_raw:.2f}, "
            f"mitre={mitre_raw:.2f}, agent={agent_raw:.2f})"
        )

        # ── 3. Арбитражные правила (hard overrides) ───────────────────────────
        final_score, rules_fired = self._apply_arbitration(
            base_score, ml, ioc, mitre, agent, trace
        )

        # ── 4. Severity и confidence ──────────────────────────────────────────
        severity = ThreatSeverity.from_score(final_score)
        confidence_level = self._compute_confidence(available, agreeing, len(rules_fired))

        trace.append(f"Final score: {final_score:.1f} → severity={severity.value}, "
                     f"confidence={confidence_level.value}")

        # ── 5. Объяснение и рекомендации ──────────────────────────────────────
        explanation = self._build_explanation(
            final_score, severity, ml, ioc, mitre, agent, agreeing, rules_fired
        )
        recommended_action = self._recommend_action(severity, confidence_level)

        return ThreatAssessment(
            final_score=round(final_score, 1),
            severity=severity,
            confidence_level=confidence_level,
            ml_contribution=round(weights.get("ml", 0) * ml_raw * 100, 1),
            ioc_contribution=round(weights.get("ioc", 0) * ioc_raw * 100, 1),
            mitre_contribution=round(weights.get("mitre", 0) * mitre_raw * 100, 1),
            agent_contribution=round(weights.get("agent", 0) * agent_raw * 100, 1),
            sources_available=available,
            sources_agreeing=agreeing,
            arbitration_rules_fired=rules_fired,
            explanation=explanation,
            explanation_trace=trace,
            recommended_action=recommended_action,
        )

    # ── Normalizers ───────────────────────────────────────────────────────────

    def _normalize_ml(
        self,
        sig: Optional[MLSignal],
        trace: List[str],
        available: List[str],
        agreeing: List[str],
    ) -> float:
        if sig is None:
            trace.append("ML: not available (skipped)")
            return 0.0

        available.append("ml")
        score = float(sig.score)

        # Штраф за heuristic-only режим (модель не загружена)
        if not sig.model_loaded:
            score *= 0.7
            trace.append(f"ML: heuristic-only (penalty 0.7x) → {score:.2f}")
        else:
            trace.append(f"ML: score={sig.score:.2f}, reason='{sig.reason}'")

        if sig.is_malicious:
            agreeing.append("ml")
        return min(max(score, 0.0), 1.0)

    def _normalize_ioc(
        self,
        sig: Optional[IoCSignal],
        trace: List[str],
        available: List[str],
        agreeing: List[str],
    ) -> float:
        if sig is None:
            trace.append("IoC: not available (skipped)")
            return 0.0

        available.append("ioc")
        score = float(sig.score)

        # Бонус при множественных провайдерах
        if len(sig.providers_hit) >= 2:
            score = min(score * 1.15, 1.0)
            trace.append(
                f"IoC: score={sig.score:.2f} (+15% multi-provider bonus) → {score:.2f}, "
                f"providers={sig.providers_hit}"
            )
        else:
            trace.append(
                f"IoC: score={score:.2f}, providers={sig.providers_hit}, "
                f"indicators={sig.indicator_count}"
            )

        if sig.is_malicious:
            agreeing.append("ioc")
        return min(max(score, 0.0), 1.0)

    def _normalize_mitre(
        self,
        sig: Optional[MITRESignal],
        trace: List[str],
        available: List[str],
        agreeing: List[str],
    ) -> float:
        if sig is None or not sig.techniques:
            trace.append("MITRE: no techniques detected")
            return 0.0

        available.append("mitre")

        # Базовый сигнал: max confidence по техникам
        base = sig.max_confidence

        # Тактическое разнообразие — признак многоэтапной атаки
        n_tactics = len(set(sig.tactic_coverage))
        tactic_bonus = min(n_tactics * 0.05, 0.25)  # до +25%

        # Критические комбинации тактик
        combo_bonus = 0.0
        if sig.has_credential_access and sig.has_lateral_movement:
            combo_bonus += 0.20
            trace.append("MITRE: credential_access + lateral_movement combo → +0.20")
        if sig.has_impact:
            combo_bonus += 0.15
            trace.append("MITRE: impact tactic detected → +0.15")

        score = min(base + tactic_bonus + combo_bonus, 1.0)

        trace.append(
            f"MITRE: {len(sig.techniques)} techniques, {n_tactics} tactics, "
            f"base={base:.2f}, tactic_bonus={tactic_bonus:.2f}, "
            f"combo_bonus={combo_bonus:.2f} → {score:.2f}"
        )

        # MITRE vote: если есть ≥3 техники с confidence > 0.3 → голосует за malicious
        high_conf_tech = [t for t in sig.techniques if t.get("confidence", 0) >= 0.3]
        if len(high_conf_tech) >= 3:
            agreeing.append("mitre")

        return score

    def _normalize_agent(
        self,
        sig: Optional[AgentSignal],
        trace: List[str],
        available: List[str],
        agreeing: List[str],
    ) -> float:
        if sig is None:
            trace.append("Agent: not available (skipped)")
            return 0.0

        available.append("agent")

        verdict_map = {
            "MALICIOUS":      1.0,
            "SUSPICIOUS":     0.6,
            "FALSE_POSITIVE": 0.05,
            "UNKNOWN":        0.3,
        }
        verdict_score = verdict_map.get(sig.verdict.upper(), 0.3)

        # Взвешиваем с confidence агента
        score = verdict_score * min(sig.confidence, 1.0)

        # Бонус за использование большего числа инструментов (агент глубже расследовал)
        if sig.reasoning_steps >= 5:
            score = min(score * 1.1, 1.0)

        trace.append(
            f"Agent: verdict={sig.verdict}, confidence={sig.confidence:.2f}, "
            f"tools_used={sig.tools_used}, steps={sig.reasoning_steps} → {score:.2f}"
        )

        if sig.verdict.upper() in ("MALICIOUS", "SUSPICIOUS"):
            agreeing.append("agent")

        return min(max(score, 0.0), 1.0)

    # ── Arbitration ───────────────────────────────────────────────────────────

    def _apply_arbitration(
        self,
        base_score: float,
        ml:    Optional[MLSignal],
        ioc:   Optional[IoCSignal],
        mitre: Optional[MITRESignal],
        agent: Optional[AgentSignal],
        trace: List[str],
    ) -> tuple[float, List[str]]:
        """
        Арбитражные правила — блокирующие условия, которые могут
        принудительно повысить или понизить итоговую оценку.

        Порядок применения: сначала escation-правила, затем downgrade.
        """
        score = base_score
        rules: List[str] = []

        # ── ESCALATION RULES ──────────────────────────────────────────────────

        # R1: Множественные IoC провайдеры подтвердили → CRITICAL minimum
        if ioc and ioc.is_malicious and len(ioc.providers_hit) >= 2:
            if score < 85:
                score = max(score, 85.0)
                rule = "R1: ≥2 IoC providers confirmed malicious → score forced ≥85 (CRITICAL)"
                rules.append(rule)
                trace.append(f"Arbitration {rule}")

        # R2: LSASS / credential dump паттерн в ML reason
        if ml and ml.is_malicious:
            reason_lower = ml.reason.lower()
            if any(kw in reason_lower for kw in ["lsass", "sekurlsa", "credential", "dump"]):
                if score < 80:
                    score = max(score, 80.0)
                    rule = "R2: credential dump detected in ML reason → score ≥80"
                    rules.append(rule)
                    trace.append(f"Arbitration {rule}")

        # R3: MITRE combo — lateral_movement + credential_access → HIGH minimum
        if mitre and mitre.has_lateral_movement and mitre.has_credential_access:
            if score < 65:
                score = max(score, 65.0)
                rule = "R3: lateral_movement + credential_access combo → score ≥65 (HIGH)"
                rules.append(rule)
                trace.append(f"Arbitration {rule}")

        # R4: MITRE impact tactic → HIGH minimum
        if mitre and mitre.has_impact:
            if score < 65:
                score = max(score, 65.0)
                rule = "R4: MITRE impact tactic active → score ≥65"
                rules.append(rule)
                trace.append(f"Arbitration {rule}")

        # R5: Все 3+ источника согласны → confidence boost
        available_agreeing = 0
        if ml and ml.is_malicious:        available_agreeing += 1
        if ioc and ioc.is_malicious:      available_agreeing += 1
        if agent and agent.verdict.upper() == "MALICIOUS":
            available_agreeing += 1
        if available_agreeing >= 3:
            bonus = min(score * 0.10, 10.0)
            score = min(score + bonus, 100.0)
            rule = f"R5: all {available_agreeing} sources agree → +{bonus:.1f} bonus"
            rules.append(rule)
            trace.append(f"Arbitration {rule}")

        # ── DOWNGRADE RULES ───────────────────────────────────────────────────

        # R6: Agent уверенно вернул FALSE_POSITIVE при низком ML score → понизить
        if (agent and agent.verdict.upper() == "FALSE_POSITIVE"
                and agent.confidence >= 0.7
                and ml and ml.score < 0.6):
            if score > 25:
                score = min(score, 25.0)
                rule = (f"R6: Agent HIGH_CONFIDENCE FALSE_POSITIVE + ML < 0.6 "
                        f"→ score capped at 25 (LOW)")
                rules.append(rule)
                trace.append(f"Arbitration {rule}")

        # R7: IoC clean + Agent FALSE_POSITIVE при умеренном ML (0.5–0.7)
        if (ioc and not ioc.is_malicious
                and agent and agent.verdict.upper() == "FALSE_POSITIVE"
                and ml and 0.5 <= ml.score <= 0.7):
            if score > 40:
                score = min(score, 40.0)
                rule = "R7: IoC clean + Agent FP + ML uncertain → score capped at 40"
                rules.append(rule)
                trace.append(f"Arbitration {rule}")

        return round(score, 1), rules

    # ── Confidence level ──────────────────────────────────────────────────────

    def _compute_confidence(
        self,
        available: List[str],
        agreeing: List[str],
        rules_fired: int,
    ) -> ConfidenceLevel:
        """
        Уверенность в оценке = насколько согласованы источники.

        Не путать с threat score — это meta-уверенность в достоверности оценки.
        """
        n_available = len(available)
        n_agreeing  = len(agreeing)

        if n_available == 0:
            return ConfidenceLevel.LOW

        agreement_ratio = n_agreeing / n_available

        # Высокая уверенность: ≥3 источника, большинство согласны
        if n_available >= 3 and agreement_ratio >= 0.67:
            return ConfidenceLevel.HIGH
        # Средняя: ≥2 источника с частичным согласием, или арбитраж сработал
        if n_available >= 2 and (agreement_ratio >= 0.5 or rules_fired > 0):
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    # ── Explanation builder ───────────────────────────────────────────────────

    def _build_explanation(
        self,
        final_score: float,
        severity: ThreatSeverity,
        ml: Optional[MLSignal],
        ioc: Optional[IoCSignal],
        mitre: Optional[MITRESignal],
        agent: Optional[AgentSignal],
        agreeing: List[str],
        rules_fired: List[str],
    ) -> str:
        """Генерирует человекочитаемое объяснение итогового вердикта."""
        parts = [f"Threat Assessment: {severity.value.upper()} (score={final_score:.0f}/100)"]

        if ml:
            status = "MALICIOUS" if ml.is_malicious else "BENIGN"
            model_note = "" if ml.model_loaded else " [heuristic fallback]"
            parts.append(f"• ML Classifier: {status} ({ml.score:.0%} confidence){model_note}"
                         + (f" — {ml.reason}" if ml.reason else ""))

        if ioc:
            status = "MALICIOUS" if ioc.is_malicious else "CLEAN"
            providers = ", ".join(ioc.providers_hit) if ioc.providers_hit else "no providers"
            parts.append(f"• IoC Lookup: {status} (score={ioc.score:.0%}, via {providers})")

        if mitre and mitre.techniques:
            top = mitre.techniques[:3]
            tech_str = ", ".join(
                f"{t.get('id','?')} {t.get('name','?')}"
                for t in top
            )
            parts.append(
                f"• MITRE ATT&CK: {len(mitre.techniques)} techniques matched "
                f"[{', '.join(mitre.tactic_coverage[:3])}] — {tech_str}"
            )

        if agent:
            parts.append(
                f"• Agent Analysis: {agent.verdict} "
                f"(confidence={agent.confidence:.0%}, "
                f"tools={len(agent.tools_used)}, steps={agent.reasoning_steps})"
            )

        if rules_fired:
            parts.append(f"• Arbitration rules fired: {'; '.join(rules_fired)}")

        if len(agreeing) >= 2:
            parts.append(f"• Consensus: {', '.join(agreeing)} sources agree on malicious verdict")

        return "\n".join(parts)

    # ── Recommendation ────────────────────────────────────────────────────────

    def _recommend_action(
        self,
        severity: ThreatSeverity,
        confidence: ConfidenceLevel,
    ) -> str:
        matrix = {
            (ThreatSeverity.CRITICAL, ConfidenceLevel.HIGH):   "IMMEDIATE: Isolate host, escalate to SOC L3, preserve forensics",
            (ThreatSeverity.CRITICAL, ConfidenceLevel.MEDIUM): "URGENT: Escalate to SOC L2, begin containment, verify with analyst",
            (ThreatSeverity.CRITICAL, ConfidenceLevel.LOW):    "URGENT: Manual review required — high severity but limited signal confidence",
            (ThreatSeverity.HIGH,     ConfidenceLevel.HIGH):   "ESCALATE: Assign incident to analyst within 1 hour",
            (ThreatSeverity.HIGH,     ConfidenceLevel.MEDIUM): "ESCALATE: Review within 1 hour, begin timeline reconstruction",
            (ThreatSeverity.HIGH,     ConfidenceLevel.LOW):    "REVIEW: Gather additional context before escalation",
            (ThreatSeverity.MEDIUM,   ConfidenceLevel.HIGH):   "INVESTIGATE: Standard investigation within business hours",
            (ThreatSeverity.MEDIUM,   ConfidenceLevel.MEDIUM): "MONITOR: Watch for additional indicators",
            (ThreatSeverity.MEDIUM,   ConfidenceLevel.LOW):    "MONITOR: Low confidence — collect more telemetry",
            (ThreatSeverity.LOW,      ConfidenceLevel.HIGH):   "LOG: Record and monitor for pattern",
            (ThreatSeverity.LOW,      ConfidenceLevel.MEDIUM): "LOG: No immediate action required",
            (ThreatSeverity.LOW,      ConfidenceLevel.LOW):    "LOG: Likely false positive — verify rule quality",
            (ThreatSeverity.INFO,     ConfidenceLevel.HIGH):   "IGNORE: Clean event, no action needed",
            (ThreatSeverity.INFO,     ConfidenceLevel.MEDIUM): "IGNORE: Probably benign",
            (ThreatSeverity.INFO,     ConfidenceLevel.LOW):    "IGNORE: Insufficient signal",
        }
        return matrix.get((severity, confidence), "REVIEW: Manual assessment recommended")


# ── Singleton ─────────────────────────────────────────────────────────────────

_engine_instance: Optional[ThreatAssessmentEngine] = None


def get_assessment_engine() -> ThreatAssessmentEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ThreatAssessmentEngine()
    return _engine_instance
