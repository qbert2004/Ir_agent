# ML-First Architecture

## Обзор

Система использует **ML-модели как основной движок** для всего анализа.
**LLM (Groq) используется ТОЛЬКО для генерации текстовых отчётов**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ML-FIRST ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                        INPUT: Security Events                        │  │
│   └─────────────────────────────────┬───────────────────────────────────┘  │
│                                     │                                       │
│                                     ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                      CYBER ML ENGINE                                 │  │
│   │                    (All Analysis - No LLM)                           │  │
│   │                                                                      │  │
│   │   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │  │
│   │   │   Event     │ │  Incident   │ │   MITRE     │ │    IoC      │  │  │
│   │   │ Classifier  │ │   Type      │ │   Mapper    │ │  Extractor  │  │  │
│   │   │   (ML)      │ │ Classifier  │ │ (Rules)     │ │  (Regex)    │  │  │
│   │   └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘  │  │
│   │                                                                      │  │
│   │   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                   │  │
│   │   │  Timeline   │ │   Threat    │ │   Key       │                   │  │
│   │   │  Builder    │ │   Scorer    │ │  Findings   │                   │  │
│   │   │             │ │ (Algorithm) │ │  Generator  │                   │  │
│   │   └─────────────┘ └─────────────┘ └─────────────┘                   │  │
│   └─────────────────────────────────┬───────────────────────────────────┘  │
│                                     │                                       │
│                                     ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                    ML INVESTIGATION RESULT                           │  │
│   │              (Structured Data - No LLM Needed)                       │  │
│   │                                                                      │  │
│   │   • incident_type + confidence                                       │  │
│   │   • threat_level + score (0-100)                                     │  │
│   │   • timeline entries with ML confidence                              │  │
│   │   • MITRE techniques with evidence                                   │  │
│   │   • IoCs with context                                                │  │
│   │   • key_findings (rule-based)                                        │  │
│   │   • recommended_actions (rule-based)                                 │  │
│   └─────────────────────────────────┬───────────────────────────────────┘  │
│                                     │                                       │
│                    ┌────────────────┴────────────────┐                     │
│                    ▼                                 ▼                     │
│   ┌─────────────────────────┐       ┌─────────────────────────┐           │
│   │     JSON API Response   │       │   REPORT GENERATOR      │           │
│   │     (No LLM)            │       │   (LLM for prose only)  │           │
│   │                         │       │                         │           │
│   │  /ml/investigate        │       │  • Executive summary    │           │
│   │  /ml/classify           │       │  • Narrative text       │           │
│   │  /ml/mitre-map          │       │  • Detailed remediation │           │
│   │  /ml/extract-iocs       │       │                         │           │
│   └─────────────────────────┘       └─────────────────────────┘           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Компоненты

### 1. CyberMLEngine (`app/ml/cyber_ml_engine.py`)

Основной движок анализа. **НЕ использует LLM**.

#### Event Classifier
- **Метод:** `classify_event(event)`
- **Модель:** Gradient Boosting / Random Forest
- **Features:** 16 признаков (event_id, process, cmdline, etc.)
- **Output:** label (malicious/benign), confidence, explanation

```python
from app.ml.cyber_ml_engine import get_ml_engine

engine = get_ml_engine()
result = engine.classify_event({
    "event_id": 4688,
    "process_name": "mimikatz.exe",
    "command_line": "mimikatz.exe sekurlsa::logonpasswords"
})
# result.label = "malicious"
# result.confidence = 0.95
```

#### Incident Type Classifier
- **Метод:** `classify_incident_type(events, techniques)`
- **Подход:** ML + Rule-based scoring
- **Types:** ransomware, credential_theft, lateral_movement, etc.

#### MITRE ATT&CK Mapper
- **Метод:** `map_to_mitre(event)`
- **Подход:** Pattern matching (regex)
- **База:** 30+ техник с паттернами

```python
techniques = engine.map_to_mitre({
    "command_line": "vssadmin delete shadows /all"
})
# [MITRETechnique(id="T1490", name="Inhibit System Recovery", ...)]
```

#### IoC Extractor
- **Метод:** `extract_iocs(event)`
- **Подход:** Regex patterns
- **Types:** IP, domain, hash, URL, email, file_path, registry

#### Timeline Builder
- **Метод:** `build_timeline(events)`
- **Output:** Sorted list with ML classifications

#### Threat Scorer
- **Метод:** `calculate_threat_score(timeline, techniques)`
- **Algorithm:** Weighted scoring (0-100)
- **Factors:** critical events, MITRE techniques, IoCs

### 2. MLInvestigator (`app/ml/investigator.py`)

Главный интерфейс для расследований.

```python
from app.ml.investigator import MLInvestigator

investigator = MLInvestigator(use_llm_for_reports=False)

# Полное расследование (ML only)
result = investigator.investigate("INC-001", events)

# Получить отчёт (опционально с LLM)
report = investigator.get_report("INC-001", use_llm=False)  # Template
report = investigator.get_report("INC-001", use_llm=True)   # LLM prose
```

### 3. ReportGenerator (`app/ml/report_generator.py`)

Генерация отчётов. **LLM используется ТОЛЬКО здесь** (и опционально).

- **Template mode:** Всё из шаблонов, без LLM
- **LLM mode:** Executive summary и remediation через Groq

## API Endpoints

### ML Investigation (без LLM)

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/ml/investigate` | POST | Полное расследование (ML) |
| `/ml/investigate/{id}/report` | GET | Получить отчёт |
| `/ml/classify` | POST | Классификация события |
| `/ml/mitre-map` | POST | Маппинг на MITRE |
| `/ml/extract-iocs` | POST | Извлечение IoC |
| `/ml/investigations` | GET | Список расследований |
| `/ml/engine-info` | GET | Информация о ML движке |
| `/ml/investigate/example` | POST | Пример ransomware |

### Примеры запросов

**Классификация события:**
```bash
curl -X POST http://localhost:9000/ml/classify \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "event_id": 4688,
      "process_name": "powershell.exe",
      "command_line": "powershell -enc SGVsbG8="
    }
  }'
```

**Полное расследование:**
```bash
curl -X POST http://localhost:9000/ml/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-001",
    "events": [...]
  }'
```

**Отчёт с LLM:**
```bash
curl "http://localhost:9000/ml/investigate/INC-001/report?use_llm=true"
```

## Модели ML

### Текущие модели

| Файл | Алгоритм | Назначение |
|------|----------|------------|
| `gradient_boosting_model.pkl` | GradientBoosting | Event classification |
| `random_forest_model.pkl` | RandomForest | Event classification (backup) |

### Features (16 признаков)

```python
[
    "event_id",              # Windows Event ID
    "is_high_risk_event",    # Event ID in high-risk list
    "channel_hash",          # Log channel encoded
    "is_suspicious_process", # Process in LOLBin list
    "cmdline_length",        # Command line length
    "suspicious_keyword_count",  # Malicious keywords
    "has_base64_encoding",   # Base64 detected
    "has_download_command",  # Download activity
    "has_hidden_window",     # Hidden execution
    "parent_is_suspicious",  # Suspicious parent
    "logon_type",            # Logon type value
    "is_network_or_rdp_logon",   # Network/RDP logon
    "is_system_user",        # SYSTEM account
    "is_admin_user",         # Admin account
    "destination_port",      # Network port
    "is_c2_port",            # Known C2 port
]
```

### Обучение модели

```python
# См. ml_training_real_data.ipynb
from sklearn.ensemble import GradientBoostingClassifier

model = GradientBoostingClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    min_samples_split=5
)
model.fit(X_train, y_train)
```

## MITRE ATT&CK Patterns

30+ техник с паттернами:

```python
MITRE_PATTERNS = {
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "credential_access",
        "patterns": ["mimikatz", "sekurlsa", "lsass", "procdump.*lsass"],
        "processes": ["mimikatz.exe", "procdump.exe"],
        "event_ids": [10, 4688],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "patterns": ["vssadmin.*delete.*shadows", "bcdedit.*recoveryenabled.*no"],
        "file_extensions": [".encrypted", ".locked"],
        "event_ids": [4688],
    },
    # ... и другие
}
```

## Threat Scoring Algorithm

```
Score (0-100) =
    + min(malicious_events * 5, 30)      # Max 30 points
    + min(critical_events * 10, 25)      # Max 25 points
    + min(unique_techniques * 4, 20)     # Max 20 points
    + high_impact_techniques * 5         # T1486, T1490, T1003.001, T1041
    + min(ioc_count * 2, 10)             # Max 10 points

Threat Level:
    >= 80: CRITICAL
    >= 60: HIGH
    >= 40: MEDIUM
    >= 20: LOW
    < 20:  INFORMATIONAL
```

## Сравнение режимов

| Аспект | ML Only | ML + LLM |
|--------|---------|----------|
| Скорость | ~100ms | ~5-30s |
| Стоимость | $0 | API costs |
| Offline | Да | Нет |
| Отчёт | Шаблоны | Prose |
| Детализация | Структурированная | Human-readable |

## Использование без LLM

```python
from app.ml.investigator import MLInvestigator

# Создаём без LLM
investigator = MLInvestigator(use_llm_for_reports=False)

# Расследование
result = investigator.investigate("INC-001", events)

# Отчёт без LLM
report = investigator.get_report("INC-001", use_llm=False)
```

## CLI Demo

```bash
python -m app.ml.investigator
```

Output:
```
======================================================================
ML-First Cyber Incident Investigator Demo
======================================================================

[1/3] Investigating incident (ML only)...

[2/3] Investigation Results:
  Incident Type: ransomware
  Threat Level: high
  Threat Score: 75/100
  MITRE Techniques: 4
  IoCs Found: 3
  Timeline Events: 6

[3/3] Key Findings:
  - Incident classified as RANSOMWARE
  - 3 critical severity events detected
  - Primary attack techniques: T1486, T1490, T1059.001
```

## Расширение

### Добавление новой MITRE техники

```python
# В cyber_ml_engine.py
MITRE_PATTERNS["T1XXX"] = {
    "name": "Technique Name",
    "tactic": "tactic_name",
    "patterns": ["regex1", "regex2"],
    "processes": ["process.exe"],
    "event_ids": [4688],
}
```

### Добавление нового типа инцидента

```python
INCIDENT_TYPE_PATTERNS[IncidentType.NEW_TYPE] = {
    "techniques": ["T1XXX", "T1YYY"],
    "patterns": ["pattern1", "pattern2"],
    "weight": 1.2,
}
```

### Переобучение модели

```python
# См. ml_training_real_data.ipynb
# 1. Загрузить новые данные
# 2. Извлечь features
# 3. Обучить модель
# 4. Сохранить в models/
```
