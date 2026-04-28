# IR-Agent

![CI](https://github.com/qbert2004/Ir_agent/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-144%20passing-brightgreen)
![ROC-AUC](https://img.shields.io/badge/ROC--AUC-0.9899-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Автономная AI-платформа для реагирования на киберинциденты**

IR-Agent — это production-ready FastAPI сервис, который:
1. Принимает сырые события безопасности (Windows Events, Sysmon, AD, Linux, Kaspersky, Firewall)
2. Группирует их в **инциденты** по хосту и временному окну
3. Запускает **Enterprise ML-классификатор** (HistGradientBoosting, 90 признаков, ROC-AUC 0.99)
4. Отправляет **ReAct LLM агента** расследовать целый инцидент, а не отдельные события
5. Возвращает вердикт с тактиками MITRE ATT&CK, IoC, таймлайном атаки и рекомендациями

---

## Архитектура системы

```
Источники событий
  Windows Security  Sysmon  Active Directory  Linux auditd  Kaspersky  Firewall
        │                │                │             │          │          │
        └────────────────┴────────────────┴─────────────┴──────────┴──────────┘
                                          │
                                   EventProcessor
                                          │
                          ┌───────────────┴────────────────┐
                          │                                │
                 Enterprise ML                     IncidentManager
              (HistGBM, 90 features)              (корреляция по хосту,
               ROC-AUC = 0.9899                    30-мин. окно)
                          │                                │
                    score 0.0–1.0                    Incident объект
                          │                         (timeline, IoC, MITRE)
                          └───────────────┬────────────────┘
                                          │
                                  ThreatAssessmentEngine
                                (4 сигнала × веса + 7 правил)
                                          │
                                    CyberAgent (LLM)
                               ReAct loop, до 8 шагов, 11 инструментов
                                          │
                                     Verdict + Report
                              (MALICIOUS / SUSPICIOUS / FALSE_POSITIVE)
```

---

## Как это работает — шаг за шагом

### 1. Приём события

```
POST /ingest/telemetry  ← raw endpoint / SIEM-лог
```

`EventProcessor` нормализует событие через один из 7 нормализаторов (Windows Security, Sysmon, Active Directory, Linux auditd, Linux auth, Kaspersky, Firewall) в единую схему **UNIFIED\_SCHEMA** (40 полей).

### 2. ML-классификация

`MLAttackDetector` (HistGradientBoostingClassifier, 90 признаков) оценивает событие от 0.0 до 1.0:

| Диапазон | Путь |
|---|---|
| < 0.50 | Отброшено как benign |
| 0.50 – 0.80 | **Deep path** → CyberAgent |
| > 0.80 | **Fast path** → сохранить немедленно, расследование в фоне |

### 3. Корреляция в инциденты

`IncidentManager.correlate_event()` объединяет события **одного хоста** в пределах **30 минут** в один `Incident`. Агент видит сразу всю цепочку атаки, а не изолированные события.

```python
id1 = manager.correlate_event(event_powershell, 0.9, "ML malicious")
id2 = manager.correlate_event(event_mimikatz,   0.85, "ML malicious")
assert id1 == id2  # тот же инцидент
```

### 4. Rule-based расследование инцидента

До вызова LLM `IncidentManager.investigate()` выполняет:

1. **Timeline builder** — хронологическая сортировка + `AttackPhase` для каждого события (Initial Access / Execution / Credential Access / Lateral Movement / ...)
2. **IoC extractor** — RegEx по всем текстовым полям: IP, домены, хэши, URL, пути файлов, ключи реестра; фильтрация приватных IP; дедупликация
3. **MITRE ATT&CK mapper** — сопоставление с 40+ техниками по имени процесса и командной строке (T1059.001, T1003.001, T1053.005, ...)
4. **Severity scoring** — взвешенная сумма: количество событий + разнообразие фаз + критические фазы + плотность MITRE + IoC + средний ML confidence + флаг multi-host
5. **Root cause analysis** — начальный вектор из первой записи таймлайна (brute force, RDP, PowerShell, фишинг, ...)
6. **Impact assessment** — конкретные риски (кража учётных данных, persistence, активный C2, ...)
7. **Recommendations** — упорядоченный план реагирования

### 5. AI-агент (LLM)

`CyberAgent` (ReAct loop, до 8 шагов) получает богатый **промпт уровня инцидента**:

```
INCIDENT IR-20260427-A1B2C3 on WS-VICTIM01

TIMELINE (2 events):
  2026-04-27T10:00:00Z  [Execution] PowerShell execution (encoded command)
    MITRE: T1059.001, T1027
  2026-04-27T10:01:00Z  [Credential Access] mimikatz.exe
    MITRE: T1003.001

IoCs (2): [PROCESS] mimikatz.exe  |  [IP] 185.220.101.5

PRELIMINARY CLASSIFICATION: Credential access / dumping attempt

INVESTIGATION TASK: review timeline → lookup IoCs → map MITRE → assess chain
Conclude: Verdict: MALICIOUS / SUSPICIOUS / FALSE_POSITIVE
```

**11 инструментов агента:**

| Инструмент | Назначение |
|---|---|
| `get_incident` | Полный инцидент: таймлайн, IoC, MITRE, выводы, рекомендации |
| `get_incident_events` | Сырые события с фильтром по фазе и лимитом |
| `knowledge_search` | Векторный поиск по базе знаний (FAISS) |
| `search_logs` | Запрос исторических событий по хосту / времени |
| `classify_event` | ML-классификация raw event dict |
| `analyze_event` | Глубокий LLM-анализ одного события |
| `mitre_lookup` | Поиск техники MITRE по ID или ключевому слову |
| `lookup_ioc` | Проверка IP / домена / хэша в VirusTotal + AbuseIPDB |
| `query_siem` | SIEM-запрос истории событий |
| `investigate` | Rule-based расследование инцидента |
| `ml_classify` | Прямой ML-скоринг текста события |

### 6. Fusion: ThreatAssessmentEngine

```
ML score    × 0.35
IoC score   × 0.30
MITRE score × 0.20
Agent score × 0.15
─────────────────
Final score  0–100  →  INFO / LOW / MEDIUM / HIGH / CRITICAL
```

Семь правил могут переопределить взвешенный результат:

| Правило | Триггер | Эффект |
|---|---|---|
| R1 | ≥2 IoC-провайдера подтвердили malicious | Принудительно score ≥ 85 (CRITICAL) |
| R2 | «lsass»/«credential dump» в причине ML | Принудительно score ≥ 80 |
| R3 | MITRE: lateral_movement + credential_access | Принудительно score ≥ 65 (HIGH) |
| R4 | MITRE: impact тактика | Принудительно score ≥ 65 |
| R5 | Все 3+ источника голосуют malicious | +10% бонус |
| R6 | Agent FALSE_POSITIVE + ML < 0.6 | Ограничить score ≤ 25 (LOW) |
| R7 | IoC чисто + Agent FP + ML неопределён | Ограничить score ≤ 40 |

---

## Enterprise ML модель

### Обучающие данные

Модель обучена на **286 352 реальных событиях** из трёх источников:

| Источник | Событий | Описание |
|---|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | 107 000 | Реальные атаки в лаб. среде: mimikatz, PsExec, DCSync, WMI, PSRemoting, Rubeus |
| [Splunk attack_data](https://github.com/splunk/attack_data) | 42 524 | Windows Event XML: T1003, T1059, T1136, T1547 |
| Синтетические + проектные данные | 136 828 | 7 источников × 500 синтетических + 132k из train_events.json |

**Покрытие MITRE ATT&CK:**
T1021 (25k) · T1003.002 (19k) · T1003.003 (17k) · T1136.001 (12k) · T1003.006 (8k) · T1047 (6k) · T1003.001 (6k) · T1021.002 (4k) · T1558.003 (1k) · T1053.005 (1k)

### Алгоритм и результаты

```
Алгоритм:  HistGradientBoostingClassifier + Platt scaling (CalibratedClassifierCV, cv=3)
Деревьев:  300 (early stopping)
Признаков: 90 (процессы, сеть, аутентификация, Kaspersky, Linux, временные)
Разбивка:  75% train / 25% validation (stratified)
```

| Метрика | Значение |
|---|---|
| ROC-AUC | **0.9899** |
| Accuracy | 96.04% |
| F1-Score | 0.9750 |
| FPR (ложные тревоги) | 10.07% |
| FNR (пропущенные атаки) | 2.34% |
| Threshold (Youden-J) | 0.8102 |

**Топ-15 признаков** (permutation importance):

| # | Признак | Важность |
|---|---|---|
| 1 | `auth_empty_user` | 0.0945 |
| 2 | `proc_signed` | 0.0807 |
| 3 | `proc_system_path` | 0.0791 |
| 4 | `proc_has_hash` | 0.0650 |
| 5 | `etype_registry` | 0.0533 |
| 6 | `etype_process_create` | 0.0368 |
| 7 | `sev_high_or_critical` | 0.0242 |
| 8 | `sev_medium` | 0.0221 |
| 9 | `auth_admin_user` | 0.0104 |
| 10 | `src_windows_security` | 0.0048 |

### Переобучение модели

```bash
# 1. Скачать реальные датасеты (OTRF + Splunk, кэшируется в datasets/)
python scripts/download_real_datasets.py

# 2. Сгенерировать синтетические данные
python scripts/generate_enterprise_data.py

# 3. Обучить модель
python scripts/retrain_enterprise.py
```

Подробнее: [TRAINING_PLAYBOOK.md](TRAINING_PLAYBOOK.md)

---

## Быстрый старт

### Требования

- Python 3.11+ (протестировано на 3.13)
- API-ключ провайдера LLM (Google AI / Groq / OpenAI / Ollama)
- Docker + Docker Compose (опционально)

### 1. Клонирование и установка

```bash
git clone https://github.com/qbert2004/Ir_agent
cd Ir_agent
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Настройка окружения

```bash
cp .env.example .env
# Отредактировать .env
```

Минимальная конфигурация (один из провайдеров):

```env
# Google AI (рекомендуется)
GOOGLE_API_KEY=AIzaSy...
GOOGLE_AI_MODEL=models/gemma-4-31b-it

# Groq (альтернатива)
LLM_API_KEY=gsk_...

# Режим окружения
ENVIRONMENT=development    # отключает auth, включает /docs
```

### 3. Миграции БД

```bash
alembic upgrade head
```

### 4. Запуск

```bash
python app/main.py
# или
uvicorn app.main:app --host 0.0.0.0 --port 9000 --reload
```

| URL | Назначение |
|---|---|
| http://localhost:9000/docs | Swagger UI |
| http://localhost:9000/dashboard | Web-дашборд |
| http://localhost:9000/health | Health check |

### 5. Docker

```bash
docker-compose up -d
docker-compose logs -f ir-agent
```

---

## Проверка pipeline

### Отправка двух связанных событий (один хост, одна атака)

```bash
# Событие 1: PowerShell с зашифрованной командой
curl -X POST http://localhost:9000/ingest/telemetry \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-04-27T10:00:00Z",
    "event_id": 4688,
    "hostname": "WS-VICTIM01",
    "process_name": "powershell.exe",
    "command_line": "powershell -enc aQBuAHYAbwBrAGUALQBleHByZXNzaW9u",
    "user": "john.doe"
  }'

# Событие 2: Mimikatz (тот же хост, +1 мин)
curl -X POST http://localhost:9000/ingest/telemetry \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-04-27T10:01:00Z",
    "event_id": 4688,
    "hostname": "WS-VICTIM01",
    "process_name": "mimikatz.exe",
    "command_line": "sekurlsa::logonpasswords",
    "user": "john.doe"
  }'
```

### Просмотр инцидентов

```bash
curl http://localhost:9000/ingest/incidents
```

### Отчёт по инциденту

```bash
curl http://localhost:9000/ingest/incidents/IR-20260427-XXXXXX/report
```

```
======================================================================
INCIDENT INVESTIGATION REPORT
======================================================================
Incident ID:     IR-20260427-XXXXXX
Host:            WS-VICTIM01
Severity:        MEDIUM
Classification:  Credential access / dumping attempt

ATTACK TIMELINE
  10:00Z  [Execution]         PowerShell encoded command  T1059.001, T1027
  10:01Z  [Credential Access] mimikatz.exe                T1003.001

INDICATORS OF COMPROMISE
  [PROCESS]  mimikatz.exe

ROOT CAUSE: PowerShell-based delivery, credential harvesting.

RECOMMENDED RESPONSE
  1. Isolate host from network
  2. Reset credentials for john.doe
  3. Preserve forensic evidence
```

### Запуск AI-агента

```bash
curl -X POST http://localhost:9000/ingest/incidents/IR-20260427-XXXXXX/investigate
```

```json
{
  "status": "success",
  "agent_verdict": "MALICIOUS",
  "agent_confidence": 0.95,
  "summary": "Confirmed attack chain: encoded PowerShell delivery + mimikatz credential dumping.",
  "tools_used": ["get_incident", "get_incident_events", "lookup_ioc", "mitre_lookup"],
  "steps": 4
}
```

---

## API Reference

### Инциденты

| Метод | Endpoint | Описание |
|---|---|---|
| `POST` | `/ingest/telemetry` | Приём сырого события |
| `POST` | `/ingest/event` | Приём структурированного события |
| `GET` | `/ingest/incidents` | Список всех инцидентов со статистикой |
| `GET` | `/ingest/incidents/{id}` | Полный инцидент (таймлайн, IoC, MITRE, выводы) |
| `GET` | `/ingest/incidents/{id}/report` | Текстовый отчёт |
| `POST` | `/ingest/incidents/{id}/investigate` | Запуск AI-агента |

### ML / Агент

| Метод | Endpoint | Описание |
|---|---|---|
| `POST` | `/ml/classify` | ML-классификация события |
| `GET` | `/ml/status` | Статус модели и метрики |
| `GET` | `/ml/mitre-map` | MITRE ATT&CK → EventID маппинг |
| `POST` | `/agent/query` | Запрос к AI-агенту |
| `POST` | `/agent/query/stream` | Стриминг ответа агента |
| `GET` | `/health` | Статус сервиса |
| `GET` | `/metrics` | Prometheus-метрики |

---

## CLI и TUI

### CLI

```bash
python cli.py status                              # Здоровье сервера
python cli.py query "What is T1003?"             # Запрос к агенту
python cli.py query "Analyze mimikatz" --stream  # Стриминг
python cli.py tools                               # 11 инструментов агента
python cli.py metrics                             # ML + агент + инциденты
python cli.py ioc 185.220.101.45                 # IoC lookup
python cli.py mitre T1003.001                    # MITRE lookup
python cli.py assess --ml 0.87 --ioc 0.9        # Threat Assessment
python cli.py shell                               # Интерактивный REPL
```

### TUI (Terminal UI)

```bash
python tui.py
```

8 вкладок (переключение клавишами **1–8**):

| Клавиша | Вкладка | Содержимое |
|---|---|---|
| 1 | **Status** | Health, uptime, окружение |
| 2 | **Query** | Запросы к AI-агенту |
| 3 | **Tools** | 11 зарегистрированных инструментов |
| 4 | **Metrics** | ML/агент/инциденты, фоновые расследования |
| 5 | **IoC** | VirusTotal + AbuseIPDB lookup |
| 6 | **MITRE** | Поиск техник |
| 7 | **Incidents** | Список инцидентов + запуск AI |
| 8 | **Assess** | Ручной ThreatAssessment |

---

## Тестирование

```bash
pip install -r requirements-dev.txt

# Все 144 теста
pytest tests/ -v

# Один модуль
pytest tests/test_incident_investigation.py -v
pytest tests/test_comprehensive.py -v

# С покрытием
pytest tests/ --cov=app --cov-report=html
```

**144 теста** в 10 модулях:

| Модуль | Тестов | Покрывает |
|---|---|---|
| `test_comprehensive.py` | 37 | ThreatAssessmentEngine, IoC extraction, root cause, impact, recommendations |
| `test_agent_fixes.py` | 31 | LRU cache, timeouts, confidence, thread safety, prompt injection |
| `test_incident_investigation.py` | 16 | Incident correlation, GetIncidentTool, API endpoints |
| `test_event_processor.py` | 9 | ML pipeline, enrichment, metrics |
| `test_middleware.py` | 7 | Auth, rate limiting, request ID |
| `test_config.py` | 7 | Settings validation, провайдеры |
| `test_api_ml.py` | 6 | ML API contract |
| `test_ml_detector.py` | 6 | Classifier, heuristics, features |
| `test_api_ingest.py` | 5 | Ingest endpoint |
| `test_health.py` | 4 | Health/readiness probes |

---

## Структура проекта

```
Ir_agent/
├── app/
│   ├── main.py                        # FastAPI app, startup, DB init
│   ├── core/
│   │   └── config.py                  # Settings (Pydantic, .env)
│   ├── routers/
│   │   ├── ingest.py                  # /ingest/* + incident endpoints
│   │   ├── agent.py                   # /agent/query, /agent/query/stream
│   │   ├── ml.py                      # /ml/classify, /ml/status
│   │   └── assessment.py              # /assessment/analyze
│   ├── agent/
│   │   ├── core/agent.py              # CyberAgent — ReAct loop
│   │   └── tools/                     # 11 инструментов агента
│   │       ├── get_incident.py
│   │       ├── get_incident_events.py
│   │       ├── lookup_ioc.py
│   │       ├── mitre_lookup.py
│   │       └── ...
│   ├── services/
│   │   ├── event_processor.py         # ML pipeline + incident correlation
│   │   ├── incident_manager.py        # Correlation, timeline, IoC, MITRE
│   │   ├── agent_service.py           # Agent singleton, 11 tools
│   │   └── llm_client.py              # Google AI / Groq / OpenAI / Ollama
│   ├── assessment/
│   │   └── threat_assessment.py       # 4-сигнальный fusion, 7 правил
│   ├── ml/
│   │   └── detector.py                # MLAttackDetector (90 признаков)
│   └── db/
│       ├── models.py                  # ORM: SecurityEvent, Incident, IoC
│       ├── event_store.py             # Async CRUD
│       └── database.py                # SQLAlchemy async engine
├── models/
│   └── gradient_boosting_enterprise.pkl  # Enterprise ML (HistGBM, 90 feat.)
├── datasets/                          # Датасеты для обучения
│   ├── *_events.json                  # Синтетические (7 источников × 500)
│   └── real_benign_sysmon.json        # 80k реальных benign событий
├── scripts/
│   ├── retrain_enterprise.py          # Основной скрипт обучения
│   ├── download_real_datasets.py      # Скачать OTRF + Splunk датасеты
│   └── generate_enterprise_data.py    # Генерация синтетических данных
├── tests/                             # 144 теста
├── alembic/                           # Миграции БД
├── tui.py                             # Textual full-screen TUI
├── cli.py                             # CLI интерфейс
├── Dockerfile
├── docker-compose.yml
├── TRAINING_PLAYBOOK.md               # Руководство по обучению модели
└── requirements.txt
```

---

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `GOOGLE_API_KEY` | — | Google AI API ключ |
| `GOOGLE_AI_MODEL` | `models/gemma-4-31b-it` | Google AI модель |
| `LLM_API_KEY` | — | Groq API ключ (альтернатива) |
| `OPENAI_API_KEY` | — | OpenAI API ключ (альтернатива) |
| `OLLAMA_BASE_URL` | — | URL локального Ollama (альтернатива) |
| `LLM_PROVIDER` | `google` | Приоритетный провайдер |
| `MY_API_TOKEN` | — | Bearer token (в production обязателен) |
| `ENVIRONMENT` | `production` | `development` = без auth + /docs |
| `DATABASE_URL` | `sqlite+aiosqlite:///./ir_agent.db` | Строка подключения к БД |
| `VIRUSTOTAL_API_KEY` | — | IoC lookups (VirusTotal) |
| `ABUSEIPDB_API_KEY` | — | IP reputation lookups |
| `BETTER_STACK_SOURCE_TOKEN` | — | Лог-шиппинг |
| `AI_SUSPICIOUS_THRESHOLD` | `60` | Порог угрозы ML (0–100) |
| `API_PORT` | `9000` | HTTP порт |
| `CORS_ORIGINS` | `*` | Разрешённые CORS origins |
| `RATE_LIMIT_PER_MINUTE` | `60` | Rate limit (запросов/мин) |

Полный список: [`.env.example`](.env.example)

---

## Документация

| Документ | Описание |
|---|---|
| [TRAINING_PLAYBOOK.md](TRAINING_PLAYBOOK.md) | Pipeline обучения ML: архитектура, 90 признаков, датасеты, команды |
| [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md) | Детали ML-модели, MITRE-маппинг |
| [INVESTIGATION_GUIDE.md](INVESTIGATION_GUIDE.md) | Рабочие процессы расследования |
| [DIPLOMA_DOCUMENTATION.md](DIPLOMA_DOCUMENTATION.md) | Полная документация для дипломной защиты (RU) |
| [docs/api.md](docs/api.md) | Полный API Reference |
| [docs/architecture.md](docs/architecture.md) | Архитектурные решения |
| [CHANGELOG.md](CHANGELOG.md) | История версий |

---

## License

MIT License
