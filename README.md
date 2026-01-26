# Cyber Incident Investigation Agent

**Автономный ИИ-агент для полного расследования кибер-инцидентов**

---

## Что это?

Специализированный AI-агент, который проводит **комплексное расследование кибер-инцидентов** от начала до конца.

### Возможности:

- Timeline Reconstruction - Восстановление timeline атаки
- IoC Extraction - Извлечение индикаторов компрометации
- TTP Analysis - Определение тактик по MITRE ATT&CK
- Root Cause Analysis - Анализ первопричин
- Impact Assessment - Оценка ущерба
- Forensic Analysis - Криминалистический анализ
- Investigation Report - Детальный отчет о расследовании

---

## Быстрый старт

### 1. Установка

```bash
pip install groq python-dotenv
```

### 2. Настройка

Создайте `.env`:

```env
LLM_API_KEY=your-groq-api-key
LLM_ANALYZER_MODEL=llama-3.3-70b-versatile
```

Получите ключ: https://console.groq.com

### 3. Запуск

**Вариант А: Standalone**

```python
import asyncio
from cyber_incident_investigator import CyberIncidentInvestigator

async def main():
    investigator = CyberIncidentInvestigator()

    events = [
        {
            "timestamp": "2024-01-15T08:37:00Z",
            "hostname": "srv-01",
            "process_name": "mimikatz.exe",
            "event_type": "process_creation"
        }
        # ... другие события
    ]

    incident_id = await investigator.start_investigation("INC-001", events)
    report = investigator.get_investigation_report(incident_id)
    print(report)

asyncio.run(main())
```

**Вариант Б: FastAPI**

```bash
# Запустить API
python app/main.py

# Запустить пример расследования
curl -X POST http://localhost:9000/investigation/example

# Swagger UI
http://localhost:9000/docs
```

---

## API Endpoints

| Endpoint | Описание |
|----------|----------|
| `POST /investigation/start` | Начать расследование |
| `GET /investigation/{id}/report` | Получить отчет |
| `POST /investigation/example` | Пример ransomware |
| `GET /investigation/status` | Статус агента |

### Пример запроса:

```bash
curl -X POST http://localhost:9000/investigation/start \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-2024-001",
    "events": [
      {
        "timestamp": "2024-01-15T08:37:00Z",
        "hostname": "srv-01",
        "event_type": "process_creation",
        "process_name": "mimikatz.exe"
      }
    ]
  }'
```

---

## Процесс расследования

Агент проводит расследование в 8 этапов:

1. **Classification** - Определяет тип инцидента (ransomware, malware, APT, etc.)
2. **Timeline** - Строит хронологию атаки
3. **IoC Extraction** - Извлекает все индикаторы (IP, хеши, домены)
4. **TTP Analysis** - Определяет тактики MITRE ATT&CK
5. **Root Cause** - Находит первопричину и точку входа
6. **Impact** - Оценивает ущерб
7. **Response Plan** - Генерирует план сдерживания и устранения
8. **Report** - Создает детальный отчет

---

## Пример отчета

```
================================================================================
CYBER INCIDENT INVESTIGATION REPORT
================================================================================

Incident ID: INC-2024-001
Title: Ransomware Attack via Phishing Email
Type: RANSOMWARE

================================================================================
EXECUTIVE SUMMARY
================================================================================

Ransomware attack detected affecting 2 systems. Attack originated from phishing
email with malicious attachment. 500GB encrypted. Containment completed.

================================================================================
ATTACK TIMELINE
================================================================================

[1] 08:30 | WS-USER01 | User login (phishing victim)
[2] 08:37 | WS-USER01 | Malicious executable launched
[3] 08:38 | WS-USER01 | C2 communication to 185.220.101.45
[4] 08:40 | WS-USER01 | Shadow copies deleted
[5] 08:42 | WS-USER01 | File encryption started

================================================================================
IoCs
================================================================================

IP: 185.220.101.45 (C2 server)
HASH: 5d41402abc4b2a76b9719d911017c592
FILE: invoice_2024.exe
DOMAIN: malicious-c2.com

================================================================================
MITRE ATT&CK
================================================================================

Tactics: initial_access, execution, defense_evasion, impact
Techniques:
  - T1566.001: Spearphishing Attachment
  - T1490: Inhibit System Recovery
  - T1486: Data Encrypted for Impact

================================================================================
REMEDIATION
================================================================================

1. Isolate affected systems
2. Block C2 IP at firewall
3. Restore from backup
4. Reset passwords
5. Deploy email sandboxing

...
```

---

## Поддерживаемые типы инцидентов

- Malware
- Ransomware
- Data Breach
- Lateral Movement
- Credential Theft
- Insider Threat
- APT (Advanced Persistent Threat)
- DDoS
- Phishing

---

## Интеграция

### С коллекторами событий:

```python
# При обнаружении инцидента
import httpx

async def auto_investigate(events):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:9000/investigation/start",
            json={"incident_id": "AUTO-001", "events": events},
            timeout=300.0
        )
        return response.json()
```

---

## Документация

Полное руководство: **[INVESTIGATION_GUIDE.md](INVESTIGATION_GUIDE.md)**

API документация: http://localhost:9000/docs

---

## Структура проекта

```
.
├── cyber_incident_investigator.py   # Основной агент
├── app/
│   ├── main.py                      # FastAPI сервер
│   ├── routers/
│   │   └── investigation.py         # API endpoints
│   └── services/
│       └── investigation_service.py # Интеграция
├── INVESTIGATION_GUIDE.md           # Полное руководство
└── README.md                        # Этот файл
```

---

## Требования

- Python 3.8+
- groq
- python-dotenv
- FastAPI (для API)
- uvicorn (для API)

---

## Лицензия

MIT License

---

**Готово к расследованию кибер-инцидентов!**

Для начала:
```bash
python app/main.py
# Откройте http://localhost:9000/docs
# Нажмите POST /investigation/example
```
