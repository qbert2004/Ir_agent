# Cyber Incident Investigation Agent - Руководство

**Специализированный ИИ-агент для расследования кибер-инцидентов**

---

## Что это такое?

**Cyber Incident Investigation Agent** - это автономный ИИ-агент, который проводит полное расследование кибер-инцидентов от начала до конца.

### Возможности агента:

✅ **Timeline Reconstruction** - Восстановление хронологии атаки
✅ **IoC Extraction** - Извлечение всех индикаторов компрометации
✅ **TTP Analysis** - Определение тактик и техник (MITRE ATT&CK)
✅ **Root Cause Analysis** - Анализ первопричин инцидента
✅ **Impact Assessment** - Оценка масштаба ущерба
✅ **Forensic Analysis** - Криминалистический анализ
✅ **Investigation Report** - Генерация детального отчета

---

## Установка

### 1. Установите зависимости

```bash
pip install groq python-dotenv
```

### 2. Настройте .env файл

```env
LLM_API_KEY=your-groq-api-key-here
LLM_ANALYZER_MODEL=llama-3.3-70b-versatile
```

Получите API ключ: https://console.groq.com

---

## Использование

### Standalone (Python)

```python
import asyncio
from cyber_incident_investigator import CyberIncidentInvestigator

async def investigate():
    # Создаем агента
    investigator = CyberIncidentInvestigator()

    # События инцидента
    events = [
        {
            "timestamp": "2024-01-15T08:37:00Z",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
            "user": "admin"
        },
        {
            "timestamp": "2024-01-15T08:40:00Z",
            "hostname": "WS-USER01",
            "event_type": "network",
            "destination_ip": "185.220.101.45",
            "description": "C2 communication"
        }
        # ... другие события
    ]

    # Запускаем расследование
    incident_id = await investigator.start_investigation("INC-2024-001", events)

    # Получаем отчет
    report = investigator.get_investigation_report(incident_id, format="text")
    print(report)

asyncio.run(investigate())
```

### Через FastAPI

```bash
# 1. Запустите API сервер
python app/main.py

# 2. Откройте Swagger UI
# http://localhost:9000/docs

# 3. Запустите пример
curl -X POST http://localhost:9000/investigation/example

# 4. Получите отчет
curl http://localhost:9000/investigation/{incident_id}/report
```

---

## API Endpoints

| Метод | Endpoint | Описание |
|-------|----------|----------|
| GET | `/investigation/status` | Статус агента |
| POST | `/investigation/start` | Начать расследование |
| GET | `/investigation/list` | Список расследований |
| GET | `/investigation/{id}/report` | Получить отчет |
| POST | `/investigation/example` | Запустить пример |

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
        "process_name": "mimikatz.exe",
        "user": "admin"
      }
    ]
  }'
```

### Пример ответа:

```json
{
  "status": "success",
  "incident_id": "INC-2024-001",
  "message": "Investigation completed successfully"
}
```

---

## Процесс расследования

Агент проводит расследование в 8 этапов:

### 1. **Initial Triage & Classification**
Определяет тип инцидента:
- Malware
- Ransomware
- Data Breach
- Lateral Movement
- Credential Theft
- Insider Threat
- APT
- DDoS
- Phishing

### 2. **Timeline Reconstruction**
Строит хронологический timeline атаки:
- Сортирует события по времени
- Определяет ключевые моменты
- Связывает события между собой
- Определяет MITRE ATT&CK техники

### 3. **IoC Extraction**
Извлекает индикаторы компрометации:
- IP адреса
- Домены
- Хеши файлов (MD5, SHA256)
- Пути к файлам
- Ключи реестра
- Имена процессов
- URL адреса
- Email адреса

### 4. **TTP Analysis (MITRE ATT&CK)**
Определяет тактики и техники атакующего:
- Tactics: initial_access, execution, persistence, etc.
- Techniques: с конкретными ID (T1059.001, T1003, etc.)
- Procedures: конкретные методы
- Attacker Profile: уровень sophistication

### 5. **Root Cause Analysis**
Определяет первопричину:
- Как произошел инцидент?
- Какая уязвимость была использована?
- Что пошло не так?
- Точка входа атакующего

### 6. **Impact Assessment**
Оценивает ущерб:
- Затронутые системы
- Украденные данные
- Бизнес-влияние
- Финансовые потери
- Репутационный ущерб

### 7. **Containment & Remediation**
Генерирует план реагирования:
- Немедленные действия по сдерживанию
- Шаги по устранению угрозы
- Рекомендации по восстановлению

### 8. **Executive Summary & Report**
Создает финальный отчет:
- Executive Summary для руководства
- Детальный технический анализ
- Lessons Learned
- Рекомендации

---

## Пример отчета

```
================================================================================
CYBER INCIDENT INVESTIGATION REPORT
================================================================================

Incident ID: INC-2024-001
Title: Ransomware Attack via Phishing Email
Type: RANSOMWARE
Investigation Date: 2024-01-15T10:00:00Z
Investigator: Cyber Incident Investigation AI Agent

================================================================================
EXECUTIVE SUMMARY
================================================================================

A ransomware attack was detected on January 15, 2024, affecting workstation
WS-USER01 and file server FILE-SRV01. The attack originated from a phishing
email containing a malicious attachment. The attacker successfully encrypted
files on both systems and demanded ransom. Total impact: 2 systems compromised,
approximately 500GB of data encrypted. Immediate containment actions were taken.

================================================================================
ATTACK TIMELINE
================================================================================

[1] 2024-01-15T08:30:00Z | WS-USER01
    Type: initial_access | Severity: HIGH
    User john.doe logged in via phishing-compromised account
    MITRE: T1078
    IoCs: john.doe@company.com

[2] 2024-01-15T08:37:00Z | WS-USER01
    Type: execution | Severity: CRITICAL
    Malicious executable invoice_2024.exe launched from email attachment
    MITRE: T1204.002
    IoCs: invoice_2024.exe, 5d41402abc4b2a76b9719d911017c592

[3] 2024-01-15T08:38:00Z | WS-USER01
    Type: command_and_control | Severity: HIGH
    Outbound C2 communication to 185.220.101.45:443
    MITRE: T1071.001
    IoCs: 185.220.101.45

[4] 2024-01-15T08:40:00Z | WS-USER01
    Type: defense_evasion | Severity: CRITICAL
    Shadow copies deletion via vssadmin
    MITRE: T1490
    IoCs: vssadmin delete shadows /all /quiet

[5] 2024-01-15T08:42:00Z | WS-USER01
    Type: impact | Severity: CRITICAL
    File encryption started
    MITRE: T1486
    IoCs: .encrypted extension

================================================================================
INDICATORS OF COMPROMISE (IOCs)
================================================================================

IP: 185.220.101.45
  Confidence: 95%
  Context: Command and Control server

HASH: 5d41402abc4b2a76b9719d911017c592
  Confidence: 90%
  Context: Ransomware executable MD5

FILE_PATH: C:\Users\john.doe\Desktop\invoice_2024.exe
  Confidence: 100%
  Context: Initial malware dropper

DOMAIN: malicious-c2.com
  Confidence: 85%
  Context: C2 domain

================================================================================
TTP ANALYSIS (MITRE ATT&CK)
================================================================================

Attacker Profile: Ransomware-as-a-Service operator
Sophistication Level: MEDIUM

Tactics: initial_access, execution, persistence, defense_evasion, impact

Techniques:
  - T1566.001: Spearphishing Attachment (confidence: 95%)
  - T1204.002: Malicious File Execution (confidence: 100%)
  - T1071.001: HTTPS C2 Communication (confidence: 90%)
  - T1490: Inhibit System Recovery (confidence: 100%)
  - T1486: Data Encrypted for Impact (confidence: 100%)

================================================================================
ROOT CAUSE ANALYSIS
================================================================================

Entry Point: Phishing email with malicious attachment opened by user john.doe

Root Cause: Insufficient email security controls and lack of user security
awareness training. The malicious attachment bypassed email filtering and the
user executed the file without verification.

================================================================================
IMPACT ASSESSMENT
================================================================================

Affected Systems: 2
  - WS-USER01
  - FILE-SRV01

Severity: CRITICAL

Business Impact: Operations disrupted for 2 business units. Approximately 500GB
of business-critical data encrypted including financial reports, customer
database, and project files. Estimated recovery time: 48-72 hours.

Data Exfiltrated: No evidence of data exfiltration detected

================================================================================
CONTAINMENT ACTIONS
================================================================================

1. Immediately isolate affected systems from network
2. Block C2 IP 185.220.101.45 at firewall level
3. Disable compromised user account john.doe
4. Quarantine malicious file invoice_2024.exe
5. Deploy EDR to all workstations for enhanced monitoring

================================================================================
REMEDIATION STEPS
================================================================================

1. Restore encrypted files from backup (verified clean)
2. Reimage affected workstations WS-USER01 and FILE-SRV01
3. Reset passwords for all users on affected systems
4. Apply latest security patches to all systems
5. Implement email attachment sandboxing
6. Deploy advanced email filtering solution
7. Conduct security awareness training for all staff
8. Review and update incident response procedures

================================================================================
LESSONS LEARNED
================================================================================

1. Implement advanced email security with attachment sandboxing
2. Deploy endpoint detection and response (EDR) solution
3. Conduct regular security awareness training for employees
4. Implement application whitelisting to prevent unauthorized executables
5. Ensure regular testing of backup and restore procedures

================================================================================
END OF REPORT
================================================================================
```

---

## Интеграция с вашими коллекторами

Добавьте в ваши коллекторы автоматический запуск расследования:

```python
import httpx

# При обнаружении инцидента
async def trigger_investigation(incident_events):
    """Запустить расследование при обнаружении инцидента"""

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:9000/investigation/start",
            json={
                "incident_id": f"AUTO-{datetime.utcnow().timestamp()}",
                "events": incident_events
            },
            timeout=300.0  # 5 минут на расследование
        )

        if response.status_code == 200:
            result = response.json()
            incident_id = result["incident_id"]

            # Получить отчет
            report_response = await client.get(
                f"http://localhost:9000/investigation/{incident_id}/report?format=json"
            )

            # Отправить отчет в Better Stack или SIEM
            await send_to_siem(report_response.json())
```

---

## Типы поддерживаемых инцидентов

Агент специализируется на расследовании:

1. **Malware** - Вредоносное ПО
2. **Ransomware** - Шифровальщики
3. **Data Breach** - Утечки данных
4. **Lateral Movement** - Перемещение по сети
5. **Credential Theft** - Кража учетных данных
6. **Insider Threat** - Внутренние угрозы
7. **APT** - Продвинутые угрозы
8. **DDoS** - DDoS атаки
9. **Phishing** - Фишинг

---

## Обнаруживаемые MITRE ATT&CK техники

Агент распознает техники из всех тактик:

- **Initial Access**: T1566, T1190, T1078
- **Execution**: T1059, T1053, T1204
- **Persistence**: T1547, T1543, T1098
- **Privilege Escalation**: T1548, T1068, T1055
- **Defense Evasion**: T1562, T1070, T1027
- **Credential Access**: T1003, T1110, T1555
- **Discovery**: T1087, T1083, T1046
- **Lateral Movement**: T1021, T1570, T1080
- **Collection**: T1560, T1005, T1114
- **C&C**: T1071, T1573, T1132
- **Exfiltration**: T1041, T1048, T1567
- **Impact**: T1486, T1490, T1529

---

## Best Practices

### 1. Собирайте полные данные
Чем больше событий вы передадите агенту, тем точнее будет расследование:
- Windows Event Logs
- Network traffic logs
- Process execution logs
- File access logs
- Registry changes
- Network connections

### 2. Включайте timestamp
Обязательно включайте временные метки для построения timeline

### 3. Добавляйте контекст
Добавляйте максимум информации:
- Hostname
- User
- Process names
- Command lines
- IP addresses
- File paths

### 4. Группируйте связанные события
Передавайте все события одного инцидента вместе

---

## Troubleshooting

### Агент не инициализируется

```bash
# Проверьте API ключ
echo $LLM_API_KEY

# Проверьте установку groq
pip list | grep groq
```

### Расследование занимает много времени

```bash
# Нормальное время: 30-60 секунд для 10-20 событий
# Увеличьте timeout в запросах до 300 секунд
```

### Не все IoC найдены

```
Агент использует AI для анализа - точность зависит от:
- Полноты предоставленных данных
- Качества описания событий
- Наличия известных паттернов
```

---

## Лицензия

MIT License

---

## Поддержка

Для вопросов:
- API документация: http://localhost:9000/docs
- Пример: `POST /investigation/example`

---

**Готово! Агент готов к расследованию кибер-инцидентов!**
