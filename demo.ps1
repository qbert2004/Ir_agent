# =============================================================================
# IR-Agent — демонстрационный скрипт
# Запускает Docker-контейнер и показывает все возможности проекта
#
# Использование:
#   powershell -ExecutionPolicy Bypass -File demo.ps1
# =============================================================================

$docker = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
$BASE   = "http://localhost:9000"

# Вспомогательная функция — красивый вывод заголовков
function Section($title) {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
}

# Вспомогательная функция — POST-запрос с выводом результата
function Post($url, $body) {
    Invoke-RestMethod -Method POST -Uri $url `
        -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 10
}

# =============================================================================
# ШАГ 1 — Сборка Docker-образа
# =============================================================================
Section "ШАГ 1: Сборка Docker-образа"

# Собираем образ ir-agent из Dockerfile в текущей папке
& $docker build -t ir-agent .

# =============================================================================
# ШАГ 2 — Запуск контейнера
# =============================================================================
Section "ШАГ 2: Запуск контейнера"

# Останавливаем старый контейнер (если был запущен)
& $docker stop ir-agent 2>$null
& $docker rm   ir-agent 2>$null

# Запускаем контейнер:
#   -d               — фоновый режим
#   -p 9000:9000     — проброс порта
#   -e ENVIRONMENT=development — включает Swagger UI на /docs
& $docker run -d --name ir-agent -p 9000:9000 -e ENVIRONMENT=development ir-agent

# Ждём старта сервера
Write-Host "Ожидаем старт сервера..." -ForegroundColor Yellow
Start-Sleep -Seconds 6

# Показываем логи запуска
& $docker logs ir-agent

# =============================================================================
# ШАГ 3 — Health-checks
# =============================================================================
Section "ШАГ 3: Health-checks"

# Liveness — сервис живой?
Write-Host "`n[GET /health/live]" -ForegroundColor Green
Invoke-RestMethod "$BASE/health/live"

# Readiness — БД и ML готовы?
Write-Host "`n[GET /health/ready]" -ForegroundColor Green
Invoke-RestMethod "$BASE/health/ready"

# Полный health — все компоненты
Write-Host "`n[GET /health]" -ForegroundColor Green
Invoke-RestMethod "$BASE/health" | ConvertTo-Json -Depth 5

# ML-движок — модель загружена, drift-detector
Write-Host "`n[GET /health/ml]" -ForegroundColor Green
Invoke-RestMethod "$BASE/health/ml" | ConvertTo-Json -Depth 5

# =============================================================================
# ШАГ 4 — Информация о ML-движке
# =============================================================================
Section "ШАГ 4: ML-движок (точность, MITRE-техники)"

# Accuracy, ROC-AUC, количество MITRE ATT&CK техник
Invoke-RestMethod "$BASE/ml/engine-info" | ConvertTo-Json -Depth 5

# =============================================================================
# ШАГ 5 — Классификация одного события
# =============================================================================
Section "ШАГ 5: Классификация события (ML)"

# Подозрительный PowerShell с base64-кодированной командой
$event_classify = @'
{
  "event": {
    "event_id": 4688,
    "hostname": "WS-USER01",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
    "parent_image": "cmd.exe",
    "user": "john.doe"
  }
}
'@

Write-Host "[POST /ml/classify] — PowerShell с base64" -ForegroundColor Green
Post "$BASE/ml/classify" $event_classify

# =============================================================================
# ШАГ 6 — MITRE ATT&CK маппинг
# =============================================================================
Section "ШАГ 6: MITRE ATT&CK маппинг"

# Удаление теневых копий — типичный признак ransomware (T1490)
$event_mitre = @'
{
  "event": {
    "event_id": 4688,
    "hostname": "WS-USER01",
    "process_name": "cmd.exe",
    "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet"
  }
}
'@

Write-Host "[POST /ml/mitre-map] — vssadmin delete shadows" -ForegroundColor Green
Post "$BASE/ml/mitre-map" $event_mitre

# =============================================================================
# ШАГ 7 — Извлечение IoC
# =============================================================================
Section "ШАГ 7: Извлечение индикаторов компрометации (IoC)"

# Сетевое соединение с подозрительным IP Tor-узла
$event_ioc = @'
{
  "event": {
    "event_id": 3,
    "hostname": "WS-USER01",
    "process_name": "invoice_2024.exe",
    "destination_ip": "185.220.101.45",
    "destination_port": 443
  }
}
'@

Write-Host "[POST /ml/extract-iocs] — подозрительный IP" -ForegroundColor Green
Post "$BASE/ml/extract-iocs" $event_ioc

# =============================================================================
# ШАГ 8 — Готовый пример расследования (ransomware)
# =============================================================================
Section "ШАГ 8: Полное ML-расследование (пример ransomware)"

# Встроенный пример: цепочка атаки от фишинга до шифрования файлов
# Входные данные — 6 событий, которые уже зашиты в /ml/investigate/example
Write-Host "[POST /ml/investigate/example]" -ForegroundColor Green
Invoke-RestMethod -Method POST -Uri "$BASE/ml/investigate/example" | ConvertTo-Json -Depth 10

# =============================================================================
# ШАГ 9 — Инжест событий в пайплайн ML+Agent
# =============================================================================
Section "ШАГ 9: Инжест событий — ML + CyberAgent pipeline"

# Отправляем 3 события:
#   1. mimikatz — дамп учётных данных
#   2. svchost  — нормальный системный процесс (должен быть отфильтрован)
#   3. powershell с base64 — неопределённый (уйдёт в deep-path к агенту)
$events = @'
[
  {
    "event_id": 4688,
    "hostname": "DC-01",
    "process_name": "mimikatz.exe",
    "command_line": "mimikatz privilege::debug sekurlsa::logonpasswords",
    "user": "admin"
  },
  {
    "event_id": 4624,
    "hostname": "SRV-02",
    "process_name": "svchost.exe",
    "user": "SYSTEM",
    "logon_type": 5
  },
  {
    "event_id": 4688,
    "hostname": "WS-03",
    "process_name": "powershell.exe",
    "command_line": "powershell -enc SGVsbG8gV29ybGQ="
  }
]
'@

Write-Host "[POST /ingest/telemetry]" -ForegroundColor Green
Post "$BASE/ingest/telemetry" $events

# Ждём обработки в фоне
Start-Sleep -Seconds 3

# Метрики пайплайна: fast-path vs deep-path, отфильтровано/обнаружено
Write-Host "`n[GET /ingest/metrics] — статистика обработки" -ForegroundColor Green
Invoke-RestMethod "$BASE/ingest/metrics" | ConvertTo-Json -Depth 5

# Автоматически скоррелированные инциденты
Write-Host "`n[GET /ingest/incidents] — список инцидентов" -ForegroundColor Green
Invoke-RestMethod "$BASE/ingest/incidents" | ConvertTo-Json -Depth 5

# =============================================================================
# ШАГ 10 — Prometheus-метрики и веб-интерфейсы
# =============================================================================
Section "ШАГ 10: Метрики и веб-интерфейсы"

# Метрики в формате Prometheus (для Grafana/мониторинга)
Write-Host "[GET /metrics] — Prometheus" -ForegroundColor Green
(Invoke-WebRequest "$BASE/metrics").Content

# Открываем Swagger UI — интерактивная документация API
Write-Host "`nОткрываем Swagger UI..." -ForegroundColor Yellow
Start-Process "$BASE/docs"

# Открываем Dashboard — архитектура, live-запросы, инструменты агента
Write-Host "Открываем Dashboard..." -ForegroundColor Yellow
Start-Process "$BASE/dashboard"

# Открываем Report UI
Write-Host "Открываем Report UI..." -ForegroundColor Yellow
Start-Process "$BASE/report_ui"

# =============================================================================
Section "ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА"
Write-Host "Сервер продолжает работать на $BASE" -ForegroundColor Green
Write-Host "Для остановки: docker stop ir-agent" -ForegroundColor Yellow
