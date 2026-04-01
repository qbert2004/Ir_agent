# Оценка системы IR-Agent

## 1. Постановка задачи

**Цель:** Автоматизировать триаж и расследование инцидентов информационной безопасности
с помощью комбинации ML-классификации и LLM-агента, сократив нагрузку на аналитика SOC.

**Метрика успеха:**
- Точность ML-детектора на реальных данных >= 85%
- Ложноположительный уровень (FPR) < 10%
- Latency fast-path < 10 мс, deep-path < 30 с

---

## 2. История датасетов (важно для воспроизводимости)

### Версия 1 — Критическая утечка данных (`gradient_boosting_model.pkl`)

Accuracy 99.78% оказалась артефактом: `cmdline_length_norm` занимал 99.56% Gini importance.
Причина: синтетические benign события имели `command_line`, вредоносные EVTX-события — нет.

### Версия 2 — Честный split (`gradient_boosting_honest.pkl`)

Удалён `cmdline_length_norm`. Accuracy 98.81%, но train/val из одного синтетического пула.

### Версия 3 — Source-split (`gradient_boosting_production.pkl`, устаревшая)

```
TRAIN: evtx (37k атак) + synthetic (85k benign)
VAL:   unknown/PurpleSharp (48k атак)
```
Проблема (strict_audit): `synthetic=100% benign`, `evtx=100% malicious`.
Наивный классификатор по источнику = 100% accuracy. GroupKFold mean = 64.8%.

### Версия 4 — Real Benign (`gradient_boosting_production.pkl`, текущая) ✓

```
TRAIN: real_benign (60k Sysmon) + evtx (37k атак) + unknown_train (35k)
VAL:   real_benign (20k) + unknown_val (13k)
```

Ключевое изменение: **синтетика полностью убрана**. Оба класса — реальные логи.

**Источник benign:** 80 000 событий из реальных Sysmon логов (`datasets/real_benign_sysmon.json`),
`source_type=real_benign`, канал `Microsoft-Windows-Sysmon/Operational`.

**Скрипты воспроизведения:**
```bash
python scripts/rebuild_dataset.py          # пересборка датасета
python scripts/retrain_source_split.py     # переобучение
python scripts/strict_audit.py             # аудит утечек
```

---

## 3. Метрики производственной модели (версия 4)

Валидационная выборка: 32 957 событий (20 000 benign + 12 957 malicious).
Оба класса — реальные логи, не синтетика. Порог оптимизирован методом Youden J.

| Метрика | Значение |
|---------|:--------:|
| Accuracy | **91.81%** |
| ROC-AUC | **93.96%** |
| Precision (malicious) | **89.25%** |
| Recall (malicious) | **90.02%** |
| F1-Score (malicious) | **89.63%** |
| False Positive Rate | **7.03%** |
| False Negative Rate | **9.93%** |
| Threshold (Youden J) | **0.60** |

### Confusion Matrix (val = 32 957 реальных событий)

```
                   Predicted
                   Benign   Malicious
Actual Benign      18595        1405   <- 7.0% ложных тревог
Actual Malicious    1287       11670   <- 9.9% пропущено
```

### Важность признаков (Permutation, top-5)

| Ранг | Признак | Importance |
|------|---------|:---------:|
| 1 | has_hashes | 0.1538 |
| 2 | has_dest_ip | 0.0632 |
| 3 | driver_load | 0.0460 |
| 4 | eid_13 | 0.0351 |
| 5 | eid_5 | 0.0260 |

---

## 4. Сравнение подходов (Baseline Comparison)

Оценка на одной и той же валидационной выборке (32 957 событий).

| Подход | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|---|
| Rule-based (keywords/event_id) | 0.6069 | 1.0000 | 0.0002 | 0.0003 | N/A | 0.0% |
| ML-only (GradientBoosting) | 0.9181 | 0.8925 | 0.9002 | 0.8963 | 0.9396 | 7.0% |
| **ML + MITRE fusion (данная работа)** | **0.9174** | **0.8923** | **0.8984** | **0.8953** | **0.9424** | **7.0%** |

**Ключевой вывод:** Rule-based подход обнаруживает только 0.02% атак (Recall=0.0002) —
потому что реальные APT-события не всегда содержат тривиальные ключевые слова.
ML-классификатор улучшает Recall в 4500 раз при FPR=7%.

**Воспроизведение:**
```bash
python scripts/compare_baselines.py
# Результаты: reports/baseline_comparison.json
```

---

## 5. Оценка агента на ground-truth тестовых сценариях

30 вручную составленных инцидентов (19 вредоносных, 11 легитимных).

### Метрики инцидентного уровня

| Метрика | Значение |
|---------|:--------:|
| Accuracy | 70.0% (21/30) |
| Precision | 69.2% |
| Recall (atk detection) | **94.7%** |
| F1-Score | 80.0% |
| FPR на тестовых кейсах | 72.7%* |
| MITRE technique recall | **95.0%** (19/20) |

*Высокий FPR объясняется тем, что тест-кейсы содержат "граничные" benign команды
(python, schtasks, powershell без вредоносных флагов), которые имеют схожие признаки с атаками.
На реальной валидационной выборке (32k событий) FPR = 7.03%.

### Матрица ошибок (30 тестовых кейсов)

```
True Positives:  18  (обнаружены реальные атаки)
True Negatives:   3  (корректно отмечены benign)
False Positives:  8  (benign → malicious)
False Negatives:  1  (пропущена 1 атака: Cobalt Strike через svchost)
```

### Что пропущено и почему

| ID | Описание | Причина ошибки |
|----|----------|----------------|
| TC-016 | Нормальный логин | event_id=4624 схож с атаками logon |
| TC-025 | Win Defender schtasks | schtasks в cmd_line → признак атаки |
| TC-027 | Cobalt Strike через svchost | svchost.exe = нормальный процесс, нет keywords |
| TC-026 | PowerShell get-service | powershell.exe в suspicious_processes |

**Вывод:** Высокий recall на реальных атаках (94.7%), граничные случаи требуют контекстного
LLM-анализа — именно для этого и существует deep-path.

**Воспроизведение:**
```bash
python scripts/evaluate_agent.py --verbose
# Результаты: reports/agent_evaluation.json
```

---

## 6. ThreatAssessment Engine — обоснование весов

Итоговый threat score = взвешенная сумма 4 сигналов:

| Сигнал | Вес | Обоснование |
|--------|:---:|-------------|
| ML classifier | **0.35** | Быстрый, детерминированный |
| IoC provider | **0.30** | Внешняя верификация (VirusTotal/AbuseIPDB) |
| MITRE ATT&CK | **0.20** | Структурированный контекст |
| Agent (LLM) | **0.15** | Tie-breaker; LLM может галлюцинировать |

Правила арбитража: 7 жёстких правил (hard overrides), переопределяющих взвешенное слияние.

---

## 7. Explainability: LIME интеграция

LIME доступен через API эндпоинт (не просто скрипт):

```bash
POST /ml/explain
{
  "event": {
    "event_id": 4688,
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -enc SGVsbG8="
  },
  "num_features": 10
}
```

Пример ответа:
```json
{
  "prediction": "malicious",
  "confidence": 0.9823,
  "top_features": [
    {"feature": "base64_encoded", "value": 1.0, "contribution": 0.31, "direction": "malicious"},
    {"feature": "susp_process_partial", "value": 1.0, "contribution": 0.18, "direction": "malicious"}
  ]
}
```

---

## 8. Производительность пайплайна

| Путь | Условие | Latency |
|------|---------|---------|
| Fast-path (ML only) | ML confidence > 0.80 | ~5 мс |
| Deep-path (ML + Agent) | ML confidence 0.60–0.80 | 1–30 с |
| Discard | ML confidence < 0.60 | — |

---

## 9. Ограничения

1. **Coupling source-label** — real_benign=benign, evtx=malicious. Устранить полностью
   можно только при наличии benign-событий из тех же систем, где фиксировались атаки.
2. **Граничные benign кейсы** — python.exe, schtasks, powershell без вредоносных флагов
   дают FP. Решение: LLM-анализ в deep-path.
3. **LLM-зависимость** — deep-path требует Groq/OpenAI/Ollama; при недоступности используется ML-only.
4. **Temporal validation** — разбиение по источнику, не по времени.

---

## 10. Воспроизводимость (полный пайплайн)

```bash
# 1. Пересборка датасета (убирает синтетику, добавляет real benign)
python scripts/rebuild_dataset.py

# 2. Переобучение модели
python scripts/retrain_source_split.py

# 3. Аудит утечек
python scripts/strict_audit.py

# 4. Сравнение с baseline
python scripts/compare_baselines.py

# 5. Оценка агента (30 тестовых сценариев)
python scripts/evaluate_agent.py --verbose

# 6. Запуск тестов
pytest tests/ -v --tb=short

# Результаты сохраняются в reports/
```
