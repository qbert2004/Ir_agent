# Оценка системы IR-Agent

## 1. Постановка задачи

**Цель:** Автоматизировать триаж и расследование инцидентов информационной безопасности
с помощью комбинации ML-классификации и LLM-агента, сократив нагрузку на аналитика SOC.

**Метрика успеха:**
- Точность ML-детектора на реальных данных (не синтетических) ≥ 85%
- Ложноположительный уровень (FPR) < 5% (ложные тревоги недопустимы в SOC)
- Latency fast-path < 10 мс, deep-path < 30 с

---

## 2. Датасет

| Источник | События | % | Тип |
|----------|---------|---|-----|
| Реальные EVTX-логи (Windows event logs) | 37 364 | 21.9% | Настоящий трафик |
| PurpleSharp AD Playbook + PetiPotam | 48 009 | 28.1% | Реальные APT-симуляции |
| Синтетические (`augment_data.py`) | 85 355 | 50.0% | Сгенерированные |
| **Итого** | **170 728** | | |

**Классовый баланс:** malicious_critical (84 755) vs benign (85 373) — соотношение ≈ 1:1 после SMOTE.

---

## 3. Эволюция модели

### Версия 1 — Критическая утечка данных

**Файл:** `gradient_boosting_model.pkl`

Лабораторная точность 99.78% оказалась артефактом структурной утечки:

| Признак | Gini Importance |
|---------|:-:|
| `cmdline_length_norm` | **99.56%** |
| Все остальные | 0.44% |

**Причина:** бенигновые (синтетические) события всегда содержат поле `command_line` →
`cmdline_length_norm > 0`. Вредоносные события (Sysmon registry/network, event_ids 5–13) →
нет `command_line` → `cmdline_length_norm = 0`. Модель выучила тривиальный артефакт.

Дополнительно: 170 728 событий → только **469 уникальных вектора признаков** (340 дубликатов на вектор).
Feature overlap train/val: **76.8%** (случайное разбиение из одного пула).

**Оценка реальной производительности: 55–65%.**

---

### Версия 2 — Honest Split

**Файл:** `gradient_boosting_honest.pkl`

Исправления: удалён `cmdline_length_norm`, добавлены one-hot 20 event_id, итого 39 признаков.
Accuracy: **98.81%** — улучшение, но train/val по-прежнему из одного синтетического пула.

---

### Версия 3 — Production (Source-Stratified)

**Файл:** `gradient_boosting_production.pkl` ← **текущая**

**Стратегия разбиения:**
- TRAIN: `{evtx, synthetic}` → 122 719 событий
- VAL: `{unknown}` → 48 009 событий (реальные APT-записи, другой источник — утечки нет)

---

## 4. Метрики производственной модели

Валидационная выборка — **реальные APT-записи (PurpleSharp, PetiPotam), отсутствующие в обучающей выборке**.

| Метрика | Значение |
|---------|:--------:|
| Accuracy | **98.58%** |
| ROC-AUC | **99.44%** |
| Precision (malicious) | 100.00% |
| Recall (malicious) | **98.58%** |
| F1-Score (malicious) | **99.28%** |
| False Positive Rate | **0.00%** |
| False Negative Rate | **1.42%** |
| Feature overlap train/val | **46.0%** (было 76.8%) |

### Confusion Matrix (val = 48 009 реальных APT-событий)

```
                   Predicted
                   Benign   Malicious
Actual Benign          18           0   ← 0 ложных тревог
Actual Malicious      682      47 309   ← 682 пропущено (1.42%)
```

### Важность признаков (Permutation, top-5)

| Ранг | Признак | Importance |
|------|---------|:---------:|
| 1 | network_logon | 0.0020 |
| 2 | eid_4624 | 0.0017 |
| 3 | kw_count_norm | 0.0005 |
| 4 | susp_process_partial | 0.0004 |
| 5 | network_download | 0.0001 |

Низкие значения permutation importance указывают на **совместное использование 41 признака**
(нет одного доминирующего) — желательная характеристика для production-устойчивости.

---

## 5. ThreatAssessment Engine — обоснование весов

Итоговый threat score = взвешенная сумма 4 сигналов:

| Сигнал | Вес | Обоснование |
|--------|:---:|-------------|
| ML classifier | **0.35** | Быстрый, детерминированный; наиболее надёжен на обученных паттернах |
| IoC provider | **0.30** | Внешняя верификация (VirusTotal/AbuseIPDB); высокая специфичность |
| MITRE ATT&CK | **0.20** | Структурированный контекст; не всегда применим |
| Agent (LLM) | **0.15** | Наименьший вес: LLM может галлюцинировать; используется как tie-breaker |

Сумма: 1.00. Приоритет дан детерминированным источникам (ML + IoC = 65%)
над вероятностными (MITRE + Agent = 35%).

### Правила арбитража (hard overrides, 7 правил)

Блокирующие условия, переопределяющие взвешенное слияние:

| Условие | Действие |
|---------|----------|
| ≥2 IoC-провайдера подтвердили malicious | severity = CRITICAL |
| lsass dump + credential_access technique | severity = CRITICAL |
| Agent вернул FALSE_POSITIVE при ML < 0.60 | severity = LOW |
| MITRE: lateral_movement + credential_access в одном инциденте | severity ≥ HIGH |

---

## 6. Производительность пайплайна

| Путь | Условие | Latency |
|------|---------|---------|
| Fast-path (ML only) | ML confidence > 0.85 | **~5 мс** |
| Deep-path (ML + Agent) | ML confidence 0.50–0.85 | **1–30 с** |
| Discard | ML confidence < 0.50 | — |

---

## 7. Ограничения

1. **50% синтетических данных** — датасет обогащён сгенерированными событиями; на truly novel attacks ожидаемая деградация: −10 до −20% (оценка 78–88%)
2. **682 пропущенных события** (FNR 1.42%) — техники PurpleSharp/PetiPotam, отсутствующие в EVTX-выборке обучения; перекрываются слоями IoC и MITRE
3. **LLM-зависимость** — deep-path требует API-ключ (Groq/OpenAI/Ollama); при недоступности используется ML-only режим
4. **Prompt injection** — базовая защита (string substitution); полный adversarial тест не проводился
5. **Временна́я валидация** — разбиение по источнику (не по времени); сезонные паттерны не учтены
6. **Single-worker** — in-memory state (RAG, IoC cache) не разделяется между инстансами без Redis

---

## 8. Воспроизводимость

```bash
# Переобучение производственной модели (source-stratified)
python scripts/retrain_source_split.py

# Валидация модели
python scripts/validate_ml_model.py

# Строгий аудит
python scripts/strict_audit.py

# Запуск тестов
pytest tests/ -v --tb=short
```

Результаты аудита сохраняются в `reports/`.
