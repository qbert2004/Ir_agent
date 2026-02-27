# ШПАРГАЛКА ДЛЯ ЗАЩИТЫ ДИПЛОМА

## Быстрые ответы на типичные вопросы

---

## 1. ЧТО ТАКОЕ ИИ-АГЕНТ?

```
ИИ-агент = LLM + Tools + Memory + Planning

Обычный LLM:     Вопрос → Ответ
ИИ-агент:        Цель → Планирование → Действия → Наблюдения → Результат
```

**Ключевое отличие:** Агент ДЕЙСТВУЕТ, а не только отвечает.

---

## 2. АРХИТЕКТУРА ReAct (знать наизусть!)

```
THOUGHT → ACTION → OBSERVATION → THOUGHT → ... → FINAL ANSWER

Пример:
1. THOUGHT: "Нужно проанализировать mimikatz.exe"
2. ACTION: mitre_lookup(technique="T1003")
3. OBSERVATION: "T1003 - Credential Dumping"
4. THOUGHT: "Это кража учётных данных"
5. FINAL ANSWER: "Обнаружена атака credential theft..."
```

**Источник:** Yao et al., 2022 "ReAct: Synergizing Reasoning and Acting"

---

## 3. RAG PIPELINE (знать наизусть!)

```
┌──────────────────────────────────────────────────────────────┐
│  INDEXING (offline):                                         │
│  Documents → Chunking → Embedding → Vector Store             │
├──────────────────────────────────────────────────────────────┤
│  RETRIEVAL (online):                                         │
│  Query → Embedding → Similarity Search → Context → LLM       │
└──────────────────────────────────────────────────────────────┘
```

**Зачем RAG?**
- LLM не знает ваши данные
- Уменьшает галлюцинации
- Знания обновляются без переобучения

---

## 4. КЛЮЧЕВЫЕ БИБЛИОТЕКИ

| Библиотека | Для чего | Запомнить |
|------------|----------|-----------|
| **groq** | LLM API | LLaMA 3.3 70B, 500 tok/sec |
| **fastapi** | Web API | Async, автодокументация |
| **faiss** | Векторный поиск | Facebook AI, L2 distance |
| **sentence-transformers** | Embeddings | all-MiniLM-L6-v2, dim=384 |
| **scikit-learn** | ML | RandomForest, XGBoost |
| **pydantic** | Валидация | Типизация, schemas |

---

## 5. MITRE ATT&CK (знать основы!)

**14 тактик (ЗАЧЕМ атакует):**
```
1. Reconnaissance          8. Credential Access
2. Resource Development    9. Discovery
3. Initial Access         10. Lateral Movement
4. Execution              11. Collection
5. Persistence            12. Command & Control
6. Privilege Escalation   13. Exfiltration
7. Defense Evasion        14. Impact
```

**Популярные техники:**
- T1566 - Phishing
- T1003 - Credential Dumping (mimikatz)
- T1486 - Data Encrypted (ransomware)
- T1021 - Remote Services (lateral movement)

---

## 6. ТИПЫ ИНЦИДЕНТОВ

| Тип | Признаки |
|-----|----------|
| **Ransomware** | Шифрование файлов, ransom note, vssadmin delete |
| **Credential Theft** | mimikatz, lsass.exe access, T1003 |
| **Lateral Movement** | RDP, PsExec, несколько хостов |
| **Data Breach** | Exfiltration, большие объёмы данных наружу |
| **Malware** | Подозрительные процессы, C2 коммуникации |

---

## 7. СТРУКТУРА ПРОЕКТА (знать!)

```
app/
├── agent/
│   ├── core/agent.py      # ReAct loop
│   ├── tools/             # Инструменты
│   ├── memory/            # Short + Long term
│   └── rag/               # Embeddings, Vector Store
├── routers/               # API endpoints
└── services/              # Бизнес-логика
```

---

## 8. API ENDPOINTS

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/investigation/start` | POST | Начать расследование |
| `/investigation/{id}/report` | GET | Получить отчёт |
| `/agent/query` | POST | Запрос к агенту |
| `/health` | GET | Статус сервиса |

---

## 9. ФОРМУЛЫ И МЕТРИКИ

**Cosine Similarity (для векторного поиска):**
```
sim(A,B) = (A·B) / (||A|| × ||B||)
```

**Метрики классификации:**
```
Accuracy = (TP + TN) / (TP + TN + FP + FN)
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

---

## 10. СЛОВАРЬ ТЕРМИНОВ (выучить!)

| Термин | Значение |
|--------|----------|
| **IoC** | Indicator of Compromise (IP, hash, domain) |
| **TTP** | Tactics, Techniques, Procedures |
| **SOC** | Security Operations Center |
| **SIEM** | Security Information & Event Management |
| **MTTD** | Mean Time To Detect |
| **MTTR** | Mean Time To Respond |
| **Embedding** | Векторное представление текста |
| **Hallucination** | Выдумка LLM |
| **Context Window** | Максимальный размер контекста LLM |

---

## 11. ПРЕИМУЩЕСТВА СИСТЕМЫ

```
Vs Manual Analysis:        Vs Rule-based SIEM:
+ Скорость (минуты vs часы)   + Понимает контекст
+ 24/7 без усталости          + Меньше false positives
+ Консистентность             + Не нужно писать правила
+ Масштабируемость            + Работает с новыми атаками
```

---

## 12. ОГРАНИЧЕНИЯ (честно сказать!)

- Зависит от качества входных данных
- Latency из-за LLM вызовов (~5-30 сек)
- Возможны галлюцинации LLM
- Требует API ключ (стоимость)
- Не заменяет эксперта полностью

---

## 13. ПЛАН РАЗВИТИЯ

1. **Multi-agent** - специализированные агенты
2. **Self-reflection** - самооценка решений
3. **Fine-tuning** - дообучение на своих данных
4. **SIEM интеграция** - Splunk, Elastic
5. **Auto-remediation** - автоматическое реагирование

---

## 14. КАК ДЕМОНСТРИРОВАТЬ

```bash
# 1. Запустить сервер
python app/main.py

# 2. Открыть Swagger UI
http://localhost:9000/docs

# 3. Выполнить пример
POST /investigation/example

# 4. Показать отчёт
GET /investigation/INC-EXAMPLE/report
```

---

## 15. ОТВЕТЫ НА КАВЕРЗНЫЕ ВОПРОСЫ

**"Почему не OpenAI?"**
> Groq быстрее (500 vs 50 tok/sec), бесплатный tier, открытые модели.

**"Что если LLM ошибётся?"**
> Комбинация с ML-классификатором, валидация через RAG, человек в цикле.

**"Как масштабировать?"**
> Async архитектура, можно горизонтально масштабировать API, LLM через облако.

**"Это заменит аналитика?"**
> Нет, это инструмент усиления. Автоматизирует рутину, эксперт принимает решения.

**"Откуда берутся знания?"**
> RAG из MITRE ATT&CK + threat intel + внутренняя база знаний.

---

## ГЛАВНОЕ ЗАПОМНИТЬ

```
1. Агент = LLM + Tools + Memory
2. ReAct = Thought → Action → Observation → ... → Answer
3. RAG = Retrieval + Generation (знания без переобучения)
4. MITRE ATT&CK = база знаний об атаках (14 тактик, 200+ техник)
5. Цель = автоматизация рутины SOC-аналитика
```

---

**Удачи на защите!**
