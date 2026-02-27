# Документация для защиты диплома
## "ИИ-агент для расследования кибер-инцидентов"

---

# СОДЕРЖАНИЕ

1. [Введение и актуальность](#1-введение-и-актуальность)
2. [Теоретические основы](#2-теоретические-основы)
3. [Архитектура системы](#3-архитектура-системы)
4. [Технологический стек](#4-технологический-стек)
5. [Описание компонентов](#5-описание-компонентов)
6. [Алгоритмы и методы](#6-алгоритмы-и-методы)
7. [API и интерфейсы](#7-api-и-интерфейсы)
8. [Результаты и метрики](#8-результаты-и-метрики)
9. [Глоссарий терминов](#9-глоссарий-терминов)
10. [Вопросы для защиты](#10-вопросы-для-защиты)

---

# 1. ВВЕДЕНИЕ И АКТУАЛЬНОСТЬ

## 1.1 Проблематика

**Проблема:** Современные SOC (Security Operations Center) сталкиваются с:
- 10,000+ алертов в день на одного аналитика
- Среднее время обнаружения инцидента (MTTD): 207 дней
- Среднее время реагирования (MTTR): 73 дня
- Дефицит кадров: 3.5 млн вакансий в кибербезопасности глобально

**Решение:** Автономный ИИ-агент, который:
- Автоматизирует рутинный анализ
- Проводит полное расследование инцидента
- Генерирует отчёты с рекомендациями
- Работает 24/7 без усталости

## 1.2 Цели и задачи

**Цель:** Разработка автономного ИИ-агента дл**я комплексного расследования кибер-инцидентов.

**Задачи:**
1. Исследовать архитектуры ИИ-агентов (ReAct, Chain-of-Thought)
2. Разработать си**стему инструментов для анализа событий
3. Реализовать RAG-систему для базы знаний MITRE ATT&CK
4. Создать систему памяти агента
5. Интегрировать ML-модели для классификации событий
6. Разработать API для интеграции с SIEM-системами

## 1.3 Научная новизна

1. **Комбинация ReAct + RAG** для domain-specific задач кибербезопасности
2. **Автоматическое маппирование на MITRE ATT&CK** с использованием семантического поиска
3. **Мультимодальный анализ**: логи + сетевой трафик + поведенческие паттерны

---

# 2. ТЕОРЕТИЧЕСКИЕ ОСНОВЫ

## 2.1 Что такое ИИ-агент?

**Определение:** ИИ-агент - это автономная система, способная:
- Воспринимать окружение (Perceive)
- Принимать решения (Reason)
- Выполнять действия (Act)
- Обучаться на опыте (Learn)

```
┌─────────────────────────────────────────────────────────────┐
│                      ИИ-АГЕНТ                               │
│                                                             │
│    Окружение ──▶ [Восприятие] ──▶ [Рассуждение] ──▶ Действие│
│         ▲                              │                    │
│         │                              ▼                    │
│         └──────────── [Память] ◀───────┘                    │
└─────────────────────────────────────────────────────────────┘
```

**Отличие от обычного LLM:**

| Аспект | LLM (ChatGPT) | ИИ-Агент |
|--------|---------------|----------|
| Автономность | Отвечает на запросы | Самостоятельно планирует и действует |
| Инструменты | Нет доступа к внешним системам | Использует tools (API, БД, код) |
| Память | Только контекст диалога | Долгосрочная + краткосрочная память |
| Цели | Ответить на вопрос | Достичь поставленной цели |

## 2.2 Архитектура ReAct (Reasoning + Acting)

**ReAct** - парадигма, объединяющая рассуждение и действие.

**Цикл работы:**
```
1. THOUGHT (Мысль): "Мне нужно проанализировать процесс mimikatz.exe"
2. ACTION (Действие): analyze_event(process_name="mimikatz.exe")
3. OBSERVATION (Наблюдение): "Это известный инструмент для дампа credentials"
4. THOUGHT: "Это атака T1003 - Credential Dumping"
5. ACTION: mitre_lookup(technique_id="T1003")
6. OBSERVATION: "T1003 - OS Credential Dumping..."
7. FINAL ANSWER: "Обнаружена попытка кражи учётных данных..."
```

**Преимущества ReAct:**
- Прозрачность рассуждений (explainability)
- Возможность использовать внешние инструменты
- Итеративное уточнение через наблюдения

**Источник:** Yao et al., "ReAct: Synergizing Reasoning and Acting in Language Models", 2022

## 2.3 RAG (Retrieval-Augmented Generation)

**RAG** - метод дополнения LLM внешними знаниями.

```
┌─────────────────────────────────────────────────────────────┐
│                        RAG Pipeline                         │
│                                                             │
│  Запрос ──▶ [Embedding] ──▶ [Vector Search] ──▶ Контекст   │
│                                     │                       │
│                                     ▼                       │
│                    [LLM + Контекст] ──▶ Ответ              │
└─────────────────────────────────────────────────────────────┘
```

**Компоненты RAG в проекте:**
1. **Chunker** - разбивка документов на фрагменты
2. **Embeddings** - векторизация текста (sentence-transformers)
3. **Vector Store** - хранение и поиск (FAISS)
4. **Retriever** - извлечение релевантных фрагментов

**Зачем RAG:**
- LLM не знает специфику вашей организации
- База знаний MITRE ATT&CK обновляется
- Уменьшает галлюцинации LLM

## 2.4 MITRE ATT&CK Framework

**MITRE ATT&CK** - база знаний о тактиках и техниках атакующих.

**Структура:**
```
Тактика (Зачем?) ──▶ Техника (Как?) ──▶ Процедура (Конкретно как?)

Пример:
Credential Access (TA0006) ──▶ OS Credential Dumping (T1003) ──▶ Mimikatz
```

**14 тактик:**
1. Reconnaissance - Разведка
2. Resource Development - Подготовка ресурсов
3. Initial Access - Первичный доступ
4. Execution - Выполнение
5. Persistence - Закрепление
6. Privilege Escalation - Повышение привилегий
7. Defense Evasion - Обход защиты
8. Credential Access - Доступ к учётным данным
9. Discovery - Исследование
10. Lateral Movement - Горизонтальное перемещение
11. Collection - Сбор данных
12. Command and Control - Управление
13. Exfiltration - Вывод данных
14. Impact - Воздействие

## 2.5 Incident Response Lifecycle

**NIST SP 800-61 Rev. 2:**
```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Preparation │───▶│  Detection & │───▶│ Containment, │───▶│Post-Incident │
│              │    │   Analysis   │    │ Eradication, │    │   Activity   │
│              │    │              │    │   Recovery   │    │              │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

**Наш агент автоматизирует:**
- Detection & Analysis (классификация, timeline, IoC)
- Частично Containment (рекомендации)
- Post-Incident (отчёты, lessons learned)

---

# 3. АРХИТЕКТУРА СИСТЕМЫ

## 3.1 Высокоуровневая архитектура

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CYBER INCIDENT INVESTIGATION AGENT                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                           PRESENTATION LAYER                         │   │
│  │                                                                       │   │
│  │   FastAPI Server ◀──▶ REST API ◀──▶ Swagger UI                      │   │
│  │        :9000           /investigation    /docs                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                            AGENT LAYER                               │   │
│  │                                                                       │   │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │   │
│  │   │   ReAct     │    │   Memory    │    │    RAG      │             │   │
│  │   │   Engine    │◀──▶│   Manager   │◀──▶│   System    │             │   │
│  │   │             │    │             │    │             │             │   │
│  │   └──────┬──────┘    └─────────────┘    └─────────────┘             │   │
│  │          │                                                           │   │
│  │          ▼                                                           │   │
│  │   ┌─────────────────────────────────────────────────────────┐       │   │
│  │   │                    TOOL REGISTRY                         │       │   │
│  │   │                                                          │       │   │
│  │   │  analyze_event │ search_logs │ mitre_lookup │ query_siem │       │   │
│  │   │  classify_event│ lookup_ioc  │ investigate  │ knowledge  │       │   │
│  │   └─────────────────────────────────────────────────────────┘       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                            DATA LAYER                                │   │
│  │                                                                       │   │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │   │
│  │   │   Vector    │    │   Event     │    │   Knowledge │             │   │
│  │   │   Store     │    │   Store     │    │   Base      │             │   │
│  │   │   (FAISS)   │    │   (JSON)    │    │   (MITRE)   │             │   │
│  │   └─────────────┘    └─────────────┘    └─────────────┘             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          EXTERNAL SERVICES                           │   │
│  │                                                                       │   │
│  │   Groq API (LLM)  │  Threat Intel APIs  │  SIEM Integration         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 3.2 Структура проекта

```
PythonProject2/
│
├── app/                              # Основное приложение
│   ├── main.py                       # FastAPI точка входа
│   │
│   ├── agent/                        # Агентный модуль
│   │   ├── core/
│   │   │   ├── agent.py              # ReAct агент
│   │   │   └── reasoning.py          # Парсинг LLM output
│   │   │
│   │   ├── tools/                    # Инструменты агента
│   │   │   ├── base.py               # Базовый класс Tool
│   │   │   ├── analyze_event.py      # Анализ событий
│   │   │   ├── classify_event.py     # ML-классификация
│   │   │   ├── mitre_lookup.py       # Поиск по MITRE
│   │   │   ├── lookup_ioc.py         # Проверка IoC
│   │   │   ├── search_logs.py        # Поиск в логах
│   │   │   ├── query_siem.py         # Запросы к SIEM
│   │   │   └── knowledge_search.py   # RAG поиск
│   │   │
│   │   ├── memory/                   # Система памяти
│   │   │   ├── memory_manager.py     # Менеджер памяти
│   │   │   ├── short_term.py         # Краткосрочная память
│   │   │   └── long_term.py          # Долгосрочная память
│   │   │
│   │   ├── rag/                      # RAG система
│   │   │   ├── embeddings.py         # Векторизация
│   │   │   ├── vector_store.py       # FAISS хранилище
│   │   │   ├── chunker.py            # Разбиение текста
│   │   │   ├── retriever.py          # Извлечение контекста
│   │   │   └── ingestion.py          # Загрузка документов
│   │   │
│   │   ├── prompts/                  # Промпты
│   │   │   ├── system_prompts.py     # Системные промпты
│   │   │   └── react_templates.py    # ReAct шаблоны
│   │   │
│   │   └── schemas.py                # Pydantic модели
│   │
│   ├── routers/                      # API endpoints
│   │   ├── agent.py                  # /agent/*
│   │   ├── investigation.py          # /investigation/*
│   │   ├── ingest.py                 # /ingest/*
│   │   └── health.py                 # /health
│   │
│   ├── services/                     # Бизнес-логика
│   │   ├── agent_service.py          # Сервис агента
│   │   ├── investigation_service.py  # Сервис расследований
│   │   ├── ml_detector.py            # ML детектор
│   │   └── event_processor.py        # Обработка событий
│   │
│   └── models/                       # Модели данных
│       ├── telemetry.py              # Телеметрия
│       └── analysis.py               # Результаты анализа
│
├── cyber_incident_investigator.py    # Standalone агент
├── knowledge_base/                   # База знаний
├── datasets/                         # Датасеты
├── models/                           # ML модели
├── scripts/                          # Утилиты
│
├── requirements.txt                  # Зависимости
├── .env                              # Конфигурация
└── README.md                         # Документация
```

## 3.3 Диаграмма последовательности расследования

```
┌──────┐     ┌─────────┐     ┌───────┐     ┌───────┐     ┌─────┐     ┌────────┐
│Client│     │  API    │     │ Agent │     │ Tools │     │ LLM │     │ Memory │
└──┬───┘     └────┬────┘     └───┬───┘     └───┬───┘     └──┬──┘     └────┬───┘
   │              │              │             │            │             │
   │ POST /start  │              │             │            │             │
   │─────────────▶│              │             │            │             │
   │              │ start_invest │             │            │             │
   │              │─────────────▶│             │            │             │
   │              │              │             │            │             │
   │              │              │ get_context │            │             │
   │              │              │────────────────────────────────────────▶│
   │              │              │◀───────────────────────────────────────│
   │              │              │             │            │             │
   │              │              │──── ReAct Loop ─────────────────────── │
   │              │              │             │            │             │
   │              │              │ Thought+Act │            │             │
   │              │              │────────────────────────▶│             │
   │              │              │◀────────────────────────│             │
   │              │              │             │            │             │
   │              │              │ execute_tool│            │             │
   │              │              │────────────▶│            │             │
   │              │              │◀────────────│            │             │
   │              │              │             │            │             │
   │              │              │  ... repeat max 8 times ...            │
   │              │              │             │            │             │
   │              │              │ store_result│            │             │
   │              │              │────────────────────────────────────────▶│
   │              │              │             │            │             │
   │              │◀─────────────│             │            │             │
   │◀─────────────│              │             │            │             │
   │   Report     │              │             │            │             │
```

---

# 4. ТЕХНОЛОГИЧЕСКИЙ СТЕК

## 4.1 Основные библиотеки

### Языковые модели (LLM)

| Библиотека | Версия | Назначение |
|------------|--------|------------|
| **groq** | 0.33.0 | API клиент для Groq Cloud (LLaMA 3.3 70B) |

**Почему Groq:**
- Скорость: ~500 tokens/sec (в 10x быстрее OpenAI)
- Бесплатный tier: 30 запросов/мин
- Поддержка LLaMA 3.3 70B - state-of-the-art открытая модель

```python
from groq import Groq

client = Groq(api_key="...")
response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": "Analyze this event..."}]
)
```

### Web Framework

| Библиотека | Версия | Назначение |
|------------|--------|------------|
| **fastapi** | 0.115.0 | Асинхронный веб-фреймворк |
| **uvicorn** | 0.32.0 | ASGI сервер |
| **pydantic** | 2.9.0 | Валидация данных |
| **starlette** | 0.38.6 | ASGI toolkit (под капотом FastAPI) |

**Почему FastAPI:**
- Автоматическая документация (Swagger/OpenAPI)
- Асинхронность (async/await)
- Типизация и валидация из коробки
- Высокая производительность

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class InvestigationRequest(BaseModel):
    incident_id: str
    events: list[dict]

@app.post("/investigation/start")
async def start_investigation(request: InvestigationRequest):
    ...
```

### Векторные базы данных и Embeddings

| Библиотека | Версия | Назначение |
|------------|--------|------------|
| **faiss-cpu** | 1.7.4 | Векторный поиск (Facebook AI) |
| **sentence-transformers** | 2.7.0 | Генерация embeddings |
| **transformers** | 4.46.3 | Hugging Face transformers |
| **torch** | 2.4.1 | PyTorch (backend для моделей) |

**FAISS (Facebook AI Similarity Search):**
```python
import faiss
import numpy as np

# Создание индекса
dimension = 384  # размерность embedding
index = faiss.IndexFlatL2(dimension)

# Добавление векторов
vectors = np.array([...], dtype='float32')
index.add(vectors)

# Поиск похожих
query = np.array([...], dtype='float32')
distances, indices = index.search(query, k=5)
```

**Sentence Transformers:**
```python
from sentence_transformers import SentenceTransformer

model = SentenceTransformer('all-MiniLM-L6-v2')
embeddings = model.encode(["Mimikatz credential dumping detected"])
# Output: numpy array shape (1, 384)
```

### Machine Learning

| Библиотека | Версия | Назначение |
|------------|--------|------------|
| **scikit-learn** | 1.3.2 | Классические ML алгоритмы |
| **xgboost** | 2.1.4 | Gradient Boosting |
| **tensorflow** | 2.13.0 | Deep Learning |
| **numpy** | 1.24.3 | Численные вычисления |
| **pandas** | 2.0.3 | Работа с данными |

**Использование в проекте:**
```python
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb

# Классификация событий
clf = RandomForestClassifier(n_estimators=100)
clf.fit(X_train, y_train)

# XGBoost для более сложных задач
model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1
)
```

### Обработка данных

| Библиотека | Версия | Назначение |
|------------|--------|------------|
| **python-evtx** | 0.7.4 | Парсинг Windows Event Logs |
| **lxml** | 6.0.2 | XML парсинг |
| **beautifulsoup4** | 4.14.3 | HTML/XML парсинг |
| **requests** | 2.32.3 | HTTP клиент |
| **httpx** | 0.27.0 | Асинхронный HTTP клиент |

**Парсинг EVTX:**
```python
import Evtx.Evtx as evtx

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        # Парсинг события
```

### Утилиты

| Библиотека | Версия | Назначение |
|------------|--------|------------|
| **python-dotenv** | 1.0.1 | Загрузка .env файлов |
| **pydantic-settings** | 2.5.0 | Конфигурация через env |
| **tqdm** | 4.67.1 | Progress bars |
| **colorama** | 0.4.6 | Цветной вывод в терминал |

## 4.2 Полный список зависимостей (requirements.txt)

```
# === LLM & AI ===
groq==0.33.0                    # Groq API клиент

# === Web Framework ===
fastapi==0.115.0                # Web framework
uvicorn==0.32.0                 # ASGI server
pydantic==2.9.0                 # Data validation
pydantic-settings==2.5.0        # Settings management

# === Vector DB & Embeddings ===
faiss-cpu==1.7.4                # Vector similarity search
sentence-transformers==2.7.0    # Text embeddings
transformers==4.46.3            # Hugging Face
torch==2.4.1                    # PyTorch
tokenizers==0.20.3              # Fast tokenization

# === Machine Learning ===
scikit-learn==1.3.2             # ML algorithms
xgboost==2.1.4                  # Gradient boosting
tensorflow==2.13.0              # Deep learning
numpy==1.24.3                   # Numerical computing
pandas==2.0.3                   # Data manipulation
scipy==1.10.1                   # Scientific computing
joblib==1.4.2                   # Model serialization

# === Data Processing ===
python-evtx==0.7.4              # Windows Event Log parser
lxml==6.0.2                     # XML processing
beautifulsoup4==4.14.3          # HTML/XML parsing

# === HTTP & Networking ===
requests==2.32.3                # HTTP client
httpx==0.27.0                   # Async HTTP client
aiohttp==3.9.0                  # Async HTTP

# === Configuration & Utils ===
python-dotenv==1.0.1            # Environment variables
PyYAML==6.0.3                   # YAML parsing
tqdm==4.67.1                    # Progress bars
colorama==0.4.6                 # Colored output

# === Testing ===
pytest==8.3.0                   # Testing framework
pytest-asyncio==0.24.0          # Async test support

# === Visualization (для Jupyter) ===
matplotlib==3.7.5               # Plotting
seaborn==0.13.2                 # Statistical visualization
```

## 4.3 Конфигурация (.env)

```env
# LLM Configuration
LLM_API_KEY=gsk_xxxxxxxxxxxxx
LLM_ANALYZER_MODEL=llama-3.3-70b-versatile
GROQ_MODEL=llama-3.3-70b-versatile

# Server Configuration
HOST=0.0.0.0
PORT=9000
DEBUG=false

# Vector Store
VECTOR_STORE_PATH=./vector_db
EMBEDDING_MODEL=all-MiniLM-L6-v2

# Memory
MEMORY_PATH=./memory
SHORT_TERM_LIMIT=20
LONG_TERM_LIMIT=1000

# External APIs (опционально)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
```

---

# 5. ОПИСАНИЕ КОМПОНЕНТОВ

## 5.1 ReAct Agent (app/agent/core/agent.py)

**Назначение:** Основной движок агента, реализующий ReAct цикл.

**Ключевые методы:**

```python
class CyberAgent:
    def __init__(self, tool_registry, memory_manager):
        self.tools = tool_registry      # Доступные инструменты
        self.memory = memory_manager    # Система памяти

    def run(self, query: str, session_id: str) -> AgentResponse:
        """
        Основной метод выполнения запроса.

        1. Получает контекст из памяти
        2. Формирует промпт с инструментами
        3. Запускает ReAct цикл (max 8 итераций)
        4. Сохраняет результат в память
        """

    def _call_llm(self, system_prompt, user_prompt) -> str:
        """Вызов LLM через Groq API"""
```

**ReAct цикл:**
```
for step in range(1, MAX_STEPS + 1):
    1. Вызвать LLM с текущим контекстом
    2. Распарсить ответ (Thought/Action/Final Answer)
    3. Если Final Answer → вернуть результат
    4. Если Action → выполнить инструмент
    5. Добавить Observation в контекст
    6. Повторить
```

## 5.2 Tool Registry (app/agent/tools/base.py)

**Назначение:** Регистрация и управление инструментами агента.

```python
@dataclass
class ToolParameter:
    name: str           # Имя параметра
    description: str    # Описание
    type: str          # Тип (string, int, etc.)
    required: bool     # Обязательный?

@dataclass
class ToolResult:
    success: bool      # Успешно?
    output: str        # Текстовый результат
    data: dict         # Структурированные данные
    error: str         # Ошибка (если есть)

class BaseTool(ABC):
    name: str
    description: str
    parameters: List[ToolParameter]

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        """Выполнить инструмент"""

class ToolRegistry:
    def register(self, tool: BaseTool): ...
    def execute(self, tool_name: str, **kwargs) -> ToolResult: ...
    def get_tools_prompt(self) -> str: ...
```

## 5.3 Доступные инструменты

### analyze_event
```python
class AnalyzeEventTool(BaseTool):
    """Глубокий анализ отдельного события безопасности"""

    name = "analyze_event"
    parameters = [
        ToolParameter("event_data", "JSON событие для анализа", required=True)
    ]

    def execute(self, event_data: dict) -> ToolResult:
        # Анализ через LLM
        # Определение подозрительных паттернов
        # Извлечение IoC
```

### classify_event
```python
class ClassifyEventTool(BaseTool):
    """ML-классификация события (нормальное/подозрительное/вредоносное)"""

    def execute(self, event_data: dict) -> ToolResult:
        # Загрузка ML модели
        # Предобработка features
        # Предсказание класса
```

### mitre_lookup
```python
class MitreLookupTool(BaseTool):
    """Поиск информации о технике/тактике в MITRE ATT&CK"""

    parameters = [
        ToolParameter("technique_id", "ID техники (например T1003)")
    ]

    def execute(self, technique_id: str) -> ToolResult:
        # Поиск в локальной базе MITRE
        # Возврат описания, detection, mitigation
```

### search_logs
```python
class SearchLogsTool(BaseTool):
    """Поиск в логах по паттернам"""

    parameters = [
        ToolParameter("query", "Поисковый запрос"),
        ToolParameter("time_range", "Временной диапазон", required=False)
    ]
```

### lookup_ioc
```python
class LookupIocTool(BaseTool):
    """Проверка индикатора компрометации в threat intel"""

    parameters = [
        ToolParameter("ioc_type", "Тип: ip, domain, hash"),
        ToolParameter("ioc_value", "Значение IoC")
    ]

    def execute(self, ioc_type, ioc_value) -> ToolResult:
        # Проверка в VirusTotal/AbuseIPDB
        # Возврат репутации
```

### knowledge_search
```python
class KnowledgeSearchTool(BaseTool):
    """RAG поиск по базе знаний"""

    def execute(self, query: str) -> ToolResult:
        # Векторизация запроса
        # Поиск в FAISS
        # Возврат релевантных документов
```

## 5.4 Memory Manager (app/agent/memory/)

### Архитектура памяти:
```
┌─────────────────────────────────────────────────────┐
│                  Memory Manager                      │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────────┐    ┌──────────────────┐      │
│  │  Short-Term      │    │   Long-Term      │      │
│  │  Memory          │    │   Memory         │      │
│  │                  │    │                  │      │
│  │  - Per session   │    │  - Global        │      │
│  │  - Last N msgs   │    │  - Vector store  │      │
│  │  - Fast access   │    │  - Persistent    │      │
│  └──────────────────┘    └──────────────────┘      │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### Short-Term Memory:
```python
class ShortTermMemory:
    """Краткосрочная память сессии (последние N сообщений)"""

    def __init__(self, max_messages=20):
        self.history = []
        self.max_messages = max_messages

    def add_user_message(self, message: str): ...
    def add_assistant_message(self, message: str): ...
    def get_context_string(self) -> str: ...
```

### Long-Term Memory:
```python
class LongTermMemory:
    """Долгосрочная память (векторное хранилище)"""

    def __init__(self, vector_store_path):
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        self.index = faiss.IndexFlatL2(384)
        self.documents = []

    def store(self, content: str, metadata: dict): ...
    def recall(self, query: str, top_k=5) -> List[str]: ...
    def save(self): ...
    def load(self): ...
```

## 5.5 RAG System (app/agent/rag/)

### Chunker (разбиение документов):
```python
class TextChunker:
    def __init__(self, chunk_size=500, overlap=50):
        self.chunk_size = chunk_size
        self.overlap = overlap

    def chunk(self, text: str) -> List[str]:
        """Разбивает текст на перекрывающиеся фрагменты"""
        chunks = []
        start = 0
        while start < len(text):
            end = start + self.chunk_size
            chunks.append(text[start:end])
            start = end - self.overlap
        return chunks
```

### Embeddings:
```python
class EmbeddingService:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)

    def embed(self, texts: List[str]) -> np.ndarray:
        return self.model.encode(texts, convert_to_numpy=True)

    def embed_query(self, query: str) -> np.ndarray:
        return self.model.encode([query], convert_to_numpy=True)[0]
```

### Vector Store:
```python
class VectorStore:
    def __init__(self, dimension=384):
        self.index = faiss.IndexFlatL2(dimension)
        self.documents = []

    def add(self, embeddings: np.ndarray, documents: List[str]):
        self.index.add(embeddings.astype('float32'))
        self.documents.extend(documents)

    def search(self, query_embedding: np.ndarray, k=5) -> List[Tuple[str, float]]:
        distances, indices = self.index.search(
            query_embedding.reshape(1, -1).astype('float32'),
            k
        )
        return [(self.documents[i], distances[0][j])
                for j, i in enumerate(indices[0])]
```

### Retriever:
```python
class Retriever:
    def __init__(self, embedding_service, vector_store):
        self.embedder = embedding_service
        self.store = vector_store

    def retrieve(self, query: str, top_k=5) -> List[str]:
        query_embedding = self.embedder.embed_query(query)
        results = self.store.search(query_embedding, k=top_k)
        return [doc for doc, _ in results]
```

---

# 6. АЛГОРИТМЫ И МЕТОДЫ

## 6.1 ReAct Algorithm

**Псевдокод:**
```
Algorithm: ReAct Reasoning Loop
Input: query (user question), tools (available tools), max_steps
Output: final_answer

1. context ← get_memory_context(query)
2. history ← []

3. for step = 1 to max_steps do:
4.     prompt ← build_prompt(query, context, history, tools)
5.     response ← call_llm(prompt)
6.     parsed ← parse_response(response)  # {thought, action, action_input, final_answer}
7.
8.     if parsed.final_answer ≠ null then:
9.         return parsed.final_answer
10.
11.    if parsed.action ≠ null then:
12.        observation ← execute_tool(parsed.action, parsed.action_input)
13.        history.append({
14.            thought: parsed.thought,
15.            action: parsed.action,
16.            observation: observation
17.        })
18.    else:
19.        return parsed.thought  # No action, use thought as answer

20. # Max steps reached
21. return synthesize_answer(history)
```

## 6.2 RAG Pipeline

**Индексация (offline):**
```
Algorithm: Document Indexing
Input: documents (list of text files)

1. all_chunks ← []
2. for doc in documents:
3.     text ← read_file(doc)
4.     chunks ← chunker.chunk(text)
5.     all_chunks.extend(chunks)

6. embeddings ← embedding_model.encode(all_chunks)
7. vector_store.add(embeddings, all_chunks)
8. vector_store.save()
```

**Поиск (online):**
```
Algorithm: Semantic Search
Input: query (user question), k (number of results)

1. query_embedding ← embedding_model.encode(query)
2. distances, indices ← vector_store.search(query_embedding, k)
3. relevant_docs ← [documents[i] for i in indices]
4. return relevant_docs
```

## 6.3 Классификация событий (ML)

**Feature Engineering:**
```python
def extract_features(event: dict) -> np.ndarray:
    features = []

    # Категориальные признаки
    features.append(encode_event_type(event.get('event_type')))
    features.append(encode_process_name(event.get('process_name')))

    # Численные признаки
    features.append(event.get('event_id', 0))
    features.append(len(event.get('command_line', '')))

    # Временные признаки
    timestamp = parse_timestamp(event.get('timestamp'))
    features.append(timestamp.hour)
    features.append(timestamp.weekday())

    # Булевы признаки
    features.append(1 if is_admin_process(event) else 0)
    features.append(1 if has_network_connection(event) else 0)

    return np.array(features)
```

**Модель:**
```python
from sklearn.ensemble import RandomForestClassifier

# Обучение
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    class_weight='balanced'
)
model.fit(X_train, y_train)

# Предсказание
prediction = model.predict(X_new)
probability = model.predict_proba(X_new)
```

## 6.4 Timeline Reconstruction

**Алгоритм построения timeline:**
```
Algorithm: Attack Timeline Construction
Input: events (list of security events)
Output: timeline (chronologically ordered attack stages)

1. # Сортировка по времени
2. sorted_events ← sort(events, key=timestamp)

3. # Группировка по хостам
4. hosts ← group_by(sorted_events, key=hostname)

5. # Для каждого хоста определяем стадии атаки
6. timeline ← []
7. for host, host_events in hosts:
8.     for event in host_events:
9.         stage ← classify_attack_stage(event)  # initial_access, execution, etc.
10.        iocs ← extract_iocs(event)
11.        mitre ← map_to_mitre(event)
12.
13.        timeline.append({
14.            timestamp: event.timestamp,
15.            hostname: host,
16.            stage: stage,
17.            description: generate_description(event),
18.            iocs: iocs,
19.            mitre_technique: mitre
20.        })

21. return sort(timeline, key=timestamp)
```

## 6.5 IoC Extraction

**Регулярные выражения для извлечения IoC:**
```python
IOC_PATTERNS = {
    'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
    'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    'md5': r'\b[a-fA-F0-9]{32}\b',
    'sha1': r'\b[a-fA-F0-9]{40}\b',
    'sha256': r'\b[a-fA-F0-9]{64}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'url': r'https?://[^\s<>"{}|\\^`\[\]]+'
}

def extract_iocs(text: str) -> dict:
    iocs = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            iocs[ioc_type] = list(set(matches))
    return iocs
```

---

# 7. API И ИНТЕРФЕЙСЫ

## 7.1 REST API Endpoints

### POST /investigation/start
**Начать расследование инцидента**

Request:
```json
{
    "incident_id": "INC-2024-001",
    "events": [
        {
            "timestamp": "2024-01-15T08:37:00Z",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "mimikatz.exe",
            "user": "john.doe"
        }
    ]
}
```

Response:
```json
{
    "status": "completed",
    "incident_id": "INC-2024-001",
    "investigation_time_seconds": 45.2,
    "report_available": true
}
```

### GET /investigation/{id}/report
**Получить отчёт о расследовании**

Response:
```json
{
    "incident_id": "INC-2024-001",
    "incident_type": "CREDENTIAL_THEFT",
    "title": "Credential Dumping Attack",
    "executive_summary": "...",
    "timeline": [...],
    "iocs": [...],
    "ttp_analysis": {
        "tactics": ["credential_access"],
        "techniques": [{"id": "T1003", "name": "OS Credential Dumping"}]
    },
    "remediation_steps": [...]
}
```

### POST /agent/query
**Интерактивный запрос к агенту**

Request:
```json
{
    "query": "Что такое техника T1003?",
    "session_id": "session-123"
}
```

Response:
```json
{
    "answer": "T1003 - OS Credential Dumping...",
    "steps": [
        {
            "thought": "Нужно найти информацию о T1003",
            "action": "mitre_lookup",
            "observation": "T1003 описывает..."
        }
    ],
    "tools_used": ["mitre_lookup"],
    "session_id": "session-123"
}
```

### GET /health
**Проверка состояния сервиса**

Response:
```json
{
    "status": "healthy",
    "version": "1.0.0",
    "llm_available": true,
    "vector_store_loaded": true,
    "active_sessions": 5
}
```

## 7.2 Pydantic Schemas

```python
from pydantic import BaseModel
from typing import List, Optional
from enum import Enum

class IncidentType(str, Enum):
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_BREACH = "data_breach"

class SecurityEvent(BaseModel):
    timestamp: str
    hostname: str
    event_type: str
    process_name: Optional[str] = None
    user: Optional[str] = None
    command_line: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

class InvestigationRequest(BaseModel):
    incident_id: str
    events: List[SecurityEvent]

class TimelineEvent(BaseModel):
    timestamp: str
    hostname: str
    event_type: str
    description: str
    severity: str
    iocs: List[str]
    mitre_technique: Optional[str]

class IoC(BaseModel):
    type: str  # ip, domain, hash, etc.
    value: str
    confidence: float
    context: str

class TTPAnalysis(BaseModel):
    tactics: List[str]
    techniques: List[dict]
    procedures: List[str]
    sophistication_level: str

class InvestigationReport(BaseModel):
    incident_id: str
    incident_type: IncidentType
    title: str
    executive_summary: str
    timeline: List[TimelineEvent]
    iocs: List[IoC]
    ttp_analysis: TTPAnalysis
    root_cause: str
    affected_systems: List[str]
    remediation_steps: List[str]

class AgentStep(BaseModel):
    step_number: int
    thought: str
    action: Optional[str]
    action_input: Optional[dict]
    observation: Optional[str]
    is_final: bool

class AgentResponse(BaseModel):
    answer: str
    steps: List[AgentStep]
    tools_used: List[str]
    total_steps: int
    session_id: str
```

---

# 8. РЕЗУЛЬТАТЫ И МЕТРИКИ

## 8.1 Метрики качества агента

### Accuracy метрики:

| Метрика | Описание | Целевое значение |
|---------|----------|------------------|
| **Classification Accuracy** | Точность определения типа инцидента | > 85% |
| **IoC Extraction Recall** | Полнота извлечения IoC | > 90% |
| **MITRE Mapping Accuracy** | Точность маппинга на техники | > 80% |
| **Timeline Correctness** | Корректность хронологии | > 95% |

### Operational метрики:

| Метрика | Описание | Целевое значение |
|---------|----------|------------------|
| **MTTD** | Mean Time To Detect | < 5 минут |
| **MTTR** | Mean Time To Respond (отчёт) | < 2 минуты |
| **Steps per Investigation** | Среднее число шагов агента | 4-6 |
| **Tool Usage Rate** | Использование инструментов | > 80% запросов |

### Performance метрики:

| Метрика | Описание | Целевое значение |
|---------|----------|------------------|
| **Latency** | Время ответа агента | < 30 сек |
| **Throughput** | Расследований в час | > 20 |
| **LLM Calls** | Вызовов LLM на расследование | < 10 |
| **Memory Usage** | Потребление RAM | < 4 GB |

## 8.2 Тестовые сценарии

### Сценарий 1: Ransomware Attack
```
Input: 9 событий (logon, process creation, network, file encryption)
Expected Output:
- Type: RANSOMWARE
- Timeline: 9 событий в хронологическом порядке
- IoCs: IP (C2), hash (malware), file paths
- MITRE: T1566, T1486, T1490
- Remediation: isolate, block, restore
```

### Сценарий 2: Credential Theft
```
Input: 5 событий (mimikatz, lsass access)
Expected Output:
- Type: CREDENTIAL_THEFT
- MITRE: T1003.001 (LSASS Memory)
- IoCs: process names, hashes
```

### Сценарий 3: Lateral Movement
```
Input: 12 событий (multiple hosts, RDP, PsExec)
Expected Output:
- Type: LATERAL_MOVEMENT
- Affected systems: 4 hosts
- MITRE: T1021.001 (RDP), T1021.002 (SMB)
```

## 8.3 Сравнение с baseline

| Аспект | Manual Analysis | Rule-based SIEM | Our Agent |
|--------|-----------------|-----------------|-----------|
| Время анализа | 2-4 часа | 5-10 минут | 1-2 минуты |
| IoC Extraction | Manual | Predefined patterns | ML + LLM |
| MITRE Mapping | Expert knowledge | Static rules | Semantic search |
| False Positives | Low | High | Medium |
| Scalability | Limited | Good | Good |
| Novel Attacks | Yes | No | Partially |

---

# 9. ГЛОССАРИЙ ТЕРМИНОВ

## Кибербезопасность

| Термин | Определение |
|--------|-------------|
| **SOC** | Security Operations Center - центр мониторинга безопасности |
| **SIEM** | Security Information and Event Management - система сбора и анализа логов |
| **SOAR** | Security Orchestration, Automation and Response - автоматизация реагирования |
| **IoC** | Indicator of Compromise - индикатор компрометации (IP, hash, domain) |
| **TTP** | Tactics, Techniques, Procedures - тактики, техники и процедуры атакующих |
| **MITRE ATT&CK** | База знаний о тактиках и техниках кибератак |
| **APT** | Advanced Persistent Threat - целевая продолжительная атака |
| **EDR** | Endpoint Detection and Response - защита конечных точек |
| **MTTD** | Mean Time To Detect - среднее время обнаружения |
| **MTTR** | Mean Time To Respond - среднее время реагирования |
| **Lateral Movement** | Горизонтальное перемещение по сети |
| **C2/C&C** | Command and Control - сервер управления вредоносом |
| **Forensics** | Цифровая криминалистика |

## Искусственный интеллект

| Термин | Определение |
|--------|-------------|
| **LLM** | Large Language Model - большая языковая модель |
| **RAG** | Retrieval-Augmented Generation - генерация с извлечением контекста |
| **ReAct** | Reasoning + Acting - парадигма рассуждения и действия |
| **CoT** | Chain-of-Thought - цепочка рассуждений |
| **Embedding** | Векторное представление текста |
| **Vector Store** | Векторная база данных для семантического поиска |
| **Fine-tuning** | Дообучение модели на специфичных данных |
| **Prompt Engineering** | Разработка эффективных промптов |
| **Tokenization** | Разбиение текста на токены |
| **Hallucination** | Галлюцинация LLM - генерация несуществующих фактов |
| **Temperature** | Параметр "креативности" LLM (0 = детерминированно) |
| **Context Window** | Максимальный размер контекста модели |

## Технические термины

| Термин | Определение |
|--------|-------------|
| **API** | Application Programming Interface |
| **REST** | Representational State Transfer - архитектурный стиль API |
| **ASGI** | Asynchronous Server Gateway Interface |
| **Async/Await** | Асинхронное программирование в Python |
| **Pydantic** | Библиотека валидации данных через типы |
| **FAISS** | Facebook AI Similarity Search - библиотека векторного поиска |
| **Transformer** | Архитектура нейросети (основа LLM) |
| **Attention** | Механизм внимания в трансформерах |

---

# 10. ВОПРОСЫ ДЛЯ ЗАЩИТЫ

## Базовые вопросы

**Q1: Что такое ИИ-агент и чем он отличается от обычного LLM?**
> ИИ-агент - автономная система, способная воспринимать окружение, принимать решения и выполнять действия. В отличие от LLM, агент имеет доступ к инструментам, долгосрочную память и может самостоятельно планировать последовательность действий для достижения цели.

**Q2: Почему выбрана архитектура ReAct?**
> ReAct объединяет рассуждение (Reasoning) и действие (Acting) в единый цикл. Это обеспечивает:
> - Прозрачность решений (explainability)
> - Возможность использовать внешние инструменты
> - Итеративное уточнение через наблюдения
> - Лучшую производительность на задачах, требующих планирования

**Q3: Что такое RAG и зачем он нужен?**
> RAG (Retrieval-Augmented Generation) - метод дополнения LLM внешними знаниями. Нужен потому что:
> - LLM не знает специфику организации
> - Знания LLM устаревают (cutoff date)
> - Уменьшает галлюцинации
> - Позволяет работать с приватными данными без fine-tuning

**Q4: Как работает система памяти агента?**
> Двухуровневая архитектура:
> - **Short-term memory**: последние N сообщений сессии, быстрый доступ
> - **Long-term memory**: векторное хранилище, семантический поиск, персистентность
>
> При каждом запросе агент получает контекст из обоих источников.

**Q5: Какие инструменты доступны агенту?**
> - `analyze_event` - глубокий анализ события
> - `classify_event` - ML-классификация
> - `mitre_lookup` - поиск в MITRE ATT&CK
> - `search_logs` - поиск в логах
> - `lookup_ioc` - проверка IoC в threat intel
> - `knowledge_search` - RAG поиск по базе знаний

## Технические вопросы

**Q6: Почему используется Groq вместо OpenAI?**
> - Скорость: ~500 tokens/sec (в 10x быстрее)
> - Бесплатный tier для разработки
> - Поддержка открытых моделей (LLaMA 3.3 70B)
> - Приватность: данные не используются для обучения

**Q7: Как реализован векторный поиск?**
> Используется FAISS (Facebook AI Similarity Search):
> 1. Текст разбивается на chunks (500 символов с overlap 50)
> 2. Каждый chunk векторизуется через sentence-transformers
> 3. Векторы индексируются в FAISS (IndexFlatL2)
> 4. При поиске: запрос векторизуется → ищутся k ближайших соседей → возвращаются документы

**Q8: Как агент определяет тип инцидента?**
> Комбинация методов:
> 1. ML-классификатор (RandomForest/XGBoost) на features событий
> 2. LLM-анализ с примерами (few-shot)
> 3. Маппинг на MITRE ATT&CK через семантический поиск

**Q9: Как обрабатываются Windows Event Logs?**
> 1. Парсинг EVTX через библиотеку python-evtx
> 2. Извлечение XML структуры события
> 3. Нормализация в единый JSON формат
> 4. Feature engineering для ML
> 5. Анализ через агента

**Q10: Как ограничивается число шагов агента?**
> - MAX_STEPS = 8 (hardcoded limit)
> - Агент может завершить раньше через "Final Answer"
> - При достижении лимита - принудительный синтез ответа из накопленных observations

## Вопросы по кибербезопасности

**Q11: Что такое MITRE ATT&CK?**
> База знаний о тактиках, техниках и процедурах атакующих:
> - 14 тактик (Initial Access, Execution, Persistence, etc.)
> - 200+ техник с уникальными ID (T1003, T1566, etc.)
> - Описания, примеры детекции, митигации
> - Обновляется сообществом

**Q12: Как извлекаются IoC из событий?**
> 1. Регулярные выражения для известных паттернов (IP, hash, domain, URL)
> 2. Контекстный анализ через LLM
> 3. Валидация формата (checksum для хешей, RFC для IP)
> 4. Дедупликация

**Q13: Какие типы инцидентов поддерживаются?**
> - Malware
> - Ransomware
> - Credential Theft
> - Lateral Movement
> - Data Breach
> - APT
> - Phishing
> - Insider Threat

**Q14: Как строится timeline атаки?**
> 1. Сортировка событий по timestamp
> 2. Группировка по hostname
> 3. Определение стадии атаки для каждого события
> 4. Маппинг на MITRE technique
> 5. Извлечение IoC
> 6. Генерация описания через LLM

## Вопросы на понимание

**Q15: В чём преимущество агента перед rule-based системой?**
> | Rule-based | Agent |
> |------------|-------|
> | Только известные паттерны | Понимает контекст |
> | Много false positives | Адаптивный анализ |
> | Требует постоянного обновления правил | Использует LLM + RAG |
> | Не объясняет решения | Прозрачные рассуждения |

**Q16: Как агент обучается/улучшается?**
> В текущей версии - не обучается в процессе работы. Улучшения через:
> - Обновление базы знаний (RAG)
> - Улучшение промптов
> - Дообучение ML-классификаторов на новых данных
> - Fine-tuning LLM (будущее развитие)

**Q17: Как обеспечивается безопасность самого агента?**
> - API аутентификация (API keys)
> - Валидация входных данных (Pydantic)
> - Ограничение rate limit на LLM вызовы
> - Логирование всех действий
> - Нет прямого выполнения shell команд

**Q18: Какие ограничения у системы?**
> - Зависимость от качества входных данных
> - Latency из-за LLM вызовов
> - Стоимость API при больших объёмах
> - Возможны галлюцинации LLM
> - Не заменяет эксперта полностью

## Вопросы о развитии

**Q19: Как можно улучшить систему?**
> 1. Multi-agent архитектура (специализированные агенты)
> 2. Self-reflection модуль (оценка своих решений)
> 3. Fine-tuning на domain-specific данных
> 4. Интеграция с реальными SIEM/EDR
> 5. Автоматическое выполнение remediation actions
> 6. A/B тестирование промптов

**Q20: Какие метрики используются для оценки?**
> - Classification Accuracy (тип инцидента)
> - IoC Extraction Recall
> - MITRE Mapping Accuracy
> - MTTD/MTTR
> - Latency и Throughput
> - Количество шагов агента

---

# ПРИЛОЖЕНИЯ

## A. Запуск проекта

```bash
# 1. Клонирование
git clone <repository>
cd PythonProject2

# 2. Виртуальное окружение
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# 3. Установка зависимостей
pip install -r requirements.txt

# 4. Конфигурация
cp .env.example .env
# Добавить LLM_API_KEY

# 5. Запуск
python app/main.py

# 6. Тестирование
curl -X POST http://localhost:9000/investigation/example
```

## B. Пример расследования

```python
import asyncio
from cyber_incident_investigator import CyberIncidentInvestigator

async def main():
    investigator = CyberIncidentInvestigator()

    events = [
        {
            "timestamp": "2024-01-15T08:37:00Z",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "mimikatz.exe"
        }
    ]

    incident_id = await investigator.start_investigation("INC-001", events)
    report = investigator.get_investigation_report(incident_id)
    print(report)

asyncio.run(main())
```

## C. Полезные команды

```bash
# Запуск тестов
pytest tests/ -v

# Проверка типов
mypy app/

# Форматирование
black app/
ruff check app/

# Документация API
# Откройте http://localhost:9000/docs
```

---

**Дата создания документации:** 2024
**Версия:** 1.0
**Автор:** [Ваше имя]

---

*Документация подготовлена для защиты дипломного проекта*
