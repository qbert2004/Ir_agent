# Changelog

## [1.0.0] — 2024

### Added

#### Ядро системы
- FastAPI-приложение с middleware-стеком (AuthMiddleware, RateLimit, RequestID, Logging)
- 42 REST-эндпоинта через 8 роутеров (ingest, agent, assessment, ml, report, investigation, health, dashboard)
- Async SQLAlchemy + Alembic миграции (SQLite dev / PostgreSQL prod)

#### ML-подсистема
- GradientBoosting-классификатор v1 → v2 (honest) → **v3 production** (source-stratified split)
- 41 feature engineering группа (event_id one-hot, keyword density, process signals, MITRE indicators)
- SMOTE-оверсэмплинг для балансировки классов
- Platt scaling (CalibratedClassifierCV) для калиброванных вероятностей
- Drift detector (Kolmogorov-Smirnov тест для мониторинга дрейфа признаков)
- ML validation pipeline: `scripts/validate_ml_model.py`, `scripts/strict_audit.py`

#### ThreatAssessment Engine
- Байесовски-вдохновленное взвешенное слияние 4 сигналов: ML(35%) + IoC(30%) + MITRE(20%) + Agent(15%)
- 7 правил арбитража (hard overrides): CRITICAL-эскалация, FALSE_POSITIVE-понижение
- Трассировка объяснений (explanation_trace) для аудита каждого решения

#### CyberAgent (ReAct LLM)
- ReAct-цикл до 8 шагов с таймаутом (asyncio.TimeoutError)
- 9 инструментов: analyze_event, classify_event, lookup_ioc, investigate, ml_classify, extract_mitre, search_logs, get_knowledge, estimate_timeline
- Потоковый вывод шагов рассуждений (NDJSON)
- RAG-подсистема: FAISS vector store, sentence-transformers embeddings, LRU-кэш сессий

#### Интерфейсы
- CLI (`cli.py`): Click с Rich-форматированием, интерактивный REPL-режим
- TUI (`tui.py`): Textual, 8 вкладок (Status, Query, Tools, Metrics, IoC, MITRE, Investigate, Assess)
- HTML-дашборд (`/dashboard`): single-page с live-данными

#### Инфраструктура
- Docker + docker-compose (PostgreSQL + IR-Agent, non-root пользователь, healthcheck)
- GitHub Actions CI: ruff lint, pytest, Docker build + smoke test
- Prometheus `/metrics`, Better Stack log shipping
- Bearer token auth, rate limiting (Redis или in-memory), CORS

### ML Model Evolution (История версий модели)

| Версия | Файл | Accuracy (lab) | Est. Production | Проблема |
|--------|------|:-:|:-:|---------|
| v1 (original) | `gradient_boosting_model.pkl` | 99.78% | ~55-65% | Критическая утечка: `cmdline_length_norm` = 99.56% важности |
| v2 (honest) | `gradient_boosting_honest.pkl` | 98.81% | ~70-80% | Случайное разбиение из одного пула — частичная утечка |
| **v3 (production)** | `gradient_boosting_production.pkl` | **98.58%** | **~78-88%** | Source-stratified split: обучение на evtx+synthetic, валидация на реальных APT-записях |
