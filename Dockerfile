FROM python:3.11-slim AS base

WORKDIR /app

# ── Системные зависимости ─────────────────────────────────────────────────────
# build-essential нужен для компиляции C-расширений (faiss-cpu, scipy и др.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

# ── Python-зависимости (отдельный слой — кешируется при изменении кода) ───────
COPY requirements.txt .

# Устанавливаем torch CPU-only (без CUDA экономим ~1.5 ГБ в образе).
# Остальные зависимости ставим из requirements.txt без строки torch.
RUN grep -v "^torch" requirements.txt > /tmp/requirements_no_torch.txt && \
    pip install --no-cache-dir torch==2.12.0 --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r /tmp/requirements_no_torch.txt

# ── Код приложения ────────────────────────────────────────────────────────────
# FIX: cyber_incident_investigator.py обязателен — без него FastAPI не стартует
COPY cyber_incident_investigator.py .
COPY app/ app/
COPY models/ models/
COPY vector_db/ vector_db/
COPY knowledge_base/ knowledge_base/

# ── Непривилегированный пользователь ──────────────────────────────────────────
# FIX: создаём /app/data с правами agent для SQLite-базы данных.
# Без этого пользователь agent не мог создать ir_agent.db в /app (нет прав на запись).
RUN useradd --create-home agent && \
    mkdir -p /app/data && \
    chown -R agent:agent /app/data
USER agent

# Путь к SQLite-файлу внутри контейнера (записываемая папка /app/data)
ENV DATABASE_URL=sqlite+aiosqlite:////app/data/ir_agent.db

EXPOSE 9000

# Healthcheck: проверяем /health/live каждые 30 секунд
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; r=httpx.get('http://localhost:9000/health/live'); r.raise_for_status()"

# Один worker: ML-модели и incident-синглтоны хранятся in-memory.
# Для масштабирования используй docker-compose --scale или Kubernetes replicas.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000", "--workers", "1"]
