FROM python:3.11-slim AS base

WORKDIR /app

# System deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

# Python deps (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY app/ app/
COPY models/ models/
COPY vector_db/ vector_db/
COPY knowledge_base/ knowledge_base/

# Non-root user
RUN useradd --create-home agent
USER agent

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; r=httpx.get('http://localhost:9000/health/live'); r.raise_for_status()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000", "--workers", "2"]
