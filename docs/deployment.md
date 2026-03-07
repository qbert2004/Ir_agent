# IR-Agent — Production Deployment Guide

## Table of Contents

1. [Pre-deployment Checklist](#pre-deployment-checklist)
2. [Docker Compose (Recommended)](#docker-compose-recommended)
3. [Bare-metal / VM](#bare-metal--vm)
4. [Kubernetes (Helm-style)](#kubernetes)
5. [Environment Variables Reference](#environment-variables-reference)
6. [Database Setup](#database-setup)
7. [Security Hardening](#security-hardening)
8. [Observability](#observability)
9. [Scaling](#scaling)
10. [Backup and Recovery](#backup-and-recovery)
11. [Common Issues](#common-issues)

---

## Pre-deployment Checklist

Before going to production, verify every item below:

### Security
- [ ] `MY_API_TOKEN` set to a random 32+ character string
- [ ] `ENVIRONMENT=production` (disables `/docs`, `/redoc`, `/ai/test`, `/ai/stream`)
- [ ] `CORS_ORIGINS` restricted to your actual frontend domains
- [ ] TLS termination at reverse proxy (nginx / Caddy / AWS ALB)
- [ ] Firewall: port 9000 NOT exposed to internet (only reverse proxy)
- [ ] Database password changed from `changeme_in_production`
- [ ] API keys (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) stored in secrets manager, not `.env` file in VCS

### Functionality
- [ ] `LLM_API_KEY` (Groq) or `OPENAI_API_KEY` or `OLLAMA_BASE_URL` set
- [ ] `DATABASE_URL` pointing to PostgreSQL (not SQLite)
- [ ] `alembic upgrade head` run against production database
- [ ] `GET /health/ready` returns `{"status":"ready"}`
- [ ] ML model artifacts present in `models/` directory
- [ ] FAISS vector index present in `vector_db/`

### Observability
- [ ] `BETTER_STACK_SOURCE_TOKEN` set for centralized logging
- [ ] Prometheus scrape job configured for `/metrics`
- [ ] Health checks configured in orchestrator (liveness: `/health/live`, readiness: `/health/ready`)

### Scaling
- [ ] `REDIS_URL` set if running >1 instance (required for shared rate-limiting)
- [ ] Sessions are in-memory per-instance — acceptable for independent replicas

---

## Docker Compose (Recommended)

### 1. Prepare environment file

```bash
cp .env.example .env
```

Edit `.env` with production values:

```env
ENVIRONMENT=production

# LLM (required)
LLM_PROVIDER=groq
LLM_API_KEY=gsk_...

# Auth (required in production)
MY_API_TOKEN=your-random-32-char-token-here

# Database (docker-compose injects DATABASE_URL automatically)
POSTGRES_PASSWORD=strong-random-password

# IoC threat intelligence
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...

# Logging
BETTER_STACK_SOURCE_TOKEN=...

# CORS (your actual frontend URL)
CORS_ORIGINS=https://yourdomain.com

# Redis (distributed rate-limiting)
REDIS_URL=redis://redis:6379/0
```

### 2. Start services

```bash
docker-compose up -d
```

This starts:
- **postgres** — PostgreSQL 16 with `ir_agent` database
- **ir-agent** — The FastAPI application on port 9000

### 3. Run migrations

```bash
docker-compose exec ir-agent alembic upgrade head
```

### 4. Verify

```bash
curl http://localhost:9000/health/live
# {"status":"alive"}

curl http://localhost:9000/health/ready
# {"status":"ready","components":{"database":true,"ml_model":true,...}}
```

### 5. Add Redis (optional but recommended for multi-instance)

Add to `docker-compose.yml`:

```yaml
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis_data:/data

volumes:
  redis_data:
```

And set `REDIS_URL=redis://redis:6379/0` in `.env`.

---

## Bare-metal / VM

### System requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 4 GB (ML model + FAISS index) |
| Disk | 5 GB | 20 GB |
| Python | 3.11 | 3.11 or 3.12 |

### Install

```bash
# Create dedicated user
useradd --create-home --shell /bin/bash iragent

# Install dependencies
apt-get update && apt-get install -y python3.11 python3.11-venv postgresql-client

# Clone repo
git clone <repo-url> /opt/ir-agent
cd /opt/ir-agent

# Virtual environment
python3.11 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with production values

# Migrations
alembic upgrade head
```

### Systemd service

Create `/etc/systemd/system/ir-agent.service`:

```ini
[Unit]
Description=IR-Agent Cyber Incident Response API
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=iragent
WorkingDirectory=/opt/ir-agent
EnvironmentFile=/opt/ir-agent/.env
ExecStart=/opt/ir-agent/.venv/bin/uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 9000 \
  --workers 1 \
  --log-level info
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/ir-agent/vector_db /opt/ir-agent/models /opt/ir-agent/ir_agent.db

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable ir-agent
systemctl start ir-agent
systemctl status ir-agent
```

### nginx reverse proxy

```nginx
upstream ir_agent {
    server 127.0.0.1:9000;
}

server {
    listen 443 ssl http2;
    server_name ir-agent.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/ir-agent.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ir-agent.yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;

    # Request size limit (block oversized payloads)
    client_max_body_size 10m;

    location / {
        proxy_pass         http://ir_agent;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Streaming support (agent/query/stream)
        proxy_buffering    off;
        proxy_read_timeout 300s;
    }
}

server {
    listen 80;
    server_name ir-agent.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

---

## Kubernetes

### ConfigMap + Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ir-agent-secrets
type: Opaque
stringData:
  LLM_API_KEY: "gsk_..."
  MY_API_TOKEN: "your-api-token"
  POSTGRES_PASSWORD: "strong-password"
  VIRUSTOTAL_API_KEY: "..."
  ABUSEIPDB_API_KEY: "..."
  BETTER_STACK_SOURCE_TOKEN: "..."
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ir-agent-config
data:
  ENVIRONMENT: "production"
  LLM_PROVIDER: "groq"
  LLM_ANALYZER_MODEL: "llama-3.3-70b-versatile"
  DATABASE_URL: "postgresql+asyncpg://ir_agent:$(POSTGRES_PASSWORD)@postgres:5432/ir_agent"
  REDIS_URL: "redis://redis:6379/0"
  API_PORT: "9000"
  RATE_LIMIT_PER_MINUTE: "60"
  CORS_ORIGINS: "https://yourdomain.com"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ir-agent
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ir-agent
  template:
    metadata:
      labels:
        app: ir-agent
    spec:
      containers:
        - name: ir-agent
          image: ir-agent:latest
          ports:
            - containerPort: 9000
          envFrom:
            - configMapRef:
                name: ir-agent-config
            - secretRef:
                name: ir-agent-secrets
          livenessProbe:
            httpGet:
              path: /health/live
              port: 9000
            initialDelaySeconds: 30
            periodSeconds: 30
            timeoutSeconds: 5
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 9000
            initialDelaySeconds: 40
            periodSeconds: 10
            timeoutSeconds: 5
          resources:
            requests:
              memory: "1Gi"
              cpu: "500m"
            limits:
              memory: "3Gi"
              cpu: "2000m"
          volumeMounts:
            - name: vector-db
              mountPath: /app/vector_db
            - name: models
              mountPath: /app/models
      volumes:
        - name: vector-db
          persistentVolumeClaim:
            claimName: ir-agent-vectordb
        - name: models
          persistentVolumeClaim:
            claimName: ir-agent-models
```

---

## Environment Variables Reference

### Required in Production

| Variable | Description |
|---|---|
| `MY_API_TOKEN` | Bearer token for all authenticated endpoints. Generate with: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ENVIRONMENT` | Set to `production`. Disables Swagger UI and debug endpoints |
| `DATABASE_URL` | PostgreSQL connection string: `postgresql+asyncpg://user:pass@host:5432/db` |
| `LLM_API_KEY` | Groq API key — required for LLM features (agent, report generation) |

### LLM Configuration

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `groq` | Primary provider (`groq`, `openai`, `ollama`) |
| `LLM_API_KEY` | — | Groq API key |
| `OPENAI_API_KEY` | — | OpenAI fallback (used if Groq key absent) |
| `OLLAMA_BASE_URL` | — | Ollama local endpoint (e.g., `http://localhost:11434`) |
| `LLM_ANALYZER_MODEL` | `llama-3.3-70b-versatile` | Model for event analysis and agent reasoning |
| `LLM_REPORT_MODEL` | `llama-3.3-70b-versatile` | Model for report generation |
| `AGENT_TIMEOUT_SECONDS` | `120` | Max wall-clock time per agent call before 504 |

### Security

| Variable | Default | Description |
|---|---|---|
| `MY_API_TOKEN` | — | Auth token; leave empty only for local dev |
| `CORS_ORIGINS` | `http://localhost:3000,...` | Comma-separated allowed origins |
| `RATE_LIMIT_PER_MINUTE` | `60` | Requests/minute per IP |
| `REDIS_URL` | — | Redis for distributed rate-limiting in multi-instance deployments |

### Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./ir_agent.db` | DB connection string |
| `POSTGRES_PASSWORD` | `changeme_in_production` | PostgreSQL password (docker-compose) |

### Threat Intelligence

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | — | VirusTotal lookups (free: 4 req/min, 500/day) |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB lookups (free: 1000/day) |
| `IOC_CACHE_TTL_SECONDS` | `3600` | IoC cache TTL in seconds |
| `IOC_CACHE_MAX_SIZE` | `10000` | Max IoC cache entries (LRU eviction) |

### Observability

| Variable | Default | Description |
|---|---|---|
| `BETTER_STACK_SOURCE_TOKEN` | — | Better Stack log shipping |
| `SEND_ALL_TO_BETTERSTACK` | `true` | Forward all events, not just suspicious ones |

### Agent Memory

| Variable | Default | Description |
|---|---|---|
| `AGENT_SESSION_MAX_SIZE` | `1000` | Max concurrent in-memory sessions (LRU) |
| `AGENT_SESSION_TTL_SECONDS` | `3600` | Session inactivity timeout |
| `AI_SUSPICIOUS_THRESHOLD` | `60` | ML score threshold for triggering deep analysis |

---

## Database Setup

### SQLite (Development only)

No setup needed. The file `ir_agent.db` is created automatically.

```bash
alembic upgrade head
```

### PostgreSQL (Production)

```bash
# Create database and user
psql -U postgres <<EOF
CREATE USER ir_agent WITH PASSWORD 'strong-password';
CREATE DATABASE ir_agent OWNER ir_agent;
GRANT ALL PRIVILEGES ON DATABASE ir_agent TO ir_agent;
EOF

# Set DATABASE_URL in .env
DATABASE_URL=postgresql+asyncpg://ir_agent:strong-password@localhost:5432/ir_agent

# Run migrations
alembic upgrade head
```

### Migrations workflow

```bash
# Check current migration state
alembic current

# Apply all pending migrations
alembic upgrade head

# Roll back one step
alembic downgrade -1

# View migration history
alembic history

# Generate new migration (after model changes)
alembic revision --autogenerate -m "describe_change"
```

---

## Security Hardening

### Token generation

```bash
python -c "import secrets; print(secrets.token_hex(32))"
# Use the output as MY_API_TOKEN
```

### API authentication

All non-public endpoints require:
```
Authorization: Bearer <MY_API_TOKEN>
```

Public endpoints (no auth required):
- `GET /` — root redirect
- `GET /health` — health check
- `GET /health/live` — liveness probe
- `GET /health/ready` — readiness probe

### Rate limiting

Default: 60 requests/minute per IP (sliding window).

- **Single instance**: in-memory rate limiter (automatically used when no `REDIS_URL`)
- **Multi-instance**: set `REDIS_URL` for shared rate-limiting across replicas

### Known security gaps (to address in next iteration)

1. **Timing-safe token comparison**: Current `AuthMiddleware` uses `==` for token comparison. Replace with `hmac.compare_digest()` to prevent timing attacks.
2. **Per-client API keys**: Current implementation is single-token. For multi-tenant deployments, implement key-per-client with usage tracking.
3. **Request size limits**: Add `client_max_body_size` at nginx level (shown above). Application-level limit is not yet implemented.
4. **Secrets management**: Prefer HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets over `.env` files in production.

---

## Observability

### Prometheus metrics

IR-Agent exposes Prometheus-format metrics at `GET /metrics`:

```
ir_agent_events_total               # Total events processed
ir_agent_benign_filtered_total      # Benign events discarded
ir_agent_malicious_detected_total   # Malicious events detected
ir_agent_agent_invocations_total    # Deep-path agent calls
ir_agent_fast_path_total            # Fast-path event count
ir_agent_deep_path_total            # Deep-path event count
ir_agent_betterstack_sent_total     # Events forwarded to Better Stack
```

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: ir-agent
    static_configs:
      - targets: ['ir-agent:9000']
    bearer_token: '<MY_API_TOKEN>'
```

### Better Stack logging

Set `BETTER_STACK_SOURCE_TOKEN` to enable structured log forwarding. All `uvicorn`, `fastapi`, and `ir-agent` logger events are shipped.

### Health probes

| Endpoint | Purpose | Expected response |
|---|---|---|
| `GET /health/live` | Liveness (is the process alive?) | `200 {"status":"alive"}` |
| `GET /health/ready` | Readiness (can it accept traffic?) | `200 {"status":"ready"}` or `503` |
| `GET /health/ml` | ML pipeline status and drift | `200` with model stats |
| `GET /health` | Full component status | `200` with component map |

---

## Scaling

### Single instance (default)

One `uvicorn` worker with in-memory ML singleton and FAISS index. Suitable for up to ~100 req/s.

### Horizontal scaling

Each replica is independent — no shared in-memory state between processes. Scale with:

```bash
# Docker Compose
docker-compose up -d --scale ir-agent=3

# Add a load balancer (nginx upstream / AWS ALB)
```

**Requirements for horizontal scaling:**
- `REDIS_URL` — shared rate-limiting across instances
- Shared `vector_db/` and `models/` volumes (PVC in Kubernetes, EFS on AWS, NFS otherwise)
- Sessions are per-instance; if session continuity is required, use sticky sessions at the load balancer

### Vertical scaling (ML performance)

The GradientBoosting ML classifier and FAISS index are loaded once per process at startup. Increase RAM to accommodate larger FAISS indices.

---

## Backup and Recovery

### What to back up

| Path | Description | Frequency |
|---|---|---|
| PostgreSQL database | All incidents, reports, events | Daily (pg_dump) |
| `vector_db/` | FAISS knowledge-base index | After each knowledge update |
| `models/` | Trained ML model artifacts | After each model retrain |
| `.env` | Configuration (store in secrets manager) | On every change |

### Database backup

```bash
# Backup
pg_dump -U ir_agent -h localhost ir_agent | gzip > ir_agent_$(date +%Y%m%d).sql.gz

# Restore
gunzip < ir_agent_20260305.sql.gz | psql -U ir_agent -h localhost ir_agent
```

---

## Common Issues

### Server starts but `/health/ready` returns 503

**Cause**: Database not initialized.
```bash
alembic upgrade head
```

### `Agent error: ConnectError` on Python 3.14+

**Cause**: `httpx.AsyncClient` + anyio incompatibility on Python 3.14.
**Fix**: Already handled in TUI and CLI via sync `httpx.Client` in thread workers. For the server itself, use Python 3.11 or 3.12.

### `Rate limiter: in-memory backend` warning on startup

**Info**: Normal for single-instance deployments. Set `REDIS_URL` only if running multiple instances.

### `CyberAgent init failed` on startup

**Cause**: Missing FAISS index or model files.
```bash
ls vector_db/    # Should contain .faiss and .pkl files
ls models/       # Should contain .pkl model files
```

### High memory usage

The FAISS index and ML model are loaded into RAM once at startup. Expected baseline: ~800 MB. If RSS exceeds 2 GB, check for event processing backlogs.

### Groq rate limit errors (`429 Too Many Requests`)

Groq free tier: 30 requests/minute. Options:
1. Upgrade to paid Groq plan
2. Switch to `OPENAI_API_KEY` fallback
3. Reduce `AI_SUSPICIOUS_THRESHOLD` to send fewer events to deep-path

### Database connection pool exhausted

Default SQLAlchemy pool: 5 connections. Under high load, increase:

```env
DATABASE_URL=postgresql+asyncpg://user:pass@host/db?pool_size=20&max_overflow=10
```
