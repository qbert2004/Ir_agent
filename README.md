# IR-Agent

![CI](https://github.com/qbert2004/Ir_agent/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Autonomous AI-powered Cyber Incident Response Platform**

IR-Agent is a production-ready FastAPI service that combines a GradientBoosting ML classifier, a ReAct LLM agent, IoC threat-intelligence lookups, and a MITRE ATT&CK mapper into a unified pipeline for real-time security event triage and investigation.

---

## Key Features

| Feature | Details |
|---|---|
| **Dual-path event pipeline** | Fast-path ML (~5 ms) for high-confidence events; Deep-path LLM agent (~1–30 s) for uncertain cases |
| **ReAct CyberAgent** | Up to 8 reasoning steps, 9 tools, streaming NDJSON output |
| **Threat Assessment Engine** | Weighted fusion of ML + IoC + MITRE + Agent signals with 7 arbitration rules |
| **MITRE ATT&CK mapping** | 200+ technique patterns, tactic coverage, lateral-movement/credential-access escalation |
| **IoC Lookup** | VirusTotal + AbuseIPDB with in-process LRU cache (TTL 1 h, max 10 000 entries) |
| **REST API** | 42 endpoints across 8 routers, Swagger UI in dev, NDJSON streaming |
| **Observability** | Prometheus `/metrics`, Better Stack log shipping, per-request IDs, readiness/liveness probes |
| **Interfaces** | CLI (`cli.py`), full-screen TUI (`tui.py`), HTML dashboard (`/dashboard`) |
| **Database** | Async SQLAlchemy — SQLite (dev) or PostgreSQL (prod) via Alembic migrations |

---

## Architecture Overview

```
Security Event
      │
      ▼
┌─────────────────────────────────────────────┐
│              /ingest/telemetry               │
│              EventProcessor                  │
│                                             │
│  ┌──────────────────────────────────────┐   │
│  │  ML Classifier  (GradientBoosting)   │   │
│  │  confidence score  0.0 – 1.0         │   │
│  └──────────────┬───────────────────────┘   │
│                 │                            │
│   < 0.50        │ 0.50-0.80      > 0.80      │
│   BENIGN        │ UNCERTAIN      HIGH CONF   │
│   (discard)     │                (fast-path) │
│                 ▼                    │       │
│      ┌──────────────────┐            │       │
│      │  CyberAgent      │            │       │
│      │  ReAct loop      │            │       │
│      │  ≤ 8 steps       │            │       │
│      └──────────┬───────┘            │       │
│                 │                    │       │
└─────────────────┼────────────────────┼───────┘
                  │                    │
                  ▼                    ▼
         ┌────────────────────────────────┐
         │   ThreatAssessmentEngine       │
         │   ML(35%) + IoC(30%)           │
         │   + MITRE(20%) + Agent(15%)    │
         └──────────────┬─────────────────┘
                        │
                        ▼
                 Better Stack / SIEM
```

---

## Quick Start

### Prerequisites

- Python 3.11+ (3.14 supported via sync-httpx thread workers)
- [Groq API key](https://console.groq.com) (free tier, required for LLM features)
- Docker + Docker Compose (optional, for production)

### 1. Clone and install

```bash
git clone https://github.com/qbert2004/Ir_agent
cd Ir_agent
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — at minimum set LLM_API_KEY
```

Minimum required settings:

```env
LLM_API_KEY=gsk_...           # Groq API key
ENVIRONMENT=development        # disables auth + shows /docs
```

### 3. Run migrations

```bash
alembic upgrade head
```

### 4. Start the server

```bash
python app/main.py
# or
uvicorn app.main:app --host 0.0.0.0 --port 9000 --reload
```

Server starts on **http://localhost:9000**
- Swagger UI: http://localhost:9000/docs
- ReDoc: http://localhost:9000/redoc
- Dashboard: http://localhost:9000/dashboard

### 5. Verify

```bash
curl http://localhost:9000/health
# {"status":"healthy","version":"1.0.0",...}
```

---

## Interfaces

### REST API

All endpoints are documented at `/docs` (dev only). See [docs/api.md](docs/api.md) for full reference.

```bash
# Send a security event
curl -X POST http://localhost:9000/ingest/telemetry \
  -H "Content-Type: application/json" \
  -d '{"process_name":"mimikatz.exe","hostname":"srv-01","event_type":"process_creation"}'

# Query the AI agent
curl -X POST http://localhost:9000/agent/query \
  -H "Content-Type: application/json" \
  -d '{"query":"Is mimikatz.exe malicious? What MITRE techniques?"}'

# Stream agent reasoning steps
curl -N -X POST http://localhost:9000/agent/query/stream \
  -H "Content-Type: application/json" \
  -d '{"query":"Analyze this attack: lateral movement via PsExec"}'
```

### CLI

```bash
python cli.py status                           # Server health
python cli.py query "What is T1003?"          # Agent query
python cli.py query "Analyze mimikatz" --stream  # Streaming
python cli.py tools                            # List agent tools
python cli.py metrics                          # ML + agent stats
python cli.py ioc 185.220.101.45              # IoC lookup
python cli.py mitre T1566.001                 # MITRE technique
python cli.py investigate INC-001             # Investigate incident
python cli.py assess --ml 0.87 --ioc 0.9     # Threat assessment
python cli.py shell                            # Interactive REPL
```

### TUI (Terminal UI)

```bash
python tui.py                  # Full-screen terminal interface

# Key bindings:
# 1-8  Switch tabs
# r    Refresh current tab
# q    Quit
```

Eight tabs: **Status · Query · Tools · Metrics · IoC · MITRE · Investigate · Assess**

---

## Docker Deployment

```bash
# Build and start with PostgreSQL
docker-compose up -d

# Check logs
docker-compose logs -f ir-agent

# Scale (each replica is independent — no shared in-memory state)
docker-compose up -d --scale ir-agent=3
```

See [docs/deployment.md](docs/deployment.md) for production checklist and env vars.

---

## Project Structure

```
Ir_agent/
├── app/
│   ├── main.py                      # FastAPI app, middleware, lifespan
│   ├── core/
│   │   ├── config.py                # Pydantic settings (env vars)
│   │   └── middleware.py            # Auth, rate-limit, request-ID, logging
│   ├── routers/
│   │   ├── health.py                # /health, /health/live, /health/ready, /metrics
│   │   ├── ingest.py                # /ingest/telemetry, /ingest/event, incidents
│   │   ├── agent.py                 # /agent/query, /agent/query/stream, /agent/tools
│   │   ├── assessment.py            # /assessment/analyze, /assessment/explain
│   │   ├── ml_investigation.py      # /ml/investigate, /ml/classify, /ml/mitre
│   │   ├── report.py                # /report, /report/generate
│   │   ├── investigation.py         # /investigation/start, /investigation/{id}/report
│   │   └── dashboard.html           # Single-page dashboard UI
│   ├── agent/
│   │   ├── core/agent.py            # CyberAgent — ReAct loop, tool dispatch, streaming
│   │   └── schemas.py               # Request/response Pydantic models
│   ├── services/
│   │   ├── agent_service.py         # Singleton wrapper; aquery(), astream()
│   │   ├── event_processor.py       # Hybrid ML+Agent pipeline
│   │   ├── incident_manager.py      # Incident correlation and state
│   │   ├── ai_analyzer.py           # LLM client (Groq→OpenAI→Ollama fallback chain)
│   │   ├── ioc_lookup.py            # VirusTotal + AbuseIPDB + LRU cache
│   │   ├── ml_detector.py           # MLAttackDetector wrapper
│   │   ├── drift_detector.py        # Feature drift detection
│   │   ├── metrics.py               # In-process metrics counters
│   │   └── betterstack.py           # Better Stack log forwarder
│   ├── ml/
│   │   ├── cyber_ml_engine.py       # CyberMLEngine — MITRE mapping, heuristics
│   │   ├── attack_detector.py       # MLAttackDetector — GradientBoosting model
│   │   └── investigator.py          # MLInvestigator — full incident investigation
│   ├── assessment/
│   │   └── threat_assessment.py     # ThreatAssessmentEngine — signal fusion
│   ├── db/
│   │   └── database.py              # Async SQLAlchemy engine, session factory
│   └── common/
│       └── ai_groq.py               # Low-level LLM helpers (ask, stream)
├── alembic/                         # Database migrations
├── models/                          # Trained ML model artifacts
├── vector_db/                       # FAISS knowledge-base index
├── knowledge_base/                  # Source documents for RAG
├── tests/                           # pytest test suite (76 tests)
├── cli.py                           # Click CLI
├── tui.py                           # Textual TUI
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── docs/
    ├── api.md                       # Full endpoint reference
    ├── architecture.md              # System design deep-dive
    └── deployment.md                # Production deployment guide
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `groq` | Primary LLM provider |
| `LLM_API_KEY` | — | Groq API key (required for AI features) |
| `OPENAI_API_KEY` | — | OpenAI fallback key |
| `OLLAMA_BASE_URL` | — | Ollama local endpoint |
| `LLM_ANALYZER_MODEL` | `llama-3.3-70b-versatile` | Model for event analysis |
| `LLM_REPORT_MODEL` | `llama-3.3-70b-versatile` | Model for report generation |
| `MY_API_TOKEN` | — | Bearer token (required in production) |
| `ENVIRONMENT` | `production` | `development` enables /docs and disables auth |
| `DATABASE_URL` | `sqlite+aiosqlite:///./ir_agent.db` | Database connection string |
| `REDIS_URL` | — | Redis for distributed rate-limiting |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal IoC lookups |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB IoC lookups |
| `BETTER_STACK_SOURCE_TOKEN` | — | Better Stack log shipping |
| `AI_SUSPICIOUS_THRESHOLD` | `60` | ML confidence threshold (0–100) |
| `API_PORT` | `9000` | HTTP listen port |
| `CORS_ORIGINS` | `http://localhost:3000,...` | Allowed CORS origins |
| `RATE_LIMIT_PER_MINUTE` | `60` | Requests per minute per IP |

Full list: [`.env.example`](.env.example)

---

## Supported Incident Types

- Ransomware
- Malware / Backdoor
- Lateral Movement (PsExec, WMI, pass-the-hash)
- Credential Theft (mimikatz, lsass dump)
- Data Exfiltration
- Phishing
- Insider Threat
- APT (Advanced Persistent Threat)
- DDoS
- Anomalous Network Activity

---

## Documentation

| Document | Description |
|---|---|
| [docs/api.md](docs/api.md) | Complete endpoint reference with request/response examples |
| [docs/architecture.md](docs/architecture.md) | System design, ReAct loop, ML pipeline, signal fusion |
| [docs/deployment.md](docs/deployment.md) | Production deployment guide, security checklist, scaling |
| [docs/EVALUATION.md](docs/EVALUATION.md) | ML model evolution, production metrics, fusion weights justification, limitations |
| [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md) | ML model training, features, MITRE mapping details |
| [INVESTIGATION_GUIDE.md](INVESTIGATION_GUIDE.md) | Step-by-step investigation workflows |
| [DIPLOMA_DOCUMENTATION.md](DIPLOMA_DOCUMENTATION.md) | Полная документация для защиты диплома |
| [CHANGELOG.md](CHANGELOG.md) | История версий |

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/ -v                    # Run all 76 tests
pytest tests/ -v --tb=short -q     # Compact output
pytest tests/test_agent.py -v      # Single module
```

---

## License

MIT License
