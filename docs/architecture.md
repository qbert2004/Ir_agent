# IR-Agent — System Architecture

## Table of Contents

1. [High-Level Overview](#1-high-level-overview)
2. [Component Map](#2-component-map)
3. [Event Processing Pipeline](#3-event-processing-pipeline)
4. [CyberAgent — ReAct Loop](#4-cyberagent--react-loop)
5. [ML Pipeline](#5-ml-pipeline)
6. [ThreatAssessment Engine — Signal Fusion](#6-threatassessment-engine--signal-fusion)
7. [Knowledge Base & RAG](#7-knowledge-base--rag)
8. [IoC Lookup Service](#8-ioc-lookup-service)
9. [Middleware Stack](#9-middleware-stack)
10. [Database Layer](#10-database-layer)
11. [LLM Provider Chain](#11-llm-provider-chain)
12. [Interfaces](#12-interfaces)
13. [Data Flow Diagrams](#13-data-flow-diagrams)
14. [Performance Characteristics](#14-performance-characteristics)
15. [Known Limitations](#15-known-limitations)

---

## 1. High-Level Overview

IR-Agent is a **hybrid AI system** for real-time cybersecurity event triage and incident investigation. It combines:

- **ML classifier** (GradientBoosting, ~5 ms) for high-throughput event filtering
- **LLM ReAct agent** (Groq/OpenAI/Ollama, 1–30 s) for contextual reasoning and investigation
- **MITRE ATT&CK mapper** (rule-based + pattern matching) for technique identification
- **IoC threat intelligence** (VirusTotal + AbuseIPDB) for indicator enrichment
- **ThreatAssessment engine** (weighted signal fusion) for unified scoring

The system is built on **FastAPI** with full async support, **SQLAlchemy** for persistence, and **FAISS** for vector similarity search.

```
                    ┌─────────────────────────────────┐
                    │           REST API               │
                    │        FastAPI + uvicorn         │
                    │                                  │
                    │  Middleware:                     │
                    │  RequestID → Auth → RateLimit    │
                    │  → RequestLogging                │
                    └────────────────┬────────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
                 ▼                   ▼                   ▼
        ┌──────────────┐   ┌──────────────────┐   ┌─────────────────┐
        │ Event Ingest │   │   CyberAgent     │   │ThreatAssessment │
        │  /ingest/*   │   │  /agent/*        │   │  /assessment/*  │
        └──────┬───────┘   └────────┬─────────┘   └────────┬────────┘
               │                    │                       │
               ▼                    ▼                       │
        ┌──────────────┐   ┌──────────────────┐            │
        │  ML Pipeline │   │  ReAct Loop      │            │
        │  Classifier  │   │  ≤ 8 steps       │            │
        │  ~5ms        │   │  9 tools         │            │
        └──────┬───────┘   └────────┬─────────┘            │
               │                    │                       │
               └────────────────────┴───────────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  Signal Fusion     │
                          │  ML(35%) IoC(30%) │
                          │  MITRE(20%)       │
                          │  Agent(15%)       │
                          └─────────┬─────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  Better Stack /    │
                          │  SIEM / Alerts     │
                          └───────────────────┘
```

---

## 2. Component Map

```
app/
├── core/
│   ├── config.py           Settings — pydantic-settings reads .env
│   └── middleware.py        4-layer middleware stack
│
├── routers/                 API surface — thin, delegate to services
│   ├── health.py            /health, /health/live, /health/ready, /health/ml, /metrics
│   ├── ingest.py            /ingest/telemetry, /ingest/event, /ingest/incidents/*
│   ├── agent.py             /agent/query, /agent/query/stream, /agent/tools, /agent/sessions/*
│   ├── assessment.py        /assessment/analyze, /assessment/analyze/event, /assessment/explain, /assessment/schema
│   ├── ml_investigation.py  /ml/investigate, /ml/classify, /ml/mitre, /ml/models
│   ├── report.py            /report, /report/generate
│   └── investigation.py     /investigation/start, /investigation/{id}/report
│
├── agent/
│   ├── core/agent.py        CyberAgent: ReAct loop, tool dispatch, run_streaming() generator
│   └── schemas.py           AgentQueryRequest, AgentQueryResponse, ToolInfo, KnowledgeStats
│
├── services/
│   ├── agent_service.py     Singleton; aquery() / astream() async interfaces
│   ├── event_processor.py   Hybrid ML+Agent pipeline; classify_and_forward()
│   ├── incident_manager.py  Incident correlation, state, CRUD
│   ├── ai_analyzer.py       Low-level LLM wrapper with provider fallback chain
│   ├── ioc_lookup.py        VirusTotal + AbuseIPDB + in-process LRU cache
│   ├── ml_detector.py       MLAttackDetector: feature extraction + model predict
│   ├── drift_detector.py    Feature distribution drift detection
│   ├── metrics.py           In-process counters (thread-safe)
│   └── betterstack.py       HTTP log forwarder to Better Stack
│
├── ml/
│   ├── cyber_ml_engine.py   CyberMLEngine: MITRE mapping, heuristic analysis
│   ├── attack_detector.py   MLAttackDetector: loads .pkl model, 47-feature vector
│   └── investigator.py      MLInvestigator: full incident investigation workflow
│
├── assessment/
│   └── threat_assessment.py ThreatAssessmentEngine: weighted fusion + 7 arbitration rules
│
├── db/
│   └── database.py          Async SQLAlchemy engine, session factory, init_db()
│
└── common/
    └── ai_groq.py           ask() / stream() LLM helpers
```

---

## 3. Event Processing Pipeline

```
HTTP POST /ingest/telemetry
          │
          ▼
    EventProcessor.classify_and_forward(event)
          │
          ▼
    ┌─────────────────────────────────────────┐
    │          ML Classifier                  │
    │  MLAttackDetector.predict(event)        │
    │                                         │
    │  Input: 47 features extracted from      │
    │    - process_name, command_line         │
    │    - event_type, parent_image           │
    │    - user, hostname, ip, port           │
    │    - temporal features                  │
    │                                         │
    │  Output: confidence score 0.0–1.0       │
    └─────────────────┬───────────────────────┘
                      │
          ┌───────────┼─────────────┐
          │           │             │
          ▼           ▼             ▼
       < 0.50     0.50–0.80      > 0.80
       BENIGN     UNCERTAIN    HIGH CONF
          │           │             │
       Discard        │          Fast-path
                      ▼          to Better Stack
               ┌─────────────────────────────┐
               │       CyberAgent            │
               │   Deep analysis             │
               │   ReAct loop ≤ 8 steps      │
               │   Tools: MITRE, IoC,        │
               │   knowledge, ML, etc.       │
               └──────────────┬──────────────┘
                              │
                              ▼
                    Agent verdict (MALICIOUS /
                    SUSPICIOUS / FALSE_POSITIVE)
                              │
                              ▼
                   ThreatAssessmentEngine
                   (ML + IoC + MITRE + Agent)
                              │
                              ▼
                      Better Stack / SIEM
```

### Thresholds

| Threshold | Value | Behaviour |
|---|---|---|
| `THRESHOLD_BENIGN` | 0.50 | Events below discarded (no action) |
| `THRESHOLD_CERTAIN` | 0.80 | Events above go fast-path immediately |
| Between | 0.50–0.80 | Uncertain — deep-path with CyberAgent |

These thresholds are hardcoded in `EventProcessor`. The `AI_SUSPICIOUS_THRESHOLD` setting controls the minimum score at which AI analysis is triggered (default 60, in 0–100 scale).

---

## 4. CyberAgent — ReAct Loop

The **CyberAgent** implements the ReAct (Reason + Act) pattern for iterative reasoning over cybersecurity problems.

### Loop structure

```
User Query
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  STEP 1                                              │
│  Thought: "I need to look up what mimikatz does"     │
│  Action: knowledge_search("mimikatz credential dump") │
│  Observation: "mimikatz is a credential dumping..."   │
├──────────────────────────────────────────────────────┤
│  STEP 2                                              │
│  Thought: "Let me check MITRE techniques"            │
│  Action: mitre_lookup("credential dumping")          │
│  Observation: "T1003 - OS Credential Dumping..."      │
├──────────────────────────────────────────────────────┤
│  STEP 3                                              │
│  Thought: "I should check if the IP is malicious"    │
│  Action: ioc_check("185.220.101.45")                 │
│  Observation: "Flagged by VirusTotal (72/90 engines)"|
├──────────────────────────────────────────────────────┤
│  STEP N (max 8)                                      │
│  Thought: "I have enough information to answer"      │
│  Action: ANSWER                                      │
│  Final Answer: "This is a confirmed credential..."   │
└──────────────────────────────────────────────────────┘
```

### Tool dispatch

Each `Action` is parsed to extract `tool_name(args)`. The agent calls the corresponding tool, captures the `Observation`, and continues.

### Available tools (9 total)

| Tool | Description |
|---|---|
| `knowledge_search` | FAISS semantic search over knowledge base documents |
| `mitre_lookup` | MITRE ATT&CK technique/tactic lookup |
| `ioc_check` | VirusTotal + AbuseIPDB IoC lookup |
| `ml_analyze` | Run ML classifier on event data |
| `incident_timeline` | Reconstruct attack timeline from events |
| `threat_assessment` | Compute unified threat score |
| `report_generate` | Generate structured investigation report |
| `web_search` | Search for threat intelligence and CVEs |
| `calculate` | Perform calculations and data transformations |

### Streaming

Two interfaces:

1. **`CyberAgent.run_streaming(query, session_id)`** — synchronous generator that yields step dicts as each ReAct step completes
2. **`AgentService.astream(query, session_id)`** — async generator; bridges sync generator to async via `queue.Queue` + `run_in_executor`

```python
# Sync generator (agent core)
def run_streaming(self, query, session_id):
    for step in range(MAX_STEPS):
        thought, action = self._reason(query, history)
        observation = self._act(action)
        yield {"type": "step", "step_number": step+1,
               "thought": thought, "action": action, "observation": observation}
        if action.startswith("ANSWER"):
            break
    yield {"type": "answer", "answer": final_answer, ...}

# Async bridge (service layer)
async def astream(self, query, session_id):
    q = queue.Queue()
    loop = asyncio.get_event_loop()
    def _run():
        for event in self._agent.run_streaming(query, session_id):
            q.put(("step", event))
        q.put(("done", None))
    future = loop.run_in_executor(None, _run)
    while True:
        kind, data = await loop.run_in_executor(None, q.get)
        if kind == "done":
            break
        yield data
    await future
```

This design ensures:
- True real-time streaming (events arrive as each step completes)
- The FastAPI event loop is never blocked
- Compatible with Python 3.14+ (no anyio/asyncio backend conflicts)

### Session memory

Each session maintains a conversation history (up to `AGENT_SESSION_MAX_SIZE` sessions in-memory, LRU eviction). Sessions are per-instance — not shared across replicas.

---

## 5. ML Pipeline

### Model: GradientBoosting Classifier

- **Algorithm**: `sklearn.ensemble.GradientBoostingClassifier`
- **Features**: 47 engineered features from raw event fields
- **Output**: probability score 0.0–1.0 (malicious likelihood)
- **Latency**: ~5 ms per event
- **Accuracy**: ~94% on training set

### Feature engineering (47 features)

Features are extracted from raw event dict fields:

| Category | Features |
|---|---|
| Process | is known malicious tool, is system process, has random name pattern |
| Command line | length, argument count, encoded payload flag, suspicious switches |
| Event type | one-hot: process_creation, network_connection, file_create, registry_set, ... |
| Network | destination port category, private/public IP flag, port risk score |
| User | is SYSTEM, is admin pattern, is service account |
| Temporal | hour of day, is business hours, weekend flag |
| Parent process | parent is shell (cmd/powershell), parent is office app, parent is browser |

### CyberMLEngine (heuristic fallback)

When the trained `.pkl` model is not available, `CyberMLEngine` provides:
- Rule-based event classification using keyword matching
- MITRE ATT&CK technique mapping (200+ patterns)
- Threat scoring heuristics

### Drift detection

`DriftDetector` monitors feature distribution over rolling windows:
- Compares current feature means/variance to training baseline
- Alerts when distribution diverges by >2σ (concept drift warning)
- Accessible via `GET /health/ml`

---

## 6. ThreatAssessment Engine — Signal Fusion

`ThreatAssessmentEngine.assess()` combines up to 4 independent signals into a single normalized threat score (0–100).

### Weighted scoring formula

```
base_score = (
    ml.score    * 0.35 +
    ioc.score   * 0.30 +
    mitre.score * 0.20 +
    agent.score * 0.15
) * 100
```

When a signal is unavailable, its weight is redistributed proportionally to the remaining signals.

### 7 Arbitration Rules

Rules override the weighted base score in specific situations:

| Rule | Type | Trigger | Effect |
|---|---|---|---|
| R1 | Escalation | ≥2 IoC providers confirmed malicious | Force score ≥ 85 (CRITICAL) |
| R2 | Escalation | ML reason contains credential dump keywords | Force score ≥ 80 |
| R3 | Escalation | MITRE: lateral_movement + credential_access | Force score ≥ 65 (HIGH) |
| R4 | Escalation | MITRE: impact tactic detected | Force score ≥ 65 |
| R5 | Bonus | All 3+ sources agree malicious | +10% bonus |
| R6 | Downgrade | Agent: HIGH_CONFIDENCE FALSE_POSITIVE + ML < 0.6 | Cap score at 25 |
| R7 | Downgrade | IoC clean + Agent FALSE_POSITIVE + ML uncertain | Cap score at 40 |

### Severity levels

| Score | Severity | Response time |
|---|---|---|
| 85–100 | CRITICAL | Immediate |
| 65–84 | HIGH | Within 1 hour |
| 45–64 | MEDIUM | Within business hours |
| 25–44 | LOW | Monitor |
| 0–24 | INFO | No action |

### Confidence levels

| Level | Condition |
|---|---|
| HIGH | ≥3 sources available and majority agree |
| MEDIUM | ≥2 sources with partial agreement OR arbitration rule fired |
| LOW | Single source or strong disagreement |

---

## 7. Knowledge Base & RAG

The agent uses **Retrieval-Augmented Generation** for the `knowledge_search` tool.

### Components

- **Documents**: Cybersecurity knowledge stored in `knowledge_base/` directory
- **Embeddings**: `sentence-transformers/all-MiniLM-L6-v2` (384-dimensional vectors)
- **Index**: FAISS `IndexFlatL2` stored in `vector_db/`
- **Retrieval**: Top-K cosine similarity search

### Ingestion flow

```
Document text
      │
      ▼
Chunk (512 tokens, 64 overlap)
      │
      ▼
SentenceTransformer.encode()
      │
      ▼
FAISS.add() → persisted to vector_db/
```

### Query flow

```
Agent tool call: knowledge_search("mimikatz credential dump")
      │
      ▼
SentenceTransformer.encode(query)
      │
      ▼
FAISS.search(query_vector, k=5)
      │
      ▼
Return top-5 chunks → agent observation
```

### Adding knowledge

Via API:
```bash
curl -X POST http://localhost:9000/agent/ingest \
  -d '{"title": "CVE Analysis", "content": "...", "source": "internal"}'
```

---

## 8. IoC Lookup Service

`IoCLookupService` queries threat intelligence providers and caches results.

### Providers

| Provider | Free limit | Data |
|---|---|---|
| VirusTotal | 4 req/min, 500/day | IP, domain, file hash, URL |
| AbuseIPDB | 1000/day | IP reputation, abuse categories |

### Caching

- **Implementation**: `functools.lru_cache`-style custom LRU cache
- **TTL**: `IOC_CACHE_TTL_SECONDS` (default: 3600 s = 1 h)
- **Max size**: `IOC_CACHE_MAX_SIZE` (default: 10 000 entries)
- **Eviction**: LRU (least recently used)

### Aggregated score formula

```python
ioc_score = (
    virustotal_score * 0.6 +
    abuseipdb_score  * 0.4
)

# is_malicious = True if score > 0.5 or either provider explicitly flags
```

---

## 9. Middleware Stack

FastAPI middleware is applied in outermost-first order:

```
Incoming Request
      │
      ▼
┌─────────────────────────────┐
│  RequestLoggingMiddleware   │  Log method, path, response time, status
├─────────────────────────────┤
│  RateLimitMiddleware        │  Sliding window, 60 req/min per IP
│  (in-memory or Redis)       │  → 429 if exceeded
├─────────────────────────────┤
│  AuthMiddleware             │  Check Authorization: Bearer <token>
│                             │  Skip: /, /health*, (dev mode: all)
│                             │  → 401 if invalid
├─────────────────────────────┤
│  RequestIDMiddleware        │  Generate X-Request-ID if absent
│                             │  Add to response headers
├─────────────────────────────┤
│  CORSMiddleware             │  Allow configured origins
└─────────────────────────────┘
      │
      ▼
    Router handler
```

### Public endpoints (no auth)

- `GET /` — root
- `GET /health` — health check
- `GET /health/live` — liveness
- `GET /health/ready` — readiness

---

## 10. Database Layer

### Async SQLAlchemy

All database access is async using `asyncpg` (PostgreSQL) or `aiosqlite` (SQLite).

```python
# Session usage pattern
async with AsyncSessionLocal() as session:
    async with session.begin():
        result = await session.execute(select(Incident))
```

### Schema (via Alembic)

Single migration: `alembic/versions/20250304_0001_initial_schema.py`

Tables:
- `incidents` — correlated incident records
- `events` — raw security events (linked to incidents)
- `reports` — generated investigation reports
- `sessions` — (optional) persistent agent sessions

### Connection strings

| Environment | URL format |
|---|---|
| Development | `sqlite+aiosqlite:///./ir_agent.db` |
| Production | `postgresql+asyncpg://user:pass@host:5432/db` |

---

## 11. LLM Provider Chain

`AIAnalyzer` / `ai_groq.py` implement a fallback chain:

```
LLM_API_KEY (Groq)
      │
      ├── success → use Groq (llama-3.3-70b-versatile by default)
      │
      ├── not set → try OPENAI_API_KEY
      │                   │
      │                   ├── success → use OpenAI
      │                   │
      │                   └── not set → try OLLAMA_BASE_URL
      │                                     │
      │                                     ├── set → use Ollama (local)
      │                                     │
      │                                     └── not set → AI DISABLED
      │                                         (heuristic-only mode)
      │
      └── rate-limit / error → automatic retry with backoff
```

### Models

| Variable | Default | Used for |
|---|---|---|
| `LLM_ANALYZER_MODEL` | `llama-3.3-70b-versatile` | Agent reasoning, event analysis |
| `LLM_REPORT_MODEL` | `llama-3.3-70b-versatile` | Investigation report generation |

### Timeout

`AGENT_TIMEOUT_SECONDS` (default: 120 s) — maximum wall-clock time for a single `aquery()` / `astream()` call. Returns HTTP 504 on timeout.

---

## 12. Interfaces

### REST API (primary)

42 endpoints across 8 routers. Full reference: [api.md](api.md)

### CLI (`cli.py`)

Click-based command-line tool. Uses sync `httpx.Client` for HTTP.

```
Commands:
  status       Server health
  query        Agent query (blocking or --stream)
  tools        List agent tools
  metrics      ML + agent statistics
  ioc          IoC lookup
  mitre        MITRE technique lookup
  investigate  Run incident investigation
  assess       Threat assessment
  shell        Interactive REPL
```

### TUI (`tui.py`)

Full-screen terminal UI built with **Textual 8.0.2**.

Architecture notes:
- All HTTP calls use `@work(thread=True)` + sync `httpx.Client` (avoids Python 3.14 + anyio incompatibility)
- UI updates from workers use `call_from_thread()` (thread-safe)
- Streaming via NDJSON parsed line-by-line in thread worker

8 tabs:
1. **Status** — server health and component overview
2. **Query** — interactive agent query with streaming output
3. **Tools** — agent tool registry
4. **Metrics** — ML model stats and event processing counters
5. **IoC** — threat intelligence lookup
6. **MITRE** — ATT&CK technique browser
7. **Investigate** — incident investigation workflow
8. **Assess** — multi-signal threat assessment

### Web Dashboard (`/dashboard`)

Single-page HTML dashboard served at `GET /dashboard`:
- Architecture diagram
- Live agent query interface
- Tool list
- Metrics display
- ML vs Agent comparison

---

## 13. Data Flow Diagrams

### Streaming agent query

```
Client                FastAPI              AgentService           CyberAgent
  │                      │                     │                      │
  │  POST /agent/query/stream                  │                      │
  │─────────────────────>│                     │                      │
  │                      │  astream(query)     │                      │
  │                      │────────────────────>│                      │
  │                      │                     │  run_in_executor     │
  │                      │                     │─────────────────────>│
  │                      │                     │                      │
  │                      │                     │  ← yield step dict   │
  │  {"type":"step",...} │  queue.put(step)    │                      │
  │<─────────────────────│<────────────────────│  (step 1 complete)  │
  │                      │                     │                      │
  │                      │                     │  ← yield step dict   │
  │  {"type":"step",...} │  queue.put(step)    │                      │
  │<─────────────────────│<────────────────────│  (step 2 complete)  │
  │                      │                     │                      │
  │                      │                     │  ← yield answer      │
  │  {"type":"answer",...}│  queue.put(done)   │                      │
  │<─────────────────────│<────────────────────│                      │
  │                      │                     │                      │
```

### Ingest telemetry (fast-path)

```
Client          /ingest/telemetry    EventProcessor     MLAttackDetector   BetterStack
  │                   │                   │                   │               │
  │  POST event       │                   │                   │               │
  │──────────────────>│                   │                   │               │
  │  200 (immediate)  │                   │                   │               │
  │<──────────────────│                   │                   │               │
  │                   │  background_task  │                   │               │
  │                   │──────────────────>│                   │               │
  │                   │                   │  predict(event)   │               │
  │                   │                   │──────────────────>│               │
  │                   │                   │  score=0.93       │               │
  │                   │                   │<──────────────────│               │
  │                   │                   │  fast-path        │               │
  │                   │                   │  (score > 0.80)   │               │
  │                   │                   │─────────────────────────────────>│
  │                   │                   │                                   │ logged
```

---

## 14. Performance Characteristics

| Operation | Typical latency | Notes |
|---|---|---|
| ML classify | ~5 ms | GradientBoosting, CPU, 47 features |
| MITRE map | ~2 ms | Rule-based pattern matching |
| IoC lookup (cached) | ~0.1 ms | LRU cache hit |
| IoC lookup (live) | 500–2000 ms | VirusTotal + AbuseIPDB HTTP |
| Agent query (simple) | 3–8 s | 1–2 LLM calls |
| Agent query (complex) | 10–30 s | 4–8 LLM calls + tools |
| Knowledge search | ~10 ms | FAISS L2 search |
| DB write (SQLite) | ~5 ms | aiosqlite |
| DB write (PostgreSQL) | ~2 ms | asyncpg |
| Threat assessment | ~0.5 ms | Pure Python arithmetic |

### Memory footprint (single instance at rest)

| Component | RAM |
|---|---|
| FastAPI + uvicorn | ~100 MB |
| ML model (GBM) | ~50 MB |
| FAISS index (1 000 vectors) | ~20 MB |
| SentenceTransformer model | ~200 MB |
| Agent session cache (empty) | ~5 MB |
| **Total baseline** | **~375 MB** |

---

## 15. Known Limitations

### In-memory state

- **Agent sessions** are per-process. Restarting the server clears all sessions.
- **Rate limiter** is per-process unless `REDIS_URL` is configured.
- **Metrics counters** reset on restart.

For production multi-instance deployments, sessions and metrics should be externalized (Redis / database).

### Authentication

- Single shared API token (`MY_API_TOKEN`). No per-client key management.
- Token comparison uses `==` (not `hmac.compare_digest()`). Vulnerable to timing attacks on extremely fast networks.

### Python 3.14 + anyio

`httpx.AsyncClient` is incompatible with Python 3.14 due to changes in `asyncio` internals. The server itself (uvicorn) is unaffected. Affected areas:
- TUI — mitigated by using `@work(thread=True)` + sync `httpx.Client`
- CLI — uses sync `httpx.Client` (not affected)
- Tests that use `AsyncClient` — use Python 3.11/3.12 for running tests

### SQLite in production

SQLite does not support multiple concurrent writers. Use PostgreSQL for production. SQLite is suitable for development and single-user deployments only.

### LLM hallucinations

The agent uses LLM reasoning which can produce incorrect conclusions. The ThreatAssessment engine assigns the agent the lowest signal weight (15%) precisely because LLMs can hallucinate. Always validate agent verdicts with ML and IoC signals.

### Groq free tier limits

- 30 requests/minute on free Groq plan
- Deep-path agent invocations consume multiple requests (one per reasoning step)
- Under sustained load (>10 uncertain events/minute), Groq rate limits will be hit
- Mitigation: paid plan, OpenAI fallback, or Ollama local deployment
