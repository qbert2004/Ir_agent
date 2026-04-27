# IR-Agent

![CI](https://github.com/qbert2004/Ir_agent/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-128%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**Autonomous AI-powered Cyber Incident Response Platform**

IR-Agent is a production-ready FastAPI service that correlates raw security telemetry into **Incidents**, then dispatches a ReAct LLM agent to investigate the **full incident group** — not just individual events. A GradientBoosting ML classifier, IoC threat-intelligence lookups, MITRE ATT&CK mapper, and a Bayesian threat-score fusion engine are all wired together into one autonomous pipeline.

---

## What Changed in v2 — Incident-Based Investigation

Previous versions analysed events **one at a time**. An agent was invoked for each log entry independently, which meant multi-stage attacks (reconnaissance → credential dump → lateral movement) were never seen as a single narrative.

**v2 rewrites investigation to be incident-first:**

```
Before:  event → ML → agent(single log) → verdict
After:   event₁ ─┐
         event₂ ─┤→ IncidentManager → Incident → agent(ALL logs) → verdict
         event₃ ─┘
```

---

## How It Works — Step by Step

### 1. Event Ingestion

```
POST /ingest/telemetry  ← raw endpoint/SIEM log
```

The `EventProcessor` receives a raw event dict (Windows Security log, Sysmon, custom telemetry).

### 2. ML Classification

`MLAttackDetector` (GradientBoosting) scores the event 0.0 – 1.0.

| Score range | Path |
|---|---|
| < 0.50 | Filtered — discarded as benign |
| 0.50 – 0.80 | **Deep path** — sent to CyberAgent |
| > 0.80 | **Fast path** — saved immediately; background investigation triggered |

### 3. Incident Correlation

**Before any agent call**, the event is passed to `IncidentManager.correlate_event()`.

- Events from the **same hostname** within a **30-minute window** are merged into one `Incident`.
- A new `Incident` object is created when no active incident exists for that host (or the window has expired).
- Each `Incident` accumulates: raw events, affected hosts/users, timestamps.

```python
# Example: two events on WS-VICTIM01 within 30 min → same incident
id1 = manager.correlate_event(event_powershell, 0.9, "ML malicious")
id2 = manager.correlate_event(event_mimikatz,   0.85, "ML malicious")
assert id1 == id2  # same incident!
```

### 4. Incident Investigation (rule-based)

`IncidentManager.investigate(incident_id)` runs **before** the LLM:

1. **Timeline builder** — sorts events chronologically, classifies each into an `AttackPhase` (Initial Access, Execution, Credential Access, Lateral Movement, etc.)
2. **IoC extractor** — RegEx scans all text fields (command_line, script_block_text, source_ip, …) for IPs, domains, hashes, URLs, file paths, registry keys; filters private IPs; deduplicates
3. **MITRE ATT&CK mapper** — matches process names and command-line fragments to 40+ known technique patterns (T1059.001, T1003.001, T1053.005, …)
4. **Classification** — determines incident type from phase combination (e.g. Credential Access + Lateral Movement → "Credential theft with lateral movement")
5. **Severity scoring** — Bayesian-weighted: event count + phase diversity + critical phases + MITRE density + IoC count + avg ML confidence + multi-host flag
6. **Root cause analysis** — identifies initial vector from first timeline entry (brute force, RDP, PowerShell, phishing, etc.)
7. **Impact assessment** — lists concrete risks (credentials at risk, persistence established, active C2, data exfiltration possible)
8. **Recommendations** — generates ordered response actions (isolate host, reset credentials, block IPs, remove persistence, preserve forensics)

### 5. AI Agent Investigation (LLM)

`CyberAgent` (ReAct loop, up to 8 steps) receives a rich **incident-level prompt**:

```
INCIDENT IR-20260427-A1B2C3 on WS-VICTIM01

TIMELINE (2 events):
  2026-04-27T10:00:00Z  [Execution] PowerShell execution by john.doe (encoded command)
    MITRE: T1059.001, T1027
  2026-04-27T10:01:00Z  [Credential Access] Credential dumping: mimikatz.exe
    MITRE: T1003.001

IoCs EXTRACTED (2):
  [PROCESS] mimikatz.exe — Suspicious tool
  [IP]      185.220.101.5 — Found in event 4625

PRELIMINARY CLASSIFICATION: Credential access / dumping attempt
CONFIDENCE: 35%

AVAILABLE TOOLS: get_incident, get_incident_events, lookup_ioc, mitre_lookup, search_logs, ml_classify

INVESTIGATION TASK:
  1. Review the complete incident timeline and all events
  2. Look up any suspicious IoCs with lookup_ioc
  3. Map all observed techniques to MITRE ATT&CK
  4. Assess the attack chain from first event to last

Conclude with: Verdict: MALICIOUS / SUSPICIOUS / FALSE_POSITIVE
```

The agent has **11 tools** available:

| Tool | Purpose |
|---|---|
| `get_incident` | Fetch full incident: timeline, IoCs, MITRE, findings, root cause, recommendations |
| `get_incident_events` | Get raw log events from incident; supports `phase_filter` ("Credential Access", …) and `limit` |
| `knowledge_search` | Vector search over security knowledge base (FAISS) |
| `search_logs` | Query historical events by hostname/time range |
| `classify_event` | Run ML classifier on a raw event dict |
| `analyze_event` | Deep LLM analysis of a single event |
| `mitre_lookup` | Look up a MITRE technique by ID or keyword |
| `lookup_ioc` | Check IP/domain/hash against VirusTotal + AbuseIPDB |
| `query_siem` | Query SIEM-style event history |
| `investigate` | Trigger rule-based investigation on an incident |
| `ml_classify` | Direct ML scoring of event text |

The agent reuses the **same session** (`session_id = "incident-{incident_id}"`) across all events in the same incident, so it retains memory between calls.

### 6. Threat Assessment Fusion

After the agent completes, `ThreatAssessmentEngine` fuses all four signals:

```
ML score    × 0.35
IoC score   × 0.30
MITRE score × 0.20
Agent score × 0.15
─────────────────
Final score  0–100  →  INFO / LOW / MEDIUM / HIGH / CRITICAL
```

Seven arbitration rules can override the weighted score:

| Rule | Trigger | Effect |
|---|---|---|
| R1 | ≥2 IoC providers confirmed malicious | Force score ≥ 85 (CRITICAL) |
| R2 | "lsass"/"credential dump" in ML reason | Force score ≥ 80 |
| R3 | MITRE: lateral_movement + credential_access | Force score ≥ 65 (HIGH) |
| R4 | MITRE: impact tactic | Force score ≥ 65 |
| R5 | All 3+ sources vote malicious | +10% bonus |
| R6 | Agent FALSE_POSITIVE + ML < 0.6 | Cap score at 25 (LOW) |
| R7 | IoC clean + Agent FP + ML uncertain | Cap score at 40 |

### 7. Fast-path Background Investigation

High-confidence events (> 0.80) skip the synchronous agent call but still get investigated:

```python
# In _fast_path_forward():
if incident.agent_analysis is None:
    asyncio.create_task(_background_investigate_incident(incident_id))
```

The background task runs `run_incident_investigation()` non-blocking, stores results in the incident, and persists to DB.

### 8. Persistence

All results are stored in SQLite (dev) or PostgreSQL (prod):

- `events` table — every raw event with ML scores, threat scores, `incident_id` FK
- `incidents` table — full investigation result including `agent_analysis_json` and `incident_summary`
- `iocs` table — all extracted IoCs linked to incidents

---

## Quick Start

### Prerequisites

- Python 3.11+ (3.13 confirmed working)
- [Groq API key](https://console.groq.com) — free tier, required for LLM features
- Docker + Docker Compose (optional)

### 1. Clone and install

```bash
git clone https://github.com/qbert2004/Ir_agent
cd Ir_agent
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env
```

Minimum required:

```env
LLM_API_KEY=gsk_...           # Groq API key
ENVIRONMENT=development        # disables auth, enables /docs
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

- Swagger UI: **http://localhost:9000/docs**
- Dashboard: **http://localhost:9000/dashboard**
- Health: **http://localhost:9000/health**

---

## Verify the Incident Pipeline

### Step 1 — Send two related events (same host, within 30 min)

```bash
# Event 1: PowerShell encoded command
curl -X POST http://localhost:9000/ingest/telemetry \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-04-27T10:00:00Z",
    "event_id": 4688,
    "hostname": "WS-VICTIM01",
    "process_name": "powershell.exe",
    "command_line": "powershell -enc aQBuAHYAbwBrAGUALQBleHByZXNzaW9u",
    "user": "john.doe"
  }'

# Event 2: Mimikatz credential dumping (same host)
curl -X POST http://localhost:9000/ingest/telemetry \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-04-27T10:01:00Z",
    "event_id": 4688,
    "hostname": "WS-VICTIM01",
    "process_name": "mimikatz.exe",
    "command_line": "sekurlsa::logonpasswords",
    "user": "john.doe"
  }'
```

### Step 2 — List incidents

```bash
curl http://localhost:9000/ingest/incidents
# Returns: {"status":"success","incidents":[{"id":"IR-20260427-XXXXXX","host":"WS-VICTIM01",...}],"stats":{...}}
```

### Step 3 — Get full incident details (copy ID from step 2)

```bash
curl http://localhost:9000/ingest/incidents/IR-20260427-XXXXXX
# Returns: timeline, iocs, mitre_techniques, root_cause, impact_assessment, recommendations
```

### Step 4 — Read the investigation report (plain text)

```bash
curl http://localhost:9000/ingest/incidents/IR-20260427-XXXXXX/report
```

```
======================================================================
INCIDENT INVESTIGATION REPORT
======================================================================
Incident ID:     IR-20260427-XXXXXX
Host:            WS-VICTIM01
Severity:        MEDIUM
Confidence:      35%
Classification:  Credential access / dumping attempt

----------------------------------------------------------------------
ATTACK TIMELINE
----------------------------------------------------------------------
  2026-04-27T10:00:00Z  [!] [Execution]
    PowerShell execution by john.doe (encoded command)
    MITRE: T1059.001, T1027

  2026-04-27T10:01:00Z  [!!!] [Credential Access]
    Credential dumping: mimikatz.exe executed by john.doe
    MITRE: T1003.001

----------------------------------------------------------------------
INDICATORS OF COMPROMISE (IoCs)
----------------------------------------------------------------------
  [PROCESS]
    - mimikatz.exe (Suspicious tool)

----------------------------------------------------------------------
ROOT CAUSE ANALYSIS
----------------------------------------------------------------------
  PowerShell-based attack, likely delivered via phishing or exploit.
  Credential harvesting indicates intent for privilege escalation or lateral movement.

----------------------------------------------------------------------
RECOMMENDED RESPONSE
----------------------------------------------------------------------
  1. Isolate affected host(s) from network
  2. Reset all credentials for affected users
  3. Force password change for all accounts on affected hosts
  4. Review Active Directory for unauthorized changes
  5. Preserve evidence and forensic artifacts
```

### Step 5 — Trigger AI agent investigation

```bash
curl -X POST http://localhost:9000/ingest/incidents/IR-20260427-XXXXXX/investigate
```

```json
{
  "status": "success",
  "incident_id": "IR-20260427-XXXXXX",
  "agent_verdict": "MALICIOUS",
  "agent_confidence": 0.95,
  "summary": "Confirmed attack chain: encoded PowerShell delivery followed by mimikatz credential dumping. High confidence malicious activity.",
  "tools_used": ["get_incident", "get_incident_events", "lookup_ioc", "mitre_lookup"],
  "steps": 4
}
```

---

## Incident API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/ingest/incidents` | List all incidents with stats |
| `GET` | `/ingest/incidents/{id}` | Get full incident (timeline, IoCs, MITRE, findings) |
| `GET` | `/ingest/incidents/{id}/report` | Plain-text investigation report |
| `POST` | `/ingest/incidents/{id}/investigate` | Run full AI agent investigation |
| `POST` | `/ingest/telemetry` | Ingest a raw security event |
| `POST` | `/ingest/event` | Ingest a structured event |

---

## Other Interfaces

### CLI

```bash
python cli.py status                              # Server health
python cli.py query "What is T1003?"             # Agent query
python cli.py query "Analyze mimikatz" --stream  # Streaming
python cli.py tools                               # List 11 agent tools
python cli.py metrics                             # ML + agent + incident stats
python cli.py ioc 185.220.101.45                 # IoC lookup
python cli.py mitre T1003.001                    # MITRE technique lookup
python cli.py assess --ml 0.87 --ioc 0.9        # Threat assessment
python cli.py shell                               # Interactive REPL
```

### TUI (Terminal UI)

```bash
python tui.py
```

Eight tabs — switch with keys **1–8**:

| Key | Tab | Contents |
|---|---|---|
| 1 | **Status** | Server health, uptime, environment |
| 2 | **Query** | Send queries to the AI agent |
| 3 | **Tools** | List all 11 registered agent tools |
| 4 | **Metrics** | ML/agent/incident stats, background investigations |
| 5 | **IoC** | VirusTotal + AbuseIPDB lookup |
| 6 | **MITRE** | Technique search |
| 7 | **Incidents** | List incidents + trigger AI investigation |
| 8 | **Assess** | Manual ThreatAssessment with signal sliders |

---

## Docker

```bash
docker-compose up -d
docker-compose logs -f ir-agent
```

---

## Project Structure

```
Ir_agent/
├── app/
│   ├── main.py
│   ├── routers/
│   │   ├── ingest.py              # /ingest/telemetry + incident endpoints
│   │   ├── agent.py               # /agent/query, /agent/query/stream
│   │   ├── assessment.py          # /assessment/analyze
│   │   └── ...
│   ├── agent/
│   │   ├── core/agent.py          # CyberAgent — ReAct loop
│   │   └── tools/
│   │       ├── get_incident.py        # NEW: query full incident
│   │       ├── get_incident_events.py # NEW: raw events with phase filter
│   │       ├── knowledge_search.py
│   │       ├── mitre_lookup.py
│   │       ├── lookup_ioc.py
│   │       └── ...
│   ├── services/
│   │   ├── event_processor.py     # ML pipeline + incident correlation
│   │   ├── incident_manager.py    # Correlation engine, timeline, IoC, MITRE
│   │   ├── agent_service.py       # Agent singleton, 11 tools registered
│   │   └── ...
│   ├── assessment/
│   │   └── threat_assessment.py   # 4-signal Bayesian fusion, 7 arbitration rules
│   └── db/
│       ├── models.py              # SecurityEvent, Incident, IoC ORM models
│       ├── event_store.py         # Async CRUD
│       └── database.py
├── alembic/                       # Migrations (including agent_analysis_json)
├── tests/                         # 128 tests
├── tui.py                         # Textual full-screen TUI
├── cli.py
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LLM_API_KEY` | — | Groq API key (required for AI) |
| `LLM_PROVIDER` | `groq` | Primary LLM provider |
| `LLM_ANALYZER_MODEL` | `llama-3.3-70b-versatile` | Model for agent analysis |
| `MY_API_TOKEN` | — | Bearer token (required in production) |
| `ENVIRONMENT` | `production` | `development` = no auth + /docs enabled |
| `DATABASE_URL` | `sqlite+aiosqlite:///./ir_agent.db` | DB connection |
| `VIRUSTOTAL_API_KEY` | — | IoC lookups |
| `ABUSEIPDB_API_KEY` | — | IP reputation lookups |
| `BETTER_STACK_SOURCE_TOKEN` | — | Log shipping |
| `AI_SUSPICIOUS_THRESHOLD` | `60` | ML threshold (0–100) |
| `API_PORT` | `9000` | HTTP listen port |

Full list: [`.env.example`](.env.example)

---

## Testing

```bash
pip install -r requirements-dev.txt

# Run all unit tests (no external services needed)
pytest tests/ -k "not API" -v

# Run everything including API integration tests
pytest tests/ -v

# Single module
pytest tests/test_incident_investigation.py -v
pytest tests/test_comprehensive.py -v
```

**128 tests** across 11 modules:

| Module | Tests | Covers |
|---|---|---|
| `test_incident_investigation.py` | 22 | Incident correlation, GetIncidentTool, GetIncidentEventsTool, API endpoints |
| `test_comprehensive.py` | 46 | ThreatAssessmentEngine (16), IoC extraction (6), root cause (5), impact (4), recommendations (5), misc (7), edge cases (3) |
| `test_event_processor.py` | 9 | ML pipeline, event enrichment, metrics |
| `test_ml_detector.py` | 10 | ML classifier, heuristics, features |
| `test_api_ingest.py` | 10 | Ingest endpoint contract |
| `test_api_ml.py` | 8 | ML API |
| `test_agent_fixes.py` | 7 | Agent response parsing |
| `test_health.py` | 6 | Health/readiness probes |
| `test_middleware.py` | 5 | Auth, rate limiting |
| `test_config.py` | 3 | Settings validation |

---

## Documentation

| Document | Description |
|---|---|
| [INVESTIGATION_GUIDE.md](INVESTIGATION_GUIDE.md) | Step-by-step investigation workflows |
| [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md) | ML model training, features, MITRE mapping |
| [DIPLOMA_DOCUMENTATION.md](DIPLOMA_DOCUMENTATION.md) | Full diploma-defence documentation (RU) |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## License

MIT License
