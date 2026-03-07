# IR-Agent API Reference

Base URL: `http://localhost:9000` (development) | `https://ir-agent.yourdomain.com` (production)

## Authentication

All endpoints except health probes require a Bearer token:

```
Authorization: Bearer <MY_API_TOKEN>
```

Set `MY_API_TOKEN` in `.env`. In `ENVIRONMENT=development` the token check is skipped.

Public endpoints (no auth): `GET /`, `GET /health`, `GET /health/live`, `GET /health/ready`

---

## Table of Contents

1. [Health & Observability](#1-health--observability)
2. [Event Ingest](#2-event-ingest)
3. [Incident Management](#3-incident-management)
4. [AI Agent](#4-ai-agent)
5. [ML Investigation](#5-ml-investigation)
6. [Threat Assessment](#6-threat-assessment)
7. [Report](#7-report)
8. [Investigation](#8-investigation)

---

## 1. Health & Observability

### `GET /health`

Full component health check.

**Response 200**
```json
{
  "status": "healthy",
  "timestamp": "2026-03-05T10:00:00Z",
  "service": "IR-Agent",
  "version": "1.0.0",
  "environment": "development",
  "components": {
    "ai_analyzer": "enabled",
    "better_stack": "disabled"
  },
  "config": {
    "ai_model": "llama-3.3-70b-versatile",
    "ai_threshold": 60
  }
}
```

---

### `GET /health/live`

Liveness probe — is the process running?

**Response 200**
```json
{"status": "alive"}
```

---

### `GET /health/ready`

Readiness probe — can the service accept traffic?

**Response 200** (ready)
```json
{
  "status": "ready",
  "components": {
    "database": true,
    "ml_model": true,
    "ai_analyzer": true,
    "better_stack": false
  }
}
```

**Response 503** (not ready — database unreachable)
```json
{
  "status": "not_ready",
  "components": {"database": false, ...}
}
```

---

### `GET /health/ml`

ML pipeline status: model loaded, drift detector, recent stats.

**Response 200**
```json
{
  "timestamp": "2026-03-05T10:00:00Z",
  "ml_model": {
    "loaded": true,
    "model_type": "GradientBoostingClassifier",
    "features": 47,
    "accuracy": 0.94
  },
  "drift": {
    "status": "ok",
    "drift_detected": false
  }
}
```

---

### `GET /metrics`

Prometheus-format metrics for scraping.

**Response 200** (`text/plain; version=0.0.4`)
```
# HELP ir_agent_events_total Total events processed
# TYPE ir_agent_events_total counter
ir_agent_events_total 1547

# HELP ir_agent_malicious_detected_total Malicious events detected
# TYPE ir_agent_malicious_detected_total counter
ir_agent_malicious_detected_total 23
...
```

---

## 2. Event Ingest

### `POST /ingest/telemetry`

Ingest one or multiple security events through the hybrid ML + Agent pipeline.

Processing flow:
- Score `< 0.50` → **BENIGN**, discarded
- Score `0.50–0.80` → **UNCERTAIN**, deep-path CyberAgent analysis
- Score `> 0.80` → **HIGH CONFIDENCE MALICIOUS**, fast-path to Better Stack

Events are processed asynchronously in the background. The endpoint returns immediately.

**Request body** — single event:
```json
{
  "timestamp": "2026-03-05T08:37:00Z",
  "hostname": "srv-01",
  "process_name": "mimikatz.exe",
  "event_type": "process_creation",
  "command_line": "mimikatz.exe sekurlsa::logonpasswords",
  "parent_image": "cmd.exe",
  "user": "DOMAIN\\jsmith",
  "source_ip": "10.0.0.15"
}
```

**Request body** — batch (array):
```json
[
  {"timestamp": "...", "process_name": "mimikatz.exe", ...},
  {"timestamp": "...", "process_name": "psexec.exe", ...}
]
```

**Response 200**
```json
{
  "status": "success",
  "received": 2,
  "message": "Processing 2 events through hybrid ML+Agent pipeline",
  "processor_ready": true
}
```

---

### `POST /ingest/event`

Alias for `/ingest/telemetry`. Same request/response format.

---

### `GET /ingest/metrics`

Event processing counters.

**Response 200**
```json
{
  "status": "success",
  "processing": {
    "total_processed": 1547,
    "benign_filtered": 1210,
    "malicious_detected": 337,
    "filter_rate": 0.782
  },
  "paths": {
    "fast_path_count": 289,
    "deep_path_count": 48,
    "deep_path_rate": 0.031,
    "agent_invocations": 48
  },
  "betterstack": {
    "sent": 310,
    "failed": 0
  },
  "ml_model": {"loaded": true},
  "last_event": "2026-03-05T10:00:00Z"
}
```

---

### `POST /ingest/metrics/reset`

Reset all processing metrics to zero.

**Response 200**
```json
{"status": "success", "message": "Metrics reset"}
```

---

### `GET /ingest/ml/status`

ML model and processor status with threshold configuration.

**Response 200**
```json
{
  "status": "ready",
  "model": {"loaded": true, "model_type": "GradientBoostingClassifier"},
  "thresholds": {
    "benign": 0.5,
    "certain": 0.8
  },
  "processing_modes": {
    "fast_path": "ML only, ~5ms, confidence >=80%",
    "deep_path": "CyberAgent analysis, ~1-2s, confidence 50-80%"
  }
}
```

---

## 3. Incident Management

### `GET /ingest/incidents`

List all correlated incidents.

**Response 200**
```json
{
  "status": "success",
  "incidents": [
    {
      "incident_id": "INC-20260305-001",
      "type": "lateral_movement",
      "severity": "HIGH",
      "event_count": 7,
      "created_at": "2026-03-05T08:30:00Z"
    }
  ],
  "stats": {
    "total": 1,
    "open": 1,
    "closed": 0
  }
}
```

---

### `GET /ingest/incidents/{incident_id}`

Get details for a specific incident.

**Path parameters**: `incident_id` — incident identifier

**Response 200**
```json
{
  "status": "success",
  "incident": {
    "incident_id": "INC-20260305-001",
    "type": "lateral_movement",
    "severity": "HIGH",
    "events": [...],
    "timeline": [...],
    "iocs": ["10.0.0.15", "psexec.exe"]
  }
}
```

**Response 200** (not found)
```json
{"status": "error", "message": "Incident INC-xxx not found"}
```

---

### `POST /ingest/incidents/{incident_id}/investigate`

Run full AI investigation on a correlated incident.

Performs: timeline reconstruction, IoC extraction, MITRE ATT&CK mapping, classification, root cause analysis, impact assessment, response recommendations.

**Response 200**
```json
{
  "status": "success",
  "investigation": {
    "incident_id": "INC-20260305-001",
    "classification": "lateral_movement",
    "mitre_techniques": ["T1021.002", "T1078"],
    "root_cause": "Compromised admin credentials used for PsExec lateral movement",
    "impact": "3 systems compromised, domain admin credentials exposed",
    "recommendations": [
      "Isolate affected systems",
      "Reset all privileged account passwords",
      "Review PsExec usage policies"
    ]
  }
}
```

---

### `GET /ingest/incidents/{incident_id}/report`

Get human-readable investigation report.

**Response 200**
```json
{
  "status": "success",
  "report": "INCIDENT INVESTIGATION REPORT\n\nIncident ID: INC-20260305-001\n..."
}
```

---

## 4. AI Agent

### `POST /agent/query`

Send a query to the CyberAgent (non-streaming). Waits for full ReAct loop to complete.

**Request body**
```json
{
  "query": "Is mimikatz.exe malicious? What MITRE techniques does it map to?",
  "session_id": "optional-session-id-for-memory"
}
```

**Response 200**
```json
{
  "answer": "Yes, mimikatz.exe is highly malicious...",
  "session_id": "abc123def456",
  "steps": [
    {
      "step_number": 1,
      "thought": "I need to check if mimikatz.exe is a known malicious tool",
      "action": "knowledge_search",
      "observation": "mimikatz is a credential-dumping tool..."
    },
    {
      "step_number": 2,
      "thought": "I should check MITRE techniques for credential dumping",
      "action": "mitre_lookup",
      "observation": "T1003 - OS Credential Dumping..."
    }
  ],
  "tools_used": ["knowledge_search", "mitre_lookup", "ioc_check"],
  "total_steps": 3
}
```

**Response 504** (agent timeout)
```json
{
  "detail": "Agent timed out. The investigation exceeded the maximum allowed time. Try a simpler query or increase AGENT_TIMEOUT_SECONDS."
}
```

---

### `POST /agent/query/stream`

Streaming agent query — returns NDJSON events as the agent reasons.

**Request body** — same as `/agent/query`

**Response** — `application/x-ndjson` stream

Each line is a JSON object (one per newline):

```
{"type":"step","step":1,"thought":"I need to look up mimikatz...","action":"knowledge_search","observation":"mimikatz is a credential dumping tool..."}
{"type":"step","step":2,"thought":"Now checking MITRE techniques...","action":"mitre_lookup","observation":"T1003.001: LSASS Memory"}
{"type":"answer","answer":"mimikatz.exe is a well-known credential dumping tool...","tools_used":["knowledge_search","mitre_lookup"],"total_steps":2}
```

Event types:

| Type | Fields | Description |
|---|---|---|
| `step` | `step`, `thought`, `action`, `observation` | One ReAct reasoning step |
| `answer` | `answer`, `tools_used`, `total_steps` | Final answer |
| `error` | `error` | Timeout or agent failure |

**Response headers**:
```
X-Session-ID: abc123def456
Content-Type: application/x-ndjson
```

**curl example**:
```bash
curl -N -X POST http://localhost:9000/agent/query/stream \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "Analyze lateral movement via PsExec"}'
```

---

### `GET /agent/tools`

List all available agent tools.

**Response 200**
```json
[
  {
    "name": "knowledge_search",
    "description": "Search the cybersecurity knowledge base for relevant information"
  },
  {
    "name": "mitre_lookup",
    "description": "Look up MITRE ATT&CK techniques, tactics and procedures"
  },
  {
    "name": "ioc_check",
    "description": "Check IP addresses, domains, and file hashes against threat intelligence"
  },
  {
    "name": "ml_analyze",
    "description": "Run ML classifier on security events"
  },
  {
    "name": "incident_timeline",
    "description": "Build attack timeline from security events"
  },
  {
    "name": "threat_assessment",
    "description": "Compute unified threat score from available signals"
  },
  {
    "name": "report_generate",
    "description": "Generate structured investigation report"
  },
  {
    "name": "web_search",
    "description": "Search the web for threat intelligence and CVEs"
  },
  {
    "name": "calculate",
    "description": "Perform calculations and data transformations"
  }
]
```

---

### `GET /agent/sessions/{session_id}/history`

Get conversation history for a session.

**Response 200**
```json
{
  "session_id": "abc123def456",
  "history": [
    {"role": "user", "content": "Is mimikatz.exe malicious?"},
    {"role": "assistant", "content": "Yes, mimikatz.exe is..."}
  ]
}
```

---

### `DELETE /agent/sessions/{session_id}`

Clear session memory.

**Response 200**
```json
{"status": "cleared", "session_id": "abc123def456"}
```

---

### `POST /agent/ingest`

Ingest a knowledge document into the vector database.

**Request body**
```json
{
  "title": "CVE-2024-1234 Analysis",
  "content": "This vulnerability affects...",
  "source": "internal-research"
}
```

**Response 200**
```json
{
  "status": "ingested",
  "title": "CVE-2024-1234 Analysis",
  "chunks_added": 4
}
```

---

### `GET /agent/knowledge/stats`

Knowledge base and agent memory statistics.

**Response 200**
```json
{
  "total_vectors": 1247,
  "document_count": 89,
  "active_sessions": 3,
  "session_max_size": 1000
}
```

---

## 5. ML Investigation

### `POST /ml/investigate`

Run full ML-based incident investigation on a batch of events.

**Request body**
```json
{
  "incident_id": "INC-2026-001",
  "events": [
    {
      "timestamp": "2026-03-05T08:37:00Z",
      "hostname": "srv-01",
      "process_name": "mimikatz.exe",
      "event_type": "process_creation",
      "command_line": "mimikatz sekurlsa::logonpasswords"
    },
    {
      "timestamp": "2026-03-05T08:40:00Z",
      "hostname": "srv-02",
      "process_name": "psexec.exe",
      "event_type": "process_creation"
    }
  ]
}
```

**Response 200**
```json
{
  "incident_id": "INC-2026-001",
  "incident_type": "credential_theft",
  "incident_type_confidence": 0.87,
  "threat_level": "HIGH",
  "threat_score": 78.4,
  "total_events": 2,
  "malicious_events": 2,
  "techniques_count": 3,
  "iocs_count": 2,
  "mitre_techniques": [
    {"id": "T1003", "name": "OS Credential Dumping", "confidence": 0.9},
    {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "confidence": 0.75}
  ],
  "iocs": ["mimikatz.exe", "psexec.exe"],
  "timeline": [
    {"time": "08:37:00", "event": "Credential dump via mimikatz"},
    {"time": "08:40:00", "event": "Lateral movement via PsExec"}
  ],
  "report": "## Incident Investigation Report\n\n..."
}
```

---

### `POST /ml/classify`

Classify a single security event.

**Request body**
```json
{
  "event": {
    "process_name": "mimikatz.exe",
    "command_line": "sekurlsa::logonpasswords",
    "event_type": "process_creation"
  }
}
```

**Response 200**
```json
{
  "classification": "malicious",
  "confidence": 0.94,
  "reason": "Known credential dumping tool",
  "threat_type": "credential_theft",
  "mitre_techniques": ["T1003"]
}
```

---

### `POST /ml/mitre`

Map a security event to MITRE ATT&CK techniques.

**Request body**
```json
{
  "event": {
    "process_name": "mimikatz.exe",
    "command_line": "lsadump::sam"
  }
}
```

**Response 200**
```json
{
  "techniques": [
    {
      "id": "T1003",
      "name": "OS Credential Dumping",
      "tactic": "credential_access",
      "confidence": 0.95,
      "description": "Adversaries attempt to dump credentials..."
    },
    {
      "id": "T1003.002",
      "name": "Security Account Manager",
      "tactic": "credential_access",
      "confidence": 0.88
    }
  ]
}
```

---

### `GET /ml/models`

Get ML model metadata and performance metrics.

**Response 200**
```json
{
  "event_classifier": {
    "loaded": true,
    "model_type": "GradientBoostingClassifier",
    "features": 47,
    "training_samples": 12500,
    "accuracy": 0.94,
    "f1_score": 0.91
  },
  "mitre_techniques_count": 247,
  "knowledge_patterns": 89
}
```

---

## 6. Threat Assessment

### `POST /assessment/analyze`

Run unified threat assessment from pre-computed signals.

All signal fields are optional. Provide at least one.

**Request body**
```json
{
  "ml": {
    "score": 0.87,
    "is_malicious": true,
    "reason": "mimikatz credential dump pattern",
    "model_loaded": true
  },
  "ioc": {
    "score": 0.9,
    "is_malicious": true,
    "providers_hit": ["VirusTotal", "AbuseIPDB"],
    "indicator_count": 3
  },
  "mitre": {
    "techniques": [
      {"id": "T1003", "name": "OS Credential Dumping", "confidence": 0.9}
    ],
    "tactic_coverage": ["credential_access"],
    "max_confidence": 0.9,
    "has_lateral_movement": false,
    "has_credential_access": true,
    "has_impact": false
  },
  "agent": {
    "verdict": "MALICIOUS",
    "confidence": 0.92,
    "tools_used": ["mitre_lookup", "ioc_check"],
    "reasoning_steps": 4
  },
  "context": {
    "hostname": "srv-01",
    "user": "DOMAIN\\jsmith"
  }
}
```

**Response 200**
```json
{
  "final_score": 91.2,
  "severity": "CRITICAL",
  "confidence_level": "HIGH",
  "score_breakdown": {
    "ml": 30.45,
    "ioc": 27.0,
    "mitre": 18.0,
    "agent": 13.8,
    "arbitration": 2.0
  },
  "sources_available": ["ml", "ioc", "mitre", "agent"],
  "sources_agreeing": ["ml", "ioc", "mitre", "agent"],
  "arbitration_rules": ["R1: >=2 IoC providers confirmed malicious → score forced >=85"],
  "explanation": "CRITICAL threat (91.2/100). All 4 signals agree malicious. R1 fired: 2 IoC providers confirmed.",
  "explanation_trace": [
    "ML score 0.87 → weighted 30.45",
    "IoC score 0.90, providers=[VirusTotal,AbuseIPDB] → weighted 27.0",
    "MITRE: 1 technique, credential_access → weighted 18.0",
    "Agent: MALICIOUS (confidence=0.92) → weighted 13.8",
    "R1 fired: score forced to max(85, 88.25) = 91.2"
  ],
  "recommended_action": "IMMEDIATE ISOLATION: Block at firewall, isolate host, engage IR team"
}
```

**Signal weights** (for reference):

| Signal | Weight | Notes |
|---|---|---|
| ML | 35% | GradientBoosting classifier |
| IoC | 30% | VirusTotal + AbuseIPDB aggregated |
| MITRE | 20% | Technique density + tactic coverage |
| Agent | 15% | LLM verdict (lowest — LLMs can hallucinate) |

---

### `POST /assessment/analyze/event`

Run assessment directly from a raw security event (ML + MITRE signals extracted automatically).

**Request body**
```json
{
  "event": {
    "process_name": "mimikatz.exe",
    "command_line": "sekurlsa::logonpasswords",
    "hostname": "srv-01"
  },
  "run_ml": true,
  "run_mitre": true
}
```

**Response 200** — same structure as `/assessment/analyze`

---

### `GET /assessment/explain/{score}`

Explain what a numeric score means.

**Path parameters**: `score` — float 0–100

**Example**: `GET /assessment/explain/72`

**Response 200**
```json
{
  "score": 72.0,
  "severity": "HIGH",
  "severity_range": "65-84",
  "description": "Significant threat requiring analyst attention within 1 hour",
  "actions": {
    "high_confidence": "Escalate to SOC analyst, block at firewall",
    "medium_confidence": "Investigate within 1 hour, apply containment measures",
    "low_confidence": "Flag for review, monitor for recurrence"
  }
}
```

---

### `GET /assessment/schema`

ThreatAssessment engine configuration, weights, thresholds, and arbitration rules.

**Response 200**
```json
{
  "version": "1.0",
  "signal_weights": {
    "ml":    {"weight": 0.35, "description": "GradientBoosting ML classifier score"},
    "ioc":   {"weight": 0.30, "description": "IoC lookup aggregated score"},
    "mitre": {"weight": 0.20, "description": "MITRE ATT&CK technique density and tactic coverage"},
    "agent": {"weight": 0.15, "description": "LLM ReAct agent verdict"}
  },
  "severity_thresholds": {
    "critical": {"min": 85, "max": 100, "response": "Immediate"},
    "high":     {"min": 65, "max": 84,  "response": "Within 1 hour"},
    "medium":   {"min": 45, "max": 64,  "response": "Within business hours"},
    "low":      {"min": 25, "max": 44,  "response": "Monitor"},
    "info":     {"min": 0,  "max": 24,  "response": "No action"}
  },
  "arbitration_rules": [
    {"id": "R1", "type": "escalation", "description": ">=2 IoC providers confirmed malicious → score forced >=85"},
    {"id": "R2", "type": "escalation", "description": "Credential dump pattern in ML reason → score >=80"},
    {"id": "R3", "type": "escalation", "description": "MITRE lateral_movement + credential_access → score >=65"},
    {"id": "R4", "type": "escalation", "description": "MITRE impact tactic → score >=65"},
    {"id": "R5", "type": "bonus",      "description": "All 3+ sources agree malicious → +10% bonus"},
    {"id": "R6", "type": "downgrade",  "description": "Agent HIGH_CONFIDENCE FALSE_POSITIVE + ML<0.6 → score capped at 25"},
    {"id": "R7", "type": "downgrade",  "description": "IoC clean + Agent FALSE_POSITIVE + ML uncertain → score capped at 40"}
  ]
}
```

---

## 7. Report

### `GET /report`

Get list of investigation reports.

**Response 200**
```json
{
  "reports": [
    {"id": "RPT-001", "incident_id": "INC-001", "created_at": "2026-03-05T10:00:00Z"}
  ]
}
```

---

### `POST /report/generate`

Generate a structured investigation report using LLM.

**Request body**
```json
{
  "incident_id": "INC-2026-001",
  "investigation_data": {
    "classification": "credential_theft",
    "timeline": [...],
    "iocs": [...],
    "mitre_techniques": [...]
  }
}
```

**Response 200**
```json
{
  "report_id": "RPT-001",
  "incident_id": "INC-2026-001",
  "report": "## INCIDENT INVESTIGATION REPORT\n\n..."
}
```

---

## 8. Investigation

### `POST /investigation/start`

Start a full AI-powered investigation from a list of events.

**Request body**
```json
{
  "incident_id": "INC-2026-001",
  "events": [
    {
      "timestamp": "2026-03-05T08:37:00Z",
      "hostname": "srv-01",
      "process_name": "mimikatz.exe",
      "event_type": "process_creation"
    }
  ]
}
```

**Response 200**
```json
{
  "status": "started",
  "incident_id": "INC-2026-001",
  "investigation_id": "INV-abc123"
}
```

---

### `GET /investigation/{incident_id}/report`

Get the investigation report for an incident.

**Response 200**
```json
{
  "incident_id": "INC-2026-001",
  "report": {
    "title": "Credential Theft via mimikatz",
    "classification": "credential_theft",
    "severity": "HIGH",
    "executive_summary": "...",
    "timeline": [...],
    "iocs": [...],
    "mitre_techniques": [...],
    "root_cause": "...",
    "impact": "...",
    "recommendations": [...]
  }
}
```

---

## Error Responses

| Status | Meaning |
|---|---|
| `400 Bad Request` | Invalid request body |
| `401 Unauthorized` | Missing or invalid `Authorization` header |
| `404 Not Found` | Resource not found |
| `422 Unprocessable Entity` | Validation error (see `detail` field) |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Unexpected server error |
| `503 Service Unavailable` | Service not ready (database down, etc.) |
| `504 Gateway Timeout` | Agent timed out (increase `AGENT_TIMEOUT_SECONDS`) |

All error responses follow the FastAPI format:
```json
{
  "detail": "Human-readable error description"
}
```

---

## Rate Limits

Default: **60 requests/minute per IP** (configurable via `RATE_LIMIT_PER_MINUTE`).

When exceeded:
```
HTTP 429 Too Many Requests
```

For multi-instance deployments, set `REDIS_URL` for shared rate-limiting.

---

## Streaming Events Reference

`POST /agent/query/stream` emits NDJSON events — one JSON object per line.

### Step event
```json
{
  "type": "step",
  "step": 1,
  "thought": "I need to check if this IP is malicious",
  "action": "ioc_check",
  "observation": "185.220.101.45 is flagged by VirusTotal (72/90 engines)"
}
```

### Answer event
```json
{
  "type": "answer",
  "answer": "The IP 185.220.101.45 is a known Tor exit node...",
  "tools_used": ["ioc_check", "mitre_lookup"],
  "total_steps": 3
}
```

### Error event
```json
{
  "type": "error",
  "error": "Agent timed out. Try a simpler query or increase AGENT_TIMEOUT_SECONDS."
}
```

### Client implementation (Python)

```python
import httpx
import json

with httpx.stream("POST", "http://localhost:9000/agent/query/stream",
                  json={"query": "Is mimikatz.exe malicious?"},
                  headers={"Authorization": "Bearer <token>"},
                  timeout=120) as resp:
    buf = ""
    for chunk in resp.iter_text():
        buf += chunk
        lines = buf.split("\n")
        buf = lines.pop()
        for line in lines:
            if line.strip():
                event = json.loads(line)
                if event["type"] == "step":
                    print(f"Step {event['step']}: {event['action']}")
                elif event["type"] == "answer":
                    print(f"Answer: {event['answer']}")
```

### Client implementation (JavaScript / fetch)

```javascript
const resp = await fetch('/agent/query/stream', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  },
  body: JSON.stringify({ query: 'Is mimikatz.exe malicious?' }),
});

const reader = resp.body.getReader();
const decoder = new TextDecoder();
let buf = '';

while (true) {
  const { value, done } = await reader.read();
  if (done) break;
  buf += decoder.decode(value, { stream: true });
  const lines = buf.split('\n');
  buf = lines.pop();
  for (const line of lines) {
    if (line.trim()) {
      const event = JSON.parse(line);
      console.log(event);
    }
  }
}
```
