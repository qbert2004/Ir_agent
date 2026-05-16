"""
Full IR-Agent demo: send attack events -> show pipeline -> AI investigation.
Run with: python -X utf8 full_demo.py
"""
import httpx
import json
import time

BASE = "http://localhost:9000"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer WAhV9fBn2sRyuOXLv6MNlwT4gHFbYKPS",
}

SEP = "=" * 70


def section(title, data=None):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)
    if data is not None:
        if isinstance(data, str):
            print(data)
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))


def main():
    client = httpx.Client(timeout=30)

    # 1. Health
    r = client.get(f"{BASE}/health", headers=HEADERS)
    section("1. HEALTH CHECK", r.json())

    # 2. ML model status  (correct endpoint)
    r = client.get(f"{BASE}/ingest/ml/status", headers=HEADERS)
    section("2. ML MODEL STATUS", r.json())

    # 3. Send 3 correlated attack events
    events = [
        {   # PowerShell encoded command
            "timestamp": "2026-05-16T10:00:00Z",
            "event_id": 4688,
            "hostname": "WS-VICTIM01",
            "process_name": "powershell.exe",
            "command_line": "powershell -enc aQBuAHYAbwBrAGUALQBleHByZXNzaW9u",
            "user": "john.doe",
        },
        {   # Mimikatz credential dump
            "timestamp": "2026-05-16T10:01:00Z",
            "event_id": 4688,
            "hostname": "WS-VICTIM01",
            "process_name": "mimikatz.exe",
            "command_line": "sekurlsa::logonpasswords",
            "user": "john.doe",
        },
        {   # Lateral movement — new logon from suspicious IP
            "timestamp": "2026-05-16T10:03:00Z",
            "event_id": 4624,
            "hostname": "WS-VICTIM01",
            "process_name": "lsass.exe",
            "command_line": "",
            "user": "SYSTEM",
            "source_ip": "185.220.101.45",
        },
    ]

    for i, ev in enumerate(events, 1):
        r = client.post(f"{BASE}/ingest/telemetry", headers=HEADERS, json=ev)
        section(f"3.{i}. EVENT SENT ({ev['process_name']})", r.json())
        time.sleep(0.5)

    time.sleep(2)

    # 4. List incidents
    r = client.get(f"{BASE}/ingest/incidents", headers=HEADERS)
    data = r.json()
    section("4. INCIDENTS LIST", data)

    incidents = data.get("incidents", [])
    if not incidents:
        print("No incidents created.")
        client.close()
        return

    inc_id = incidents[0]["id"]
    print(f"\n  [*] Active incident: {inc_id}")

    # 5. Incident detail: timeline + IoC + MITRE
    r = client.get(f"{BASE}/ingest/incidents/{inc_id}", headers=HEADERS)
    section("5. INCIDENT DETAIL (timeline, IoC, MITRE)", r.json())

    # 6. ML classify mimikatz event directly (correct wrapper: {"event": ...})
    r = client.post(
        f"{BASE}/ml/classify",
        headers=HEADERS,
        json={"event": events[1]},
        timeout=30,
    )
    section("6. ML CLASSIFY (mimikatz event)", r.json())

    # 7. Agent query (correct field: "query")
    print(f"\n{SEP}\n  7. AGENT QUERY (T1003.001 MITRE)\n{SEP}")
    print("  Querying LLM agent (may take 30-90s)...")
    try:
        r = client.post(
            f"{BASE}/agent/query",
            headers=HEADERS,
            json={"query": "What is T1003.001 (mimikatz LSASS dump)? How to detect and respond?"},
            timeout=120,
        )
        print(json.dumps(r.json(), indent=2, ensure_ascii=False))
    except httpx.ReadTimeout:
        print("  LLM API timeout. Investigation continues in background.")

    # 8. Text report
    r = client.get(f"{BASE}/ingest/incidents/{inc_id}/report", headers=HEADERS)
    report_text = r.json().get("report", r.text)
    section("8. INCIDENT REPORT (rule-based)", report_text)

    # 9. AI investigation (may take 30-180s depending on LLM latency)
    print(f"\n{SEP}\n  9. AI AGENT INVESTIGATION\n{SEP}")
    print("  ReAct loop, 11 tools, up to 8 steps, timeout=180s...")
    try:
        r = client.post(
            f"{BASE}/ingest/incidents/{inc_id}/investigate",
            headers=HEADERS,
            timeout=200,
        )
        print(json.dumps(r.json(), indent=2, ensure_ascii=False))
    except httpx.ReadTimeout:
        print("  LLM API timeout (>180s). Investigation continues in background.")
        print(f"  Check status: GET {BASE}/ingest/incidents/{inc_id}")

    client.close()
    print(f"\n{SEP}")
    print("  DEMO COMPLETE")
    print(f"  Swagger UI: http://localhost:9000/docs")
    print(f"  Dashboard:  http://localhost:9000/dashboard")
    print(SEP)


if __name__ == "__main__":
    main()
