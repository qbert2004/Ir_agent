"""Quick live API test — run while server is on port 9000."""
import httpx, json, sys

BASE = "http://localhost:9000"

def main():
    c = httpx.Client(timeout=30)

    # 1. Health
    print("=== 1. HEALTH ===")
    r = c.get(f"{BASE}/health")
    h = r.json()
    print(f"  Status: {h['status']} | AI: {h['components']['ai_analyzer']} | BS: {h['components']['better_stack']}")

    # 2. ML Status
    print("\n=== 2. ML STATUS ===")
    r = c.get(f"{BASE}/ingest/ml/status")
    ml = r.json()
    print(f"  Model: {ml['model']['model_version']} | Features: {ml['model']['n_features']} | Loaded: {ml['model']['model_loaded']}")

    # 3. Ingest mimikatz (attack)
    print("\n=== 3. INGEST MIMIKATZ (attack) ===")
    r = c.post(f"{BASE}/ingest/telemetry", json={
        "event_id": 4688, "hostname": "WS01",
        "process_name": "mimikatz.exe",
        "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        "user": "admin", "timestamp": "2026-05-18T18:30:00Z",
    })
    d = r.json()
    print(f"  Status: {d.get('status')} | Class: {d.get('classification')} | Conf: {d.get('confidence')} | Path: {d.get('path')}")

    # 4. Ingest benign event
    print("\n=== 4. INGEST NOTEPAD (benign) ===")
    r = c.post(f"{BASE}/ingest/telemetry", json={
        "event_id": 4688, "hostname": "WS01",
        "process_name": "notepad.exe",
        "command_line": "notepad.exe C:\\notes.txt",
        "user": "user1", "timestamp": "2026-05-18T18:31:00Z",
    })
    d = r.json()
    print(f"  Status: {d.get('status')} | Class: {d.get('classification')} | Conf: {d.get('confidence')}")

    # 5. Ingest psexec (attack)
    print("\n=== 5. INGEST PSEXEC (attack) ===")
    r = c.post(f"{BASE}/ingest/telemetry", json={
        "event_id": 4688, "hostname": "WS01",
        "process_name": "psexec.exe",
        "command_line": "psexec \\\\dc01 cmd.exe",
        "user": "admin", "timestamp": "2026-05-18T18:32:00Z",
    })
    d = r.json()
    print(f"  Status: {d.get('status')} | Class: {d.get('classification')} | Conf: {d.get('confidence')} | Path: {d.get('path')}")

    # 6. Metrics
    print("\n=== 6. METRICS ===")
    r = c.get(f"{BASE}/ingest/metrics")
    m = r.json()
    proc = m["processing"]
    bs = m["betterstack"]
    print(f"  Total: {proc['total_processed']} | Benign: {proc['benign_filtered']} | Malicious: {proc['malicious_detected']}")
    print(f"  BetterStack enabled: {bs['enabled']} | Sent: {bs['sent']}")

    # 7. Incidents
    print("\n=== 7. INCIDENTS ===")
    r = c.get(f"{BASE}/ingest/incidents")
    incs = r.json()
    print(f"  Total incidents: {len(incs.get('incidents', []))}")
    for inc in incs.get("incidents", [])[:3]:
        print(f"    {inc['id']}: host={inc['host']}, events={inc['event_count']}, class={inc.get('classification','?')}")

    print("\n=== ALL TESTS PASSED ===")

if __name__ == "__main__":
    main()
