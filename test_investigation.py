"""Test full investigation pipeline: attack chain -> incident -> report"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import app.services.ml_detector as md; md._detector = None
import app.services.event_processor as ep; ep._processor = None
import app.services.incident_manager as im; im._manager = None

from app.services.event_processor import get_event_processor
from app.services.incident_manager import get_incident_manager

processor = get_event_processor()
manager = get_incident_manager()

attack_chain = [
    {"timestamp": "2026-02-27T10:39:04Z", "event_id": 4688, "channel": "Security",
     "hostname": "WIN-SRV01", "process_name": "powershell.exe", "user": "admin",
     "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
    {"timestamp": "2026-02-27T10:39:08Z", "event_id": 3, "channel": "Sysmon",
     "hostname": "WIN-SRV01", "process_name": "powershell.exe", "user": "admin",
     "destination_ip": "185.213.100.50", "destination_port": 4444,
     "command_line": "powershell.exe"},
    {"timestamp": "2026-02-27T10:39:12Z", "event_id": 4698, "channel": "Security",
     "hostname": "WIN-SRV01", "process_name": "schtasks.exe", "user": "admin",
     "command_line": "schtasks /create /sc onstart /tn WindowsUpdate /tr update.bat /ru SYSTEM"},
    {"timestamp": "2026-02-27T10:39:16Z", "event_id": 7045, "channel": "System",
     "hostname": "WIN-SRV01", "process_name": "services.exe", "user": "SYSTEM",
     "service_file": "C:/temp/backdoor.exe", "command_line": "services.exe"},
    {"timestamp": "2026-02-27T10:39:20Z", "event_id": 4688, "channel": "Security",
     "hostname": "WIN-SRV01", "process_name": "mimikatz.exe", "user": "admin",
     "command_line": "mimikatz.exe sekurlsa::logonpasswords"},
]

async def run():
    print("Processing attack chain...")
    for event in attack_chain:
        result = await processor.classify_and_forward(event)
        print(f'  [{result.get("confidence",0):.0%}] {event["process_name"]} -> {result["status"]}')

    incidents = manager.list_incidents()
    print(f"\nIncidents created: {len(incidents)}")

    if incidents:
        iid = incidents[0]["id"]
        print(f"Investigating: {iid}\n")
        manager.investigate(iid)
        report = manager.get_report(iid)
        print(report)

asyncio.run(run())
