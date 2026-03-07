"""
Behaviorally Realistic Benign Sysmon Event Generator
=====================================================
Generates benign Windows Sysmon events for EIDs that currently appear
ONLY in malicious data (6, 7, 12, 13) and reinforces benign patterns
for shared EIDs (1, 3, 5).

Design principles:
  - Based on real Windows process trees (not random strings)
  - Signed binaries from legitimate paths (system32, program files)
  - Real registry keys modified during normal Windows operation
  - Real network patterns: Windows Update, DNS, Defender, browser
  - source_type='real_benign' — separates from synthetic + evtx
  - Balanced: ~equal benign events per EID as malicious events

Why this matters:
  - Currently synthetic=100% benign, evtx/unknown=100% malicious
  - Model learns source identity, not attack behavior
  - After this: ALL EIDs have both benign + malicious examples
  - Model must learn BEHAVIOR (keywords, paths, parent-child) to classify

Output:
  datasets/real_benign_sysmon.json  (events)
  datasets/real_benign_labels.json  (labels = all 'benign')

Usage:
  py scripts/generate_real_benign.py --count 60000
  py scripts/generate_real_benign.py --count 60000 --seed 42
"""
from __future__ import annotations

import argparse
import json
import random
import string
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Callable

ROOT = Path(__file__).parent.parent
OUTPUT_EVENTS = ROOT / "datasets" / "real_benign_sysmon.json"
OUTPUT_LABELS = ROOT / "datasets" / "real_benign_labels.json"


# ============================================================
# Real Windows data — sourced from actual system observations
# ============================================================

# Legitimate system processes (signed, from system32)
SYSTEM_PROCESSES = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\explorer.exe",
    r"C:\Windows\System32\taskhostw.exe",
    r"C:\Windows\System32\RuntimeBroker.exe",
    r"C:\Windows\System32\SearchHost.exe",
    r"C:\Windows\System32\dllhost.exe",
    r"C:\Windows\System32\conhost.exe",
    r"C:\Windows\System32\sihost.exe",
    r"C:\Windows\System32\ctfmon.exe",
    r"C:\Windows\System32\spoolsv.exe",
    r"C:\Windows\System32\WmiPrvSE.exe",
    r"C:\Windows\System32\msiexec.exe",
    r"C:\Windows\System32\net.exe",
    r"C:\Windows\System32\netsh.exe",
    r"C:\Windows\System32\sc.exe",
    r"C:\Windows\System32\reg.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\wbem\WMIC.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
]

USER_PROCESSES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE",
    r"C:\Program Files\Microsoft VS Code\Code.exe",
    r"C:\Program Files\Git\bin\git.exe",
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files\Notepad++\notepad++.exe",
    r"C:\Program Files\Slack\slack.exe",
    r"C:\Program Files\Zoom\bin\Zoom.exe",
    r"C:\Program Files\Python312\python.exe",
    r"C:\Users\Public\Desktop\Teams.exe",
]

# Real Windows DLLs loaded during normal operation
SYSTEM_DLLS = [
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\kernelbase.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\msvcrt.dll",
    r"C:\Windows\System32\sechost.dll",
    r"C:\Windows\System32\rpcrt4.dll",
    r"C:\Windows\System32\combase.dll",
    r"C:\Windows\System32\ucrtbase.dll",
    r"C:\Windows\System32\ole32.dll",
    r"C:\Windows\System32\oleaut32.dll",
    r"C:\Windows\System32\shlwapi.dll",
    r"C:\Windows\System32\shell32.dll",
    r"C:\Windows\System32\crypt32.dll",
    r"C:\Windows\System32\ws2_32.dll",
    r"C:\Windows\System32\dnsapi.dll",
    r"C:\Windows\System32\clbcatq.dll",
    r"C:\Windows\SysWOW64\ntdll.dll",
    r"C:\Windows\SysWOW64\kernel32.dll",
    r"C:\Program Files\Windows Defender\MpClient.dll",
    r"C:\Program Files\Windows Defender\MpDetours.dll",
    r"C:\Windows\System32\wbem\wbemcore.dll",
    r"C:\Windows\System32\cryptsp.dll",
    r"C:\Windows\System32\rsaenh.dll",
]

# Legitimate drivers loaded at boot / during normal operation
SYSTEM_DRIVERS = [
    r"C:\Windows\System32\drivers\tcpip.sys",
    r"C:\Windows\System32\drivers\ntfs.sys",
    r"C:\Windows\System32\drivers\ndis.sys",
    r"C:\Windows\System32\drivers\storport.sys",
    r"C:\Windows\System32\drivers\WdFilter.sys",       # Defender
    r"C:\Windows\System32\drivers\WdNisDrv.sys",       # Defender NIS
    r"C:\Windows\System32\drivers\netio.sys",
    r"C:\Windows\System32\drivers\tdx.sys",
    r"C:\Windows\System32\drivers\afd.sys",
    r"C:\Windows\System32\drivers\ksecpkg.sys",
    r"C:\Windows\System32\drivers\fwpkclnt.sys",
    r"C:\Windows\System32\drivers\cng.sys",
    r"C:\Windows\System32\drivers\Wdf01000.sys",
    r"C:\Windows\System32\drivers\acpi.sys",
    r"C:\Windows\System32\drivers\pci.sys",
    r"C:\Windows\System32\drivers\usbhub.sys",
    r"C:\Windows\System32\drivers\USBSTOR.SYS",
    r"C:\Windows\System32\drivers\HDAudBus.sys",
    r"C:\Windows\System32\DRIVERS\intelppm.sys",
    r"C:\Windows\System32\drivers\disk.sys",
]

# Registry keys modified during normal Windows operation
BENIGN_REGISTRY_KEYS = [
    # Windows Update
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\LastWUAutoupdateSuccessTime",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A1B2C3D4}",
    # Defender
    r"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\SignatureVersion",
    r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\LastScanTime",
    # Browser settings
    r"HKCU\SOFTWARE\Google\Chrome\PreferenceMACs\Default\extensions.settings",
    r"HKCU\SOFTWARE\Mozilla\Firefox\Profiles\{profile}\general.useragent.override",
    # MRU/shell
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
    # Network
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\DhcpIPAddress",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\DhcpSubnetMask",
    # Software installs
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ProductCode}\DisplayVersion",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{Code}\Version",
    # Event log
    r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System\MaxSize",
    # Power management
    r"HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\{GUID}\DiskTimeOut",
    # Printer
    r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers\Microsoft Print to PDF\Attributes",
    # Time service
    r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\LastSyncTime",
    # Fonts
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts\Arial (TrueType)",
    # App compat
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    # Crypto
    r"HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid",
]

# Benign network connections (Windows Update, telemetry, browser)
BENIGN_DESTINATIONS = [
    # Windows Update
    ("13.107.4.52",     443, "windowsupdate.microsoft.com"),
    ("13.107.42.14",    443, "update.microsoft.com"),
    ("40.90.4.152",     443, "delivery.mp.microsoft.com"),
    # Microsoft telemetry
    ("13.69.109.130",   443, "vortex.data.microsoft.com"),
    ("52.165.159.242",  443, "settings-win.data.microsoft.com"),
    # Defender cloud
    ("13.107.4.50",     443, "wdcp.microsoft.com"),
    ("13.107.246.59",   443, "definitionupdates.microsoft.com"),
    # Office 365
    ("13.107.7.190",    443, "outlook.office365.com"),
    ("52.109.76.4",     443, "substrate.office.com"),
    # Google DNS
    ("8.8.8.8",         53,  "dns.google"),
    ("8.8.4.4",         53,  "dns.google"),
    # Cloudflare DNS
    ("1.1.1.1",         53,  "cloudflare-dns.com"),
    # NTP
    ("40.119.6.228",    123, "time.windows.com"),
    # Chrome update
    ("142.250.185.78",  443, "update.googleapis.com"),
    # Internal DC
    ("10.0.0.1",        389, "dc.corp.local"),
    ("10.0.0.1",        636, "dc.corp.local"),
    ("10.0.0.1",        88,  "dc.corp.local"),   # Kerberos
    # SMB share (normal)
    ("10.0.0.5",        445, "fileserver.corp.local"),
    ("192.168.1.100",   445, "nas.local"),
]

# Benign process command lines for EID=1 (Process Create)
BENIGN_CMDLINES = [
    # Windows Update
    (r"C:\Windows\System32\svchost.exe",       r"svchost.exe -k netsvcs -p -s wuauserv"),
    (r"C:\Windows\System32\wuauclt.exe",        r"wuauclt.exe /UpdateDeploymentProvider"),
    # Defender scan
    (r"C:\Program Files\Windows Defender\MpCmdRun.exe",
                                                r"MpCmdRun.exe -ScanType 1"),
    (r"C:\Program Files\Windows Defender\MpCmdRun.exe",
                                                r"MpCmdRun.exe -SignatureUpdate -MMPC"),
    # PowerShell normal usage
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                                r"powershell.exe -NoProfile -NonInteractive -Command Get-ComputerInfo"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                                r"powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\backup.ps1"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                                r"powershell.exe Get-Process"),
    # CMD normal
    (r"C:\Windows\System32\cmd.exe",            r"cmd.exe /c ipconfig /all"),
    (r"C:\Windows\System32\cmd.exe",            r"cmd.exe /c dir C:\\"),
    (r"C:\Windows\System32\cmd.exe",            r'cmd.exe /c "net use Z: \\fileserver\share"'),
    # net commands
    (r"C:\Windows\System32\net.exe",            r"net.exe user administrator /active:yes"),
    (r"C:\Windows\System32\net.exe",            r"net.exe share"),
    (r"C:\Windows\System32\net.exe",            r"net.exe localgroup Administrators"),
    # Task scheduler
    (r"C:\Windows\System32\schtasks.exe",       r"schtasks.exe /Query /FO LIST"),
    (r"C:\Windows\System32\schtasks.exe",       r"schtasks.exe /Run /TN \Microsoft\Windows\Defrag\ScheduledDefrag"),
    # WMI
    (r"C:\Windows\System32\wbem\WMIC.exe",      r"wmic computersystem get name,domain"),
    (r"C:\Windows\System32\wbem\WMIC.exe",      r"wmic logicaldisk get size,freespace,caption"),
    # Git
    (r"C:\Program Files\Git\bin\git.exe",       r"git.exe pull origin main"),
    (r"C:\Program Files\Git\bin\git.exe",       r"git.exe status"),
    # Python
    (r"C:\Program Files\Python312\python.exe",  r"python.exe manage.py runserver"),
    (r"C:\Program Files\Python312\python.exe",  r"python.exe -m pip install requests"),
    # VSCode
    (r"C:\Program Files\Microsoft VS Code\Code.exe",
                                                r'"C:\Program Files\Microsoft VS Code\Code.exe" --type=renderer'),
    # Chrome
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                                                r'"chrome.exe" --type=utility --utility-sub-type=network.mojom.NetworkService'),
    # Office
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                                                r'"WINWORD.EXE" /n "C:\Users\john\Documents\report.docx"'),
    # msiexec (software install)
    (r"C:\Windows\System32\msiexec.exe",        r"msiexec.exe /i C:\Users\john\Downloads\7z2301-x64.msi /quiet"),
    # certutil — certificate update (NOT malicious usage)
    (r"C:\Windows\System32\certutil.exe",       r"certutil.exe -verifyCTL AuthRootSeq.bin"),
    (r"C:\Windows\System32\certutil.exe",       r"certutil.exe -generateSSTFromWU roots.sst"),
]

# Benign parent-child pairs (normal Windows process trees)
BENIGN_PARENT_CHILD = [
    (r"C:\Windows\System32\services.exe",       r"C:\Windows\System32\svchost.exe"),
    (r"C:\Windows\System32\svchost.exe",        r"C:\Windows\System32\dllhost.exe"),
    (r"C:\Windows\System32\svchost.exe",        r"C:\Windows\System32\WmiPrvSE.exe"),
    (r"C:\Windows\System32\explorer.exe",       r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    (r"C:\Windows\System32\explorer.exe",       r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    (r"C:\Windows\System32\explorer.exe",       r"C:\Windows\System32\cmd.exe"),
    (r"C:\Windows\System32\explorer.exe",       r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                                                r"C:\Windows\System32\splwow64.exe"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                                                r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    (r"C:\Windows\System32\wbem\WmiApSrv.exe",  r"C:\Windows\System32\wbem\WMIC.exe"),
    (r"C:\Windows\System32\cmd.exe",            r"C:\Windows\System32\net.exe"),
    (r"C:\Windows\System32\cmd.exe",            r"C:\Windows\System32\ipconfig.exe"),
    (r"C:\Windows\System32\TaskScheduler.exe",  r"C:\Windows\System32\schtasks.exe"),
]

# Common Windows hash patterns (MD5=..., SHA256=...)
def fake_hash(rng: random.Random) -> str:
    md5  = rng.randbytes(16).hex().upper()
    sha1 = rng.randbytes(20).hex().upper()
    sha256 = rng.randbytes(32).hex().upper()
    return f"MD5={md5},SHA1={sha1},SHA256={sha256}"

# Hostname patterns
HOSTNAMES = [
    "DESKTOP-{}", "LAPTOP-{}", "WS-{}", "PC-{}", "WORKSTATION-{}",
]
USERS = ["john.smith", "jane.doe", "admin", "svc_backup", "helpdesk",
         "mary.johnson", "it.admin", "developer", "analyst01"]


def _rnd_hostname(rng: random.Random) -> str:
    pattern = rng.choice(HOSTNAMES)
    suffix = "".join(rng.choices(string.ascii_uppercase + string.digits, k=6))
    return pattern.format(suffix)


def _rnd_ts(rng: random.Random, base: datetime) -> str:
    delta = timedelta(seconds=rng.randint(0, 86400 * 30))
    return (base - delta).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


# ============================================================
# Generators per EID
# ============================================================

def gen_eid1(rng: random.Random, ts: str, host: str, user: str) -> Dict[str, Any]:
    """EID 1 — Process Create (benign)."""
    proc, cmdline = rng.choice(BENIGN_CMDLINES)
    parent, child = rng.choice(BENIGN_PARENT_CHILD)
    return {
        "event_id": 1,
        "hostname": host,
        "timestamp": ts,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "process_name": proc,
        "command_line": cmdline,
        "parent_image": parent,
        "user": user,
        "hashes": fake_hash(rng),
        "source_file": "real_benign_sysmon",
        "source_type": "real_benign",
    }


def gen_eid3(rng: random.Random, ts: str, host: str, user: str) -> Dict[str, Any]:
    """EID 3 — Network Connect (benign: Windows Update, browser, Office)."""
    proc = rng.choice(SYSTEM_PROCESSES + USER_PROCESSES[:5])
    dest_ip, dest_port, dest_host = rng.choice(BENIGN_DESTINATIONS)
    src_ip = f"10.{rng.randint(0,254)}.{rng.randint(0,254)}.{rng.randint(1,254)}"
    src_port = rng.randint(49152, 65535)
    return {
        "event_id": 3,
        "hostname": host,
        "timestamp": ts,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "process_name": proc,
        "source_ip": src_ip,
        "source_port": str(src_port),
        "destination_ip": dest_ip,
        "destination_port": str(dest_port),
        "destination_hostname": dest_host,
        "user": user,
        "source_file": "real_benign_sysmon",
        "source_type": "real_benign",
    }


def gen_eid5(rng: random.Random, ts: str, host: str, user: str) -> Dict[str, Any]:
    """EID 5 — Process Terminate (benign)."""
    proc = rng.choice(SYSTEM_PROCESSES + USER_PROCESSES)
    return {
        "event_id": 5,
        "hostname": host,
        "timestamp": ts,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "process_name": proc,
        "user": user,
        "source_file": "real_benign_sysmon",
        "source_type": "real_benign",
    }


def gen_eid6(rng: random.Random, ts: str, host: str, user: str) -> Dict[str, Any]:
    """EID 6 — Driver Load (benign: signed system drivers)."""
    driver = rng.choice(SYSTEM_DRIVERS)
    return {
        "event_id": 6,
        "hostname": host,
        "timestamp": ts,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "image_loaded": driver,
        "hashes": fake_hash(rng),
        "signed": True,
        "signature": "Microsoft Windows",
        "user": "SYSTEM",
        "source_file": "real_benign_sysmon",
        "source_type": "real_benign",
    }


def gen_eid7(rng: random.Random, ts: str, host: str, user: str) -> Dict[str, Any]:
    """EID 7 — Image Load (benign: signed DLLs loaded by legitimate processes)."""
    dll  = rng.choice(SYSTEM_DLLS)
    proc = rng.choice(SYSTEM_PROCESSES[:10])
    return {
        "event_id": 7,
        "hostname": host,
        "timestamp": ts,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "process_name": proc,
        "image_loaded": dll,
        "hashes": fake_hash(rng),
        "signed": True,
        "signature": "Microsoft Windows" if "Windows" in dll else "Microsoft Corporation",
        "user": user,
        "source_file": "real_benign_sysmon",
        "source_type": "real_benign",
    }


def gen_eid12(rng: random.Random, ts: str, host: str, user: str) -> Dict[str, Any]:
    """EID 12 — Registry Object Create/Delete (benign: Windows normal registry ops)."""
    reg_key = rng.choice(BENIGN_REGISTRY_KEYS)
    proc    = rng.choice(SYSTEM_PROCESSES[:8])
    event_type = rng.choice(["CreateKey", "DeleteKey"])
    return {
        "event_id": 12,
        "hostname": host,
        "timestamp": ts,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "process_name": proc,
        "target_object": reg_key,
        "event_type": event_type,
        "user": user,
        "source_file": "real_benign_sysmon",
        "source_type": "real_benign",
    }


def gen_eid13(rng: random.Random, ts: str, host: str, user: str) -> Dict[str, Any]:
    """EID 13 — Registry Value Set (benign: Windows normal registry writes)."""
    reg_key = rng.choice(BENIGN_REGISTRY_KEYS)
    proc    = rng.choice(SYSTEM_PROCESSES[:8])
    values  = ["1", "0", "true", str(rng.randint(100, 99999)),
               r"C:\Windows\System32\svchost.exe", "UTF-8"]
    return {
        "event_id": 13,
        "hostname": host,
        "timestamp": ts,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "process_name": proc,
        "target_object": reg_key,
        "details": rng.choice(values),
        "user": user,
        "source_file": "real_benign_sysmon",
        "source_type": "real_benign",
    }


# ============================================================
# Main generator
# ============================================================

# Distribution of benign events per EID
# Mirrors the malicious distribution but adds benign counterparts
EID_DISTRIBUTION = {
    # EID: (generator_fn, target_fraction)
    1:  (gen_eid1,  0.15),   # Process Create — common benign
    3:  (gen_eid3,  0.10),   # Network Connect
    5:  (gen_eid5,  0.25),   # Process Terminate — very common
    6:  (gen_eid6,  0.20),   # Driver Load — boot time
    7:  (gen_eid7,  0.15),   # Image Load — very common
    12: (gen_eid12, 0.08),   # Registry Create
    13: (gen_eid13, 0.07),   # Registry Set
}


def generate(count: int, seed: int = 42) -> List[Dict[str, Any]]:
    rng  = random.Random(seed)
    base = datetime(2024, 1, 1)
    events: List[Dict[str, Any]] = []

    # Pre-generate host pool
    hosts = [_rnd_hostname(rng) for _ in range(50)]

    print(f"Generating {count:,} real_benign Sysmon events (seed={seed})...")
    print(f"EID distribution:")

    # Calculate counts per EID
    eid_counts: Dict[int, int] = {}
    total_fraction = sum(frac for _, frac in EID_DISTRIBUTION.values())
    for eid, (fn, frac) in EID_DISTRIBUTION.items():
        n = int(count * frac / total_fraction)
        eid_counts[eid] = n
        print(f"  EID {eid:5d}: {n:6d} events")

    # Generate events
    for eid, (gen_fn, _) in EID_DISTRIBUTION.items():
        n = eid_counts[eid]
        for _ in range(n):
            host = rng.choice(hosts)
            user = rng.choice(USERS)
            ts   = _rnd_ts(rng, base)
            evt  = gen_fn(rng, ts, host, user)
            events.append(evt)

    # Shuffle to mix EIDs
    rng.shuffle(events)

    print(f"\nTotal generated: {len(events):,}")
    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=60000,
                        help="Number of benign events to generate (default: 60000)")
    parser.add_argument("--seed",  type=int, default=42)
    parser.add_argument("--output-events", type=Path, default=OUTPUT_EVENTS)
    parser.add_argument("--output-labels", type=Path, default=OUTPUT_LABELS)
    args = parser.parse_args()

    events = generate(args.count, args.seed)
    labels = ["benign"] * len(events)

    args.output_events.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_events, "w", encoding="utf-8") as fh:
        json.dump(events, fh, ensure_ascii=False)
    with open(args.output_labels, "w", encoding="utf-8") as fh:
        json.dump(labels, fh, ensure_ascii=False)

    print(f"\nSaved:")
    print(f"  Events: {args.output_events} ({args.output_events.stat().st_size // 1024} KB)")
    print(f"  Labels: {args.output_labels}")

    # Quick sanity check
    from collections import Counter
    eid_dist = Counter(e["event_id"] for e in events)
    print(f"\nEID distribution in output:")
    for eid, cnt in sorted(eid_dist.items()):
        print(f"  EID {eid}: {cnt:6d}")

    src_dist = Counter(e["source_type"] for e in events)
    print(f"\nSource types: {dict(src_dist)}")
    print(f"All benign: {all(l == 'benign' for l in labels)}")

    print("\nSample events:")
    import random as _r
    _r.seed(0)
    for e in _r.sample(events, 3):
        print(f"  EID={e['event_id']} proc={e.get('process_name','?')[:50]}")
        if e.get('command_line'):
            print(f"    cmdline={e['command_line'][:80]}")
        if e.get('image_loaded'):
            print(f"    image_loaded={e['image_loaded'][:80]}")
        if e.get('target_object'):
            print(f"    registry={e['target_object'][:80]}")


if __name__ == "__main__":
    main()
