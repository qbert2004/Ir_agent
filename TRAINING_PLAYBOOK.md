# IR-Agent Enterprise ML Training Playbook

```
╔══════════════════════════════════════════════════════════════════════════╗
║   IR-Agent — Enterprise ML Model Training Guide                          ║
║   Источники: Windows · Sysmon · Active Directory · Linux · Kaspersky     ║
║   Модель: GradientBoostingClassifier + Platt Calibration, 90 features    ║
╚══════════════════════════════════════════════════════════════════════════╝
```

## Содержание

1. [Архитектура ML Pipeline](#1-архитектура-ml-pipeline)
2. [Источники данных и форматы логов](#2-источники-данных-и-форматы-логов)
3. [Нормализация событий (UNIFIED_SCHEMA)](#3-нормализация-событий-unified_schema)
4. [Feature Engineering — 90 признаков](#4-feature-engineering--90-признаков)
5. [Автоматическая разметка (Auto-Labeling)](#5-автоматическая-разметка-auto-labeling)
6. [Обучение модели](#6-обучение-модели)
7. [Оценка качества и пороги](#7-оценка-качества-и-пороги)
8. [Производственное развёртывание](#8-производственное-развёртывание)
9. [Запуск pipeline](#9-запуск-pipeline)
10. [Результаты обучения](#10-результаты-обучения)

---

## 1. Архитектура ML Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ENTERPRISE ML PIPELINE                            │
│                                                                      │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐         │
│  │ Windows  │   │  Sysmon  │   │   AD/DC  │   │  Linux   │         │
│  │ Security │   │  EID 1,3 │   │ 4769,662 │   │ auditd   │         │
│  │  EVTX    │   │ 7,8,10.. │   │ 4648,4720│   │auth.log  │         │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘         │
│       │              │              │              │                 │
│  ┌────┴──────────────┴──────────────┴──────────────┴─────┐          │
│  │          NORMALIZERS (7 классов)                       │          │
│  │   Каждый источник → UNIFIED_SCHEMA (50+ полей)         │          │
│  └──────────────────────────┬─────────────────────────────┘          │
│                             │                                         │
│  ┌──────────────────────────▼─────────────────────────────┐          │
│  │            FEATURE ENGINEERING                          │          │
│  │        90 числовых признаков из каждого события         │          │
│  │  Source[8] + EventType[6] + Severity[6] + Process[10]  │          │
│  │  CmdLine[10] + Network[10] + Auth[10] + AD[10]          │          │
│  │  Linux[10] + Kaspersky[10]                              │          │
│  └──────────────────────────┬─────────────────────────────┘          │
│                             │                                         │
│  ┌──────────────────────────▼─────────────────────────────┐          │
│  │            AUTO-LABELING (rule-based)                   │          │
│  │  17 malicious rules + 3 benign rules → label 0/1/None  │          │
│  │  Kaspersky DetectionResult → автоматическая метка       │          │
│  └──────────────────────────┬─────────────────────────────┘          │
│                             │                                         │
│  ┌──────────────────────────▼─────────────────────────────┐          │
│  │         GRADIENT BOOSTING + PLATT CALIBRATION           │          │
│  │  GBM(n=300, depth=5) + CalibratedClassifierCV(cv=5)     │          │
│  │  Youden-J optimal threshold selection                   │          │
│  └──────────────────────────┬─────────────────────────────┘          │
│                             │                                         │
│                    gradient_boosting_enterprise.pkl                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Поток данных

```
Корпоративные логи
    │
    ├── Windows Security Log (EVTX → JSON) ──┐
    ├── Sysmon Log (EVTX → JSON)             │
    ├── AD/DC Security Log (EVTX → JSON)     │   Normalizer
    ├── Linux auditd (/var/log/audit/)       ├──────────────► UNIFIED_SCHEMA
    ├── Linux auth.log (/var/log/auth.log)   │    per source
    ├── Kaspersky KES/KSC API export         │
    └── Firewall/Proxy logs (JSON/CEF)      ─┘
                                                    │
                                            extract_features_enterprise()
                                                    │  90 float features
                                                    ▼
                                            auto_label() → 0/1/None
                                                    │
                                            GradientBoostingClassifier
                                            + CalibratedClassifierCV
                                                    │
                                            .predict_proba(X) → [0..1]
                                                    │
                                            threshold (Youden-J) → MALICIOUS/BENIGN
```

---

## 2. Источники данных и форматы логов

### 2.1 Windows Security Events (`windows_security_events.json`)

**Источник:** Windows Event Log → Channel "Security" → экспорт через EvtxECmd или python-evtx

**Ключевые Event IDs:**

| EID  | Событие                | Угроза               | Приоритет |
|------|------------------------|----------------------|-----------|
| 4624 | Logon Success          | Pass-the-Hash, PtT   | Medium    |
| 4625 | Logon Failure          | Brute Force          | Medium    |
| 4648 | Explicit Credentials   | Pass-the-Hash        | **High**  |
| 4672 | Special Privileges     | Privilege Escalation | **High**  |
| 4688 | Process Creation       | Malware Execution    | Medium    |
| 4698 | Scheduled Task         | Persistence          | **High**  |
| 4720 | Account Created        | Backdoor Account     | **High**  |
| 4728 | Group Membership       | Privilege Escalation | **High**  |
| 4740 | Account Lockout        | Brute Force          | Medium    |
| 4776 | NTLM Auth              | Pass-the-Hash        | Medium    |
| 5140 | Network Share          | Lateral Movement     | Medium    |
| 7045 | Service Installed      | Persistence          | **High**  |

**Формат JSON (пример):**
```json
{
  "EventID": 4648,
  "SubjectUserName": "finance1",
  "TargetUserName": "administrator",
  "IpAddress": "185.220.101.45",
  "LogonType": 3,
  "AuthenticationPackageName": "NTLM",
  "WorkstationName": "ATTACKER-PC",
  "TimeCreated": "2026-04-28T14:00:00Z"
}
```

**Экспорт команды:**
```powershell
# EvtxECmd (Eric Zimmermann Tools)
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Security.evtx --csv . --csvf security_events.csv

# python-evtx
python -c "
import Evtx.Evtx as evtx, json
with evtx.Evtx('Security.evtx') as log:
    for record in log.records():
        print(json.dumps(record.as_dict()))
" > windows_security_events.json
```

---

### 2.2 Sysmon Events (`sysmon_events.json`)

**Источник:** Sysinternals Sysmon → Windows Event Log → Channel "Microsoft-Windows-Sysmon/Operational"

**Конфигурация Sysmon (минимальная для обнаружения атак):**
```xml
<!-- sysmon_config.xml -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- EID 1: Process Create — все процессы -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include"><Rule groupRelation="or"/></ProcessCreate>
    </RuleGroup>
    <!-- EID 3: Network Connection — только внешние IP -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
    <!-- EID 8: CreateRemoteThread — инъекции -->
    <!-- EID 10: ProcessAccess (lsass dump) -->
    <!-- EID 22: DNS Query -->
  </EventFiltering>
</Sysmon>
```

**Ключевые EID для обнаружения:**

| EID | Событие             | Индикатор атаки                         |
|-----|---------------------|-----------------------------------------|
| 1   | ProcessCreate       | mimikatz, vssadmin, powershell -enc     |
| 3   | NetworkConnection   | C2 beacon (порты 4444, 1337, 9001)      |
| 7   | ImageLoad           | Загрузка вредоносных DLL                |
| 8   | CreateRemoteThread  | Process injection                       |
| 10  | ProcessAccess       | LSASS dump (lsass.exe как TargetImage)  |
| 11  | FileCreate          | Ransom note, dropper                    |
| 22  | DNSQuery            | C2 domain (DGA, fast-flux)              |
| 25  | ProcessTampering    | Process hollowing                       |

**Формат JSON (пример — Process Injection):**
```json
{
  "EventID": 10,
  "SourceImage": "C:\\Windows\\System32\\cmd.exe",
  "TargetImage": "C:\\Windows\\System32\\lsass.exe",
  "GrantedAccess": "0x1010",
  "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll...",
  "User": "CORP\\finance1",
  "Hashes": "MD5=DEADBEEF,SHA256=...",
  "Signed": false,
  "TimeCreated": "2026-04-28T14:01:00Z"
}
```

---

### 2.3 Active Directory Events (`active_directory_events.json`)

**Источник:** Domain Controller → Security Log (EVTX)

**Атаки и их Event IDs:**

| Атака            | EID(s)      | Признак обнаружения                              |
|------------------|-------------|--------------------------------------------------|
| Kerberoasting    | 4769        | TicketEncryptionType = 0x17 (RC4-HMAC)           |
| AS-REP Roasting  | 4768        | PreAuthType = "0" (нет преаутентификации)         |
| Pass-the-Hash    | 4648        | LogonGuid = {00000000-...}; внешний IP           |
| DCSync           | 4662        | AccessMask = 0x100 (replication права)           |
| Golden Ticket    | 4768        | TargetUserName = "krbtgt"; необычный IP          |
| Account Backdoor | 4720 + 4728 | Новый аккаунт → добавлен в Domain Admins         |
| Brute Force      | 4771 (много)| FailureCode = 0x18; много за короткое время      |

**Формат JSON (Kerberoasting):**
```json
{
  "EventID": 4769,
  "ServiceName": "mssql_svc",
  "TargetUserName": "hacker@corp.local",
  "TicketEncryptionType": "0x17",
  "IpAddress": "185.220.101.45",
  "TicketOptions": "0x40810000",
  "TimeCreated": "2026-04-28T14:00:30Z"
}
```

---

### 2.4 Linux Auditd (`linux_auditd_events.json`)

**Источник:** `/var/log/audit/audit.log` → конвертация в JSON

**Настройка правил auditd (`/etc/audit/rules.d/ir_agent.rules`):**
```bash
# Чтение чувствительных файлов
-w /etc/passwd -p r -k credentials
-w /etc/shadow -p r -k credentials
-w /etc/sudoers -p r -k sudoers
-w /root/.ssh -p r -k ssh_keys

# Выполнение из /tmp и /dev/shm
-a always,exit -F dir=/tmp -F perm=x -k tmp_exec
-a always,exit -F dir=/dev/shm -F perm=x -k shm_exec

# Загрузка ядерных модулей
-w /sbin/insmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module

# Изменение UID (SUID escalation)
-a always,exit -F arch=b64 -S setuid -k setuid
-a always,exit -F arch=b64 -S setgid -k setgid

# Сетевые подключения от серверных процессов
-a always,exit -F arch=b64 -S connect -k network_connect
```

**Формат JSON (SUID escalation):**
```json
{
  "type": "SYSCALL",
  "syscall": "execve",
  "exe": "/tmp/exploit",
  "uid": "1001",
  "euid": "0",
  "auid": "1001",
  "comm": "exploit",
  "pid": "4892",
  "ppid": "4891",
  "key": ""
}
```

**Конвертация из raw audit.log:**
```python
import subprocess, json
def parse_audit_log(path="/var/log/audit/audit.log"):
    result = subprocess.run(
        ["ausearch", "-i", "--format", "csv", "-f", path],
        capture_output=True, text=True
    )
    # Или используйте audit2json: pip install audit2json
    events = []
    for line in result.stdout.splitlines():
        parts = dict(kv.split("=",1) for kv in line.split() if "=" in kv)
        events.append(parts)
    return events
```

---

### 2.5 Linux Auth Log (`linux_auth_events.json`)

**Источник:** `/var/log/auth.log` (Debian/Ubuntu) или `/var/log/secure` (RHEL/CentOS)

**Паттерны обнаружения:**

| Событие               | Паттерн в логе                                   | Угроза           |
|-----------------------|--------------------------------------------------|------------------|
| SSH Brute Force       | `Failed password for root from <ext_ip>`         | ✗ Malicious      |
| SSH Success           | `Accepted password for root from <ext_ip>`       | ✗ Подозрительно  |
| Sudo к root           | `sudo: user NOT in sudoers`                      | ✗ Malicious      |
| PAM failure           | `pam_unix(su:auth): authentication failure`      | ✗ Malicious      |
| Normal SSH (pubkey)   | `Accepted publickey for alice from <int_ip>`     | ✓ Benign         |

**Формат JSON:**
```json
{
  "message": "Failed password for root from 185.220.101.45 port 22 ssh2",
  "process": "sshd",
  "pid": 2222,
  "remote_host": "185.220.101.45",
  "user": "root",
  "timestamp": "2026-04-28T14:02:01Z",
  "fail_count": 5
}
```

**Парсинг через GoAccess или Python:**
```python
import re, json
AUTH_LOG_PATTERN = re.compile(
    r"(\w+ \d+ \S+) \S+ (\w+)\[(\d+)\]: (.+)"
)
FAIL_PATTERN  = re.compile(r"Failed (\w+) for (\S+) from (\S+)")
ACCEPT_PATTERN= re.compile(r"Accepted (\w+) for (\S+) from (\S+)")

events = []
with open("/var/log/auth.log") as f:
    for line in f:
        m = AUTH_LOG_PATTERN.match(line.strip())
        if not m: continue
        ts, proc, pid, msg = m.groups()
        ev = {"timestamp": ts, "process": proc, "pid": pid, "message": msg}
        mf = FAIL_PATTERN.search(msg)
        if mf:
            ev.update({"auth_method": mf.group(1), "user": mf.group(2),
                       "remote_host": mf.group(3)})
        events.append(ev)
```

---

### 2.6 Kaspersky KES/KSC (`kaspersky_events.json`)

**Источник:** Kaspersky Security Center → SQL Query / REST API / Syslog CEF

**Экспорт через KSC REST API:**
```python
import requests, json

KSC_URL   = "https://ksc.corp.local:13299"
KSC_TOKEN = "YOUR_KSC_API_TOKEN"

def get_kes_events(limit=10000):
    headers = {"Authorization": f"KSCBasic {KSC_TOKEN}",
               "Content-Type": "application/json"}
    body = {
        "wstrFilter": "(LastEventTime > '2026-04-27')",
        "vecFieldsToReturn": [
            "EventType","HostName","UserName","VirusName","ObjectPath",
            "Result","Action","MD5Hash","RemoteHostAddress"
        ],
        "lMaxLifeTime": limit
    }
    resp = requests.post(f"{KSC_URL}/api/v1.0/Events.GetEvents",
                         json=body, headers=headers, verify=False)
    return resp.json()["pEvents"]

events = get_kes_events()
with open("datasets/kaspersky_events.json", "w") as f:
    json.dump(events, f, ensure_ascii=False, indent=2)
```

**Формат JSON (Detection event):**
```json
{
  "EventType": "GNRL_EV_DETECT",
  "HostName": "FINANCE-PC-01",
  "UserName": "CORP\\finance1",
  "ThreatName": "Trojan.Win32.Emotet.gen",
  "FilePath": "C:\\Users\\finance1\\AppData\\Local\\Temp\\doc.exe",
  "Action": "Detected",
  "DetectionResult": "detected",
  "MD5": "DEADBEEFDEADBEEF",
  "RemoteHost": "185.220.101.45",
  "TimeCreated": "2026-04-28T14:01:30Z"
}
```

**Важные типы детектов:**

| EventType                  | Угроза                          | ML Label |
|----------------------------|---------------------------------|----------|
| `GNRL_EV_DETECT`           | Угроза обнаружена               | 1 (auto) |
| `GNRL_EV_OBJ_BLOCKED`      | Объект заблокирован             | 1 (auto) |
| `GNRL_EV_OBJ_DISINFECTED`  | Вылечен (был заражён)           | 1 (auto) |
| `GNRL_EV_OBJ_NOT_CURED`    | Не вылечен (активная угроза)    | 1 (auto) |
| `EXPLOIT_DETECTED`         | Эксплойт                        | 1 (auto) |
| `RANSOMWARE_DETECTED`      | Ransomware поведение            | 1 (auto) |
| `Database Updated`         | Обновление БД                   | 0 (auto) |

Kaspersky события **автоматически размечаются** на основе `DetectionResult` без дополнительных правил.

---

### 2.7 Firewall Logs (`firewall_events.json`)

**Источник:** Cisco ASA / Palo Alto / CheckPoint / Windows Firewall / pfSense

**Формат JSON:**
```json
{
  "Action": "ALLOW",
  "SrcIP": "10.0.1.99",
  "DstIP": "185.220.101.45",
  "DstPort": 4444,
  "Protocol": "TCP",
  "BytesSent": 524288,
  "Application": "powershell.exe",
  "TimeCreated": "2026-04-28T14:00:20Z"
}
```

**Подозрительные паттерны:**

| Паттерн                          | Угроза                    |
|----------------------------------|---------------------------|
| DstPort: 4444, 1337, 31337       | C2 / Metasploit           |
| DstPort: 9001, 9050              | TOR network               |
| BytesSent > 50MB outbound        | Data Exfiltration         |
| External → DstPort 3389, 5985   | RDP/WinRM lateral access  |
| Application: nc.exe, ncat.exe    | Reverse shell             |

---

## 3. Нормализация событий (UNIFIED_SCHEMA)

Все источники приводятся к единой схеме **UNIFIED_SCHEMA** с 50+ полями:

```python
UNIFIED_SCHEMA = {
    # Базовые
    "source_type":   None,    # windows_security | sysmon | active_directory |
                               # linux_auditd | linux_auth | kaspersky | firewall
    "event_id":      None,    # MD5 хэш события (уникальный ID)
    "timestamp":     None,    # ISO 8601
    "hostname":      None,    # имя хоста

    # Платформа
    "os_platform":   None,    # windows | linux
    "raw_event_id":  None,    # оригинальный EventID (int) или тип события (str)
    "event_type":    None,    # process_create | network_connection | auth |
                               # threat_detection | file_create | account_change

    # Процесс
    "process_name":  None,    # basename (cmd.exe, mimikatz.exe)
    "process_path":  None,    # полный путь
    "process_hash_md5": None,
    "process_hash_sha256": None,
    "process_signed": None,   # bool: подпись Microsoft/валидная
    "parent_process": None,   # basename родительского процесса
    "command_line":  None,    # полная командная строка

    # Пользователь
    "user":          None,    # домен\имя_пользователя
    "logon_type":    None,    # interactive | network | new_credentials | ...
    "auth_package":  None,    # NTLM | Kerberos | Negotiate
    "privilege_list": None,   # "SeDebugPrivilege\nSeTcbPrivilege"

    # Сеть
    "src_ip":        None,
    "dst_ip":        None,
    "dst_port":      None,    # int
    "bytes_sent":    None,    # int, байт

    # Файл/Реестр
    "file_path":     None,
    "registry_key":  None,
    "registry_value": None,

    # AD-специфичные
    "target_user":   None,
    "kerberos_ticket_type": None,  # TGT | TGS
    "ticket_encryption": None,     # "0x17"=RC4 (Kerberoasting), "0x12"=AES
    "group_name":    None,

    # Kaspersky-специфичные
    "threat_name":   None,    # "Trojan.Win32.Emotet.gen"
    "detection_result": None, # "detected" | "blocked" | "disinfected"

    # Linux-специфичные
    "syscall":       None,    # "execve" | "connect" | "openat"
    "linux_uid":     None,    # "0" = root
    "linux_euid":    None,    # "0" = root (SUID escalation если uid≠euid)
    "linux_auid":    None,    # "4294967295" = unset (неаутентифицированный)
    "sudo_command":  None,

    # Метка (для обучения)
    "label":         None,    # 0 = benign | 1 = malicious | None = uncertain
    "label_source":  None,    # "kaspersky" | "rule_lsass_dump" | "ground_truth"
}
```

### Схема нормализации по источникам

```
Windows Security JSON               Sysmon JSON
{                                   {
  "EventID": 4648,                    "EventID": 10,
  "SubjectUserName": "finance1",      "SourceImage": "cmd.exe",
  "IpAddress": "185.220.101.45",      "TargetImage": "lsass.exe",
  "LogonType": 3,                     "GrantedAccess": "0x1010"
  "AuthPackage": "NTLM"             }
}                                         │
    │                                     │
    ▼  WindowsSecurityNormalizer()        ▼  SysmonNormalizer()
    │                                     │
    └─────────────────┬───────────────────┘
                      │
                      ▼
    UNIFIED_SCHEMA:
    {
      "source_type": "windows_security" | "sysmon",
      "raw_event_id": 4648 | 10,
      "event_type": "auth" | "process_create",
      "user": "finance1",
      "auth_package": "NTLM",
      "src_ip": "185.220.101.45",
      "logon_type": "network",
      "process_name": "" | "cmd.exe",
      "severity": "high" | "critical",
      ...
    }
```

---

## 4. Feature Engineering — 90 признаков

Функция `extract_features_enterprise(ev)` извлекает **ровно 90 числовых признаков** (float) из нормализованного события.

### Группы признаков

```
[1-8]   Источник события (8 бинарных)
        src_windows_security, src_sysmon, src_active_directory,
        src_linux_auditd, src_linux_auth, src_kaspersky,
        src_firewall, src_other

[9-14]  Тип события (6 бинарных)
        etype_process_create, etype_network, etype_auth,
        etype_threat_detection, etype_registry, etype_file

[15-20] Severity (6 бинарных)
        sev_critical, sev_high, sev_medium, sev_low,
        sev_info, sev_high_or_critical

[21-30] Процесс (10 признаков)
        proc_suspicious_exact    — процесс в списке SUSPICIOUS_PROCS
                                   (mimikatz, vssadmin, wmic, certutil...)
        proc_lolbas             — Living-off-the-Land Binary
        proc_system_path        — из C:\Windows\System32 или C:\Program Files
        proc_signed             — подписанный (Microsoft/CA)
        proc_suspicious_ext     — расширение .vbs, .ps1, .hta, .bat...
        proc_appdata_temp       — путь через AppData или Temp
        proc_suspicious_dir     — C:\Users\Public\, /dev/shm/, ...
        proc_has_hash           — хэш (MD5/SHA256) присутствует
        proc_parent_child_susp  — опасные пары: WINWORD→cmd, excel→cmd...
        proc_masquerade         — имитация системного процесса (svch0st, lsas)

[31-40] Командная строка (10 признаков)
        cmd_base64_encoded      — паттерн -enc/-encodedcommand + Base64
        cmd_lsass_cred          — sekurlsa, logonpasswords, lsadump
        cmd_vss_delete          — vssadmin delete shadows
        cmd_ps_hidden           — -nop -w hidden -windowstyle hidden
        cmd_download            — DownloadString, DownloadFile, wget, curl
        cmd_invoke_expression   — IEX(), Invoke-Expression
        cmd_net_user_group      — net user, net localgroup (разведка)
        cmd_registry_modify     — reg add, reg delete, regedit
        cmd_schtasks            — schtasks /create (persistence)
        cmd_high_entropy        — Shannon entropy > 4.5 бит (обфускация)

[41-50] Сеть (10 признаков)
        net_dst_external        — IP назначения вне RFC1918
        net_src_external        — IP источника вне RFC1918
        net_c2_port             — 4444, 4445, 1337, 31337, 9001, 9050, 6667...
        net_http_port           — 80, 443, 8080, 8443
        net_rdp_smb_port        — 3389, 5985, 5986, 445, 135, 139
        net_common_svc_port     — 21, 25, 53, 110, 143, 993, 995
        net_large_transfer_10mb — BytesSent > 10MB (эксфильтрация)
        net_huge_transfer_100mb — BytesSent > 100MB (массовая кража)
        net_dns_external        — DNS-запрос к внешнему resolver-у
        net_netcat              — процесс nc.exe/ncat.exe + network_connection

[51-60] Аутентификация (10 признаков)
        auth_network_logon      — LogonType = network (pass-the-hash)
        auth_new_creds          — LogonType = new_credentials (pass-the-hash)
        auth_ntlm               — AuthPackage = NTLM
        auth_admin_user         — user содержит "admin" или "administrator"
        auth_service_account    — user содержит "service", "svc_" или "$"
        auth_empty_user         — user пустой (анонимный)
        priv_sedebug            — SeDebugPrivilege (доступ к любым процессам)
        priv_high_privs         — SeTakeOwnership или SeTcbPrivilege
        auth_lockout            — событие блокировки аккаунта
        auth_failure            — событие отказа аутентификации

[61-70] Active Directory (10 признаков)
        ad_kerberos_rc4         — RC4-HMAC шифрование (Kerberoasting)
        ad_kerberos_aes         — AES шифрование (нормальный Kerberos)
        ad_tgt_request          — запрос TGT (EID 4768)
        ad_tgs_request          — запрос TGS service ticket (EID 4769)
        ad_krbtgt_target        — цель запроса = krbtgt (Golden Ticket)
        ad_cross_domain_access  — внешний IP + target_computer (lateral)
        ad_dcsync               — EID 4662 + AccessMask 0x100 (репликация)
        ad_explicit_creds       — EID 4648 (явные учётные данные)
        ad_group_membership     — изменение членства в группе (4728,4732...)
        ad_account_created      — создание/удаление аккаунта (4720, 4726)

[71-80] Linux (10 признаков)
        linux_root_uid          — uid=0 или euid=0
        linux_suid_escalation   — uid≠euid И euid=0 (SUID bit execution)
        linux_unset_auid        — auid=4294967295 (неаутентифицированный сеанс)
        linux_critical_path     — обращение к /etc/passwd, /etc/shadow...
        linux_tmp_execution     — выполнение из /tmp/ или /dev/shm/
        linux_sudo              — команда через sudo
        linux_cron              — изменение crontab
        linux_kernel_module     — insmod, modprobe, rmmod (rootkit)
        linux_execve            — syscall = execve (запуск процесса)
        linux_network_syscall   — syscall = connect/bind/accept

[81-90] Kaspersky + угрозы (10 признаков)
        kas_labeled_malicious   — Kaspersky уже пометил как malicious
        kas_major_threat        — ThreatName содержит trojan/backdoor/exploit
        kas_behavioral_heuristic— ThreatName содержит "PDM:" или "HEUR:"
        kas_ransomware          — ThreatName содержит "ransom"
        kas_detection_confirmed — DetectionResult in detected/blocked/not_cured
        cmd_cobalt_beacon       — cobalt, beacon, meterpreter в cmdline
        cmd_empire_powersploit  — empire, powersploit, invoke-mimikatz
        cmd_psexec_wmi          — psexec, wmiexec, dcomexec (lateral)
        etype_scheduled_task    — тип scheduled_task ИЛИ EID 4698
        net_external_unusual    — внешний IP + network_connection + необычный proc
```

### Топ-15 признаков (реальные веса из обучения)

```
Ранг  Признак                      Важность  Описание
──────────────────────────────────────────────────────────────────────
  1   kas_labeled_malicious         0.374    Kaspersky-детект (авто-метка)
  2   src_windows_security          0.180    Источник = Windows Security
  3   ad_explicit_creds             0.071    EID 4648 (Pass-the-Hash)
  4   src_sysmon                    0.070    Источник = Sysmon
  5   sev_info                      0.065    Severity = info (инверсия)
  6   etype_auth                    0.057    Тип = аутентификация
  7   proc_suspicious_exact         0.056    Процесс из чёрного списка
  8   proc_lolbas                   0.036    LOLBAS-бинарник
  9   auth_empty_user               0.032    Пустое имя пользователя
 10   sev_high                      0.020    Severity = high
 11   sev_high_or_critical          0.019    Severity high/critical
 12   net_src_external              0.011    Внешний источник IP
 13   etype_threat_detection        0.002    Детект угрозы
 14   etype_process_create          0.002    Создание процесса
 15   auth_admin_user               0.001    Имя содержит "admin"
```

---

## 5. Автоматическая разметка (Auto-Labeling)

### Приоритет источников меток

```
┌─────────────────────────────────────────────────────────────┐
│                  LABELING PRIORITY                           │
│                                                              │
│  1. Kaspersky DetectionResult         → label=1 (MALICIOUS) │
│     (Detected, Blocked, Not_Cured)                          │
│                                                              │
│  2. Ground Truth (labels.json)         → label=0 or 1       │
│     (ручная разметка аналитика SOC)                         │
│                                                              │
│  3. Rule-Based Detection (auto)        → label=0 or 1       │
│     17 malicious rules + 3 benign rules                     │
│                                                              │
│  4. Uncertain (None)                   → исключается         │
│     из обучения (не ухудшает модель)                        │
└─────────────────────────────────────────────────────────────┘
```

### Malicious Rules (17 правил)

| №  | Правило                      | Условие                                     |
|----|------------------------------|---------------------------------------------|
| R1 | rule_lsass_dump              | sekurlsa ИЛИ logonpasswords в cmdline        |
| R2 | rule_dcsync                  | lsadump::dcsync в cmdline                   |
| R3 | rule_vss_delete              | "delete shadows" + процесс vssadmin.exe      |
| R4 | rule_bcdedit_recovery        | "recoveryenabled no" + bcdedit               |
| R5 | rule_ps_base64               | Base64-кодирование + powershell              |
| R6 | rule_ps_hidden               | -nop + -w hidden в cmdline                  |
| R7 | rule_ps_download             | DownloadString ИЛИ DownloadFile              |
| R8 | rule_ps_iex                  | IEX() ИЛИ Invoke-Expression                 |
| R9 | rule_susp_proc               | mimikatz, procdump, wce и др.               |
| R10| rule_certutil_abuse          | certutil с -decode/-urlcache/-encode         |
| R11| rule_mshta_remote            | mshta + http:// ИЛИ javascript:             |
| R12| rule_regsvr32_scrobj         | regsvr32 /s /u (COM execution)              |
| R13| rule_kaspersky_threat        | ThreatName содержит trojan/backdoor/worm    |
| R14| rule_kerberoasting           | EID 4769 + EncType = RC4 (0x17/0x18)       |
| R15| rule_pass_the_hash           | EID 4648 (всегда подозрительно)             |
| R16| rule_linux_suid              | uid≠0 AND euid=0 И процесс не sudo          |
| R17| rule_linux_tmp_exec          | file_path начинается с /tmp/ или /dev/shm/  |

### Benign Rules (3 правила)

| №  | Правило                        | Условие                                        |
|----|--------------------------------|------------------------------------------------|
| B1 | rule_known_signed_proc         | Подписанный системный процесс без обфускации    |
| B2 | rule_normal_interactive_logon  | Интерактивный вход, severity=info               |
| B3 | rule_linux_daemon              | Системный демон (sshd, cron, systemd) из UID=0 |

---

## 6. Обучение модели

### Алгоритм

```python
# GradientBoostingClassifier — основной алгоритм
gb = GradientBoostingClassifier(
    n_estimators=300,     # 300 деревьев
    max_depth=5,          # глубина 5 уровней
    learning_rate=0.07,   # скорость обучения (медленнее = точнее)
    subsample=0.8,        # 80% выборки на каждое дерево (anti-overfitting)
    min_samples_leaf=5,   # min 5 событий в листе
    random_state=42
)

# Platt Calibration — калибровка вероятностей
# Преобразует score → точную вероятность [0,1]
model = CalibratedClassifierCV(gb, method="sigmoid", cv=5)

# StandardScaler — нормализация признаков
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_train)
model.fit(X_scaled, y_train)
```

### Выбор порога (Youden-J)

```
Стандартный порог 0.5 не оптимален для несбалансированных данных.
Используем критерий Youden-J для максимизации TPR + TNR:

    J = TPR - FPR = Sensitivity + Specificity - 1

    ┌──────────────────────────────────────────────────┐
    │  ROC Curve                                        │
    │                                                   │
    │  1.0 ┤                  ╭──────────────────       │
    │      │              ╭──╯                          │
    │  TPR │          ╭──╯                              │
    │      │      ╭──╯     ← Youden-J point             │
    │      │  ╭──╯           (max vertical distance)    │
    │  0.0 ├──┴────────────────────────── FPR           │
    │      0.0                          1.0             │
    └──────────────────────────────────────────────────┘

# Код выбора порога:
from sklearn.metrics import roc_curve
fpr_arr, tpr_arr, thresholds = roc_curve(y_val, proba_val)
j_scores   = tpr_arr - fpr_arr
best_idx   = np.argmax(j_scores)
threshold  = float(thresholds[best_idx])
```

### Сохранение модели

```python
bundle = {
    "model":        model,       # CalibratedClassifierCV
    "scaler":       scaler,      # StandardScaler
    "threshold":    threshold,   # Youden-J optimal
    "feature_names": FEATURE_NAMES,  # список 90 признаков
    "metrics": {
        "roc_auc":   roc_auc,
        "accuracy":  accuracy,
        "precision": precision,
        "recall":    recall,
        "f1":        f1,
        "fpr":       fpr,
        "fnr":       fnr,
    },
    "trained_at":   datetime.utcnow().isoformat(),
    "version":      "enterprise_v1"
}

with open("models/gradient_boosting_enterprise.pkl", "wb") as f:
    pickle.dump(bundle, f)
```

---

## 7. Оценка качества и пороги

### Метрики

| Метрика            | Формула                   | Целевое значение | Описание                            |
|--------------------|---------------------------|-----------------|-------------------------------------|
| ROC-AUC            | Area under ROC curve      | > 0.97          | Общее качество разделения           |
| Accuracy           | (TP+TN)/(TP+TN+FP+FN)    | > 0.95          | Общая точность                      |
| Precision          | TP/(TP+FP)                | > 0.95          | Точность тревог (мало ложных)       |
| Recall (TPR)       | TP/(TP+FN)                | > 0.93          | Доля найденных атак                 |
| F1-Score           | 2*P*R/(P+R)               | > 0.95          | Баланс Precision/Recall             |
| Brier Score        | mean((p-y)²)              | < 0.05          | Качество калиброванных вероятностей |
| FPR (False Alarm)  | FP/(FP+TN)                | < 0.05          | Ложные тревоги (< 5%)               |
| FNR (Miss Rate)    | FN/(FN+TP)                | < 0.07          | Пропущенные атаки (< 7%)            |

### Результаты текущего обучения

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  РЕЗУЛЬТАТЫ (Enterprise v1, 2026-04-28)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Размер датасета: 4,430 размеченных событий из 83,500
  Malicious: 4,235 (95.6%)   Benign: 195 (4.4%)

  Accuracy:          1.0000  (100.00%)
  ROC-AUC:           1.0000
  Precision:         1.0000
  Recall / TPR:      1.0000  (100.00%)
  F1-Score:          1.0000
  Brier Score:       0.0000

  FPR (false alarm): 0.00%   (цель: < 5%)
  FNR (missed):      0.00%   (цель: < 7%)
  Optimal threshold: 0.9942

  Источники данных:
    windows_security_events.json   500 событий
    sysmon_events.json             500 событий
    active_directory_events.json   500 событий
    linux_auditd_events.json       500 событий
    linux_auth_events.json         500 событий
    kaspersky_events.json          500 событий
    firewall_events.json           500 событий
    real_benign_sysmon.json       80,000 событий (из Sysmon EVTX)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  PROD модель ОБНОВЛЕНА:  0.9903 → 1.0000 (+0.0097)
  Сохранено: models/gradient_boosting_enterprise.pkl
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

> **Примечание:** ROC-AUC = 1.0 достигнут на синтетических данных с очевидными паттернами.
> На реальных данных (с шумом, обфускацией, zero-day) ожидаемый диапазон: **0.96–0.99**.

### Матрица ошибок

```
                    Предсказано
                  BENIGN    MALICIOUS
Реальное BENIGN  [  TN  ]  [  FP  ]   ← Ложная тревога (alert fatigue)
        MALICIOUS[  FN  ]  [  TP  ]   ← Пропущенная атака (критично!)

При threshold = 0.9942:
  TP=1059  FP=0  TN=49  FN=0
```

---

## 8. Производственное развёртывание

### Загрузка и использование модели

```python
import pickle, numpy as np
from scripts.retrain_enterprise import (
    NORMALIZERS, extract_features_enterprise, auto_label
)

# Загрузка модели
with open("models/gradient_boosting_enterprise.pkl", "rb") as f:
    bundle = pickle.load(f)

model     = bundle["model"]
scaler    = bundle["scaler"]
threshold = bundle["threshold"]   # 0.9942

def classify_event(raw_event: dict, source_type: str) -> dict:
    """Классифицировать одно событие из любого источника."""
    # 1. Нормализация
    normalizer_map = {
        "windows_security": WindowsSecurityNormalizer(),
        "sysmon":           SysmonNormalizer(),
        "active_directory": ActiveDirectoryNormalizer(),
        "linux_auditd":     LinuxAuditdNormalizer(),
        "linux_auth":       LinuxAuthNormalizer(),
        "kaspersky":        KasperskyNormalizer(),
        "firewall":         FirewallNormalizer(),
    }
    ev = normalizer_map[source_type].normalize(raw_event)

    # 2. Feature extraction
    features = extract_features_enterprise(ev)
    X = scaler.transform([features])

    # 3. Предсказание
    proba = model.predict_proba(X)[0][1]
    label = "MALICIOUS" if proba >= threshold else "BENIGN"

    return {
        "label":        label,
        "probability":  round(proba, 4),
        "threshold":    threshold,
        "is_malicious": proba >= threshold
    }

# Пример использования:
event = {
    "EventID": 1,
    "Image": "C:\\Windows\\Temp\\mimikatz.exe",
    "CommandLine": "mimikatz sekurlsa::logonpasswords exit",
    "ParentImage": "cmd.exe",
    "User": "CORP\\finance1"
}
result = classify_event(event, "sysmon")
# → {"label": "MALICIOUS", "probability": 0.9987, "is_malicious": True}
```

### Интеграция с IR-Agent

Обученная модель автоматически подхватывается IR-Agent через `app/core/ml_classifier.py`.
После сохранения в `models/gradient_boosting_enterprise.pkl`:

```bash
# Рестарт сервера (для подхвата новой модели)
pkill -f "uvicorn app.main"
python -m uvicorn app.main:app --port 9000 &

# Проверка версии
curl -H "Authorization: Bearer $MY_API_TOKEN" http://localhost:9000/health/ml
# → {"ml_model": {"model_version": "enterprise_v1", "threshold": 0.9942, ...}}
```

---

## 9. Запуск pipeline

### Предварительные требования

```bash
pip install scikit-learn numpy joblib
```

### Шаг 1: Подготовка данных

```
datasets/
├── windows_security_events.json   ← Windows Security Log
├── sysmon_events.json             ← Sysmon Events
├── active_directory_events.json   ← AD/DC Events
├── linux_auditd_events.json       ← Linux auditd
├── linux_auth_events.json         ← Linux auth.log
├── kaspersky_events.json          ← Kaspersky KES/KSC
└── firewall_events.json           ← Firewall logs
```

### Шаг 2: Генерация тестовых данных (опционально)

```bash
# Создать синтетический датасет для проверки pipeline
python scripts/generate_enterprise_data.py

# Вывод:
# → 500 events per source (3500 total)
# → 70% benign, 30% malicious
```

### Шаг 3: Обучение

```bash
python scripts/retrain_enterprise.py

# Ожидаемый вывод:
# INFO  Шаг 1/5: Загрузка датасетов ...
# INFO    → загружено 500 событий  [каждый источник]
# INFO  Шаг 2/5: Статистика разметки ...
# INFO  Шаг 3/5: Извлечение признаков (90 features) ...
# INFO  Шаг 4/5: Обучение модели ...
# INFO    Accuracy: 0.9631
# INFO    ROC-AUC:  0.9903
# INFO    FPR:      2.52%
# INFO  Шаг 5/5: Сохранение модели ...
# INFO    Сохранено: models/gradient_boosting_enterprise.pkl
```

### Шаг 4: Верификация

```bash
# Проверка что модель работает корректно
python -c "
import pickle
with open('models/gradient_boosting_enterprise.pkl', 'rb') as f:
    bundle = pickle.load(f)
print('Version:', bundle['version'])
print('ROC-AUC:', bundle['metrics']['roc_auc'])
print('Threshold:', bundle['threshold'])
print('Features:', len(bundle['feature_names']))
"
```

### Шаг 5: Тестирование live

```bash
# Запустить IR-Agent с новой моделью
python -m uvicorn app.main:app --port 9000

# Тест классификации
curl -X POST http://localhost:9000/ml/classify \
  -H "Content-Type: application/json" \
  -d '{"event": {
    "process_name": "mimikatz.exe",
    "command_line": "mimikatz sekurlsa::logonpasswords exit",
    "event_type": "process_create"
  }}'
# → {"label": "malicious", "confidence": 0.9987}
```

### Шаг 6 (опционально): Добавить ground truth метки

```json
// datasets/labels.json — ручная разметка аналитика
{
  "event_id_1": 1,
  "event_id_2": 0,
  "event_id_3": 1
}
```

Эти метки имеют наивысший приоритет и переопределяют rule-based разметку.

---

## 10. Результаты обучения

### Финальные метрики

```
╔═══════════════════════════════════════════════════════╗
║       IR-Agent Enterprise ML v1 — Training Report     ║
╠═══════════════════════════════════════════════════════╣
║  Дата обучения:  2026-04-28                           ║
║  Файл модели:    gradient_boosting_enterprise.pkl     ║
╠═══════════════════════════════════════════════════════╣
║  ДАТАСЕТ                                              ║
║  Всего событий:        83,500                        ║
║  Размечено:             4,430  (5.3%)                ║
║  └─ Malicious:          4,235  (95.6%)               ║
║  └─ Benign:               195  (4.4%)                ║
║  Не размечено (excluded): 79,070  (94.7%)            ║
╠═══════════════════════════════════════════════════════╣
║  ИСТОЧНИКИ                                            ║
║  windows_security:    500 событий                    ║
║  sysmon:              500 событий                    ║
║  active_directory:    500 событий                    ║
║  linux_auditd:        500 событий                    ║
║  linux_auth:          500 событий                    ║
║  kaspersky:           500 событий (авто-размечено)   ║
║  firewall:            500 событий                    ║
║  real_benign_sysmon: 80,000 событий (реальные EVTX)  ║
╠═══════════════════════════════════════════════════════╣
║  КАЧЕСТВО МОДЕЛИ (validation 25%)                     ║
║  Accuracy:            100.00%                        ║
║  ROC-AUC:             1.0000                         ║
║  Precision:           100.00%                        ║
║  Recall (TPR):        100.00%                        ║
║  F1-Score:            1.0000                         ║
║  Brier Score:         0.0000                         ║
║  FPR (false alarms):  0.00%  (цель < 5%)             ║
║  FNR (missed):        0.00%  (цель < 7%)             ║
║  Optimal threshold:   0.9942 (Youden-J)              ║
╠═══════════════════════════════════════════════════════╣
║  ТОП ПРИЗНАКИ                                         ║
║  1. kas_labeled_malicious     37.4%                  ║
║  2. src_windows_security      18.0%                  ║
║  3. ad_explicit_creds          7.1%                  ║
║  4. src_sysmon                 7.0%                  ║
║  5. sev_info                   6.5%                  ║
╠═══════════════════════════════════════════════════════╣
║  ОБНАРУЖЕНИЕ АТАК                                     ║
║  Ransomware chain:     ✓ (vssadmin + locker.exe)     ║
║  Credential Dump:      ✓ (mimikatz sekurlsa)         ║
║  Kerberoasting:        ✓ (EID 4769 + RC4)            ║
║  DCSync:               ✓ (EID 4662 + 0x100)          ║
║  Linux SUID Escalation:✓ (uid≠euid, euid=0)          ║
║  C2 Beacon:            ✓ (port 4444, base64)         ║
║  Data Exfiltration:    ✓ (BytesSent > 100MB)         ║
╚═══════════════════════════════════════════════════════╝
```

---

## Приложение: Структура файлов

```
Ir_agent_test/
├── scripts/
│   ├── retrain_enterprise.py        ← ОСНОВНОЙ скрипт обучения
│   └── generate_enterprise_data.py  ← Генератор синтетических данных
├── datasets/
│   ├── windows_security_events.json
│   ├── sysmon_events.json
│   ├── active_directory_events.json
│   ├── linux_auditd_events.json
│   ├── linux_auth_events.json
│   ├── kaspersky_events.json
│   └── firewall_events.json
├── models/
│   ├── gradient_boosting_enterprise.pkl  ← обученная модель
│   └── gradient_boosting_production.pkl  ← прод-версия (лучшая)
└── TRAINING_PLAYBOOK.md                  ← этот документ
```
