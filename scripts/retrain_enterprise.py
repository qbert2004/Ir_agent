# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  IR-Agent Enterprise ML Training Pipeline                                    ║
║  Источники: Windows Events · Sysmon · Active Directory · Linux · Kaspersky  ║
║  Версия: enterprise_v1                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

ЗАПУСК:
    python scripts/retrain_enterprise.py

СТРУКТУРА ДАТАСЕТА (ожидаемые файлы в datasets/):
    windows_security_events.json    — Windows Security Log (EVTX → JSON)
    sysmon_events.json              — Sysmon (EID 1,3,7,8,10,11,22...)
    active_directory_events.json    — AD/DC events (4768,4769,4648,4662...)
    linux_auditd_events.json        — Linux auditd (execve, connect, open)
    linux_auth_events.json          — /var/log/auth.log (SSH, sudo)
    kaspersky_events.json           — Kaspersky ESB/KSC alerts
    firewall_events.json            — Firewall/proxy logs (optional)
    labels.json                     — Ground truth {event_id: 0|1} (optional)
"""

from __future__ import annotations

import json
import os
import re
import sys
import math
import pickle
import logging
import hashlib
import warnings
from pathlib import Path
from typing import Any
from datetime import datetime

import numpy as np

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger("enterprise-train")

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT      = Path(__file__).parent.parent
DATASETS  = ROOT / "datasets"
MODELS    = ROOT / "models"
MODELS.mkdir(exist_ok=True)

OUTPUT_MODEL = MODELS / "gradient_boosting_enterprise.pkl"
PROD_MODEL   = MODELS / "gradient_boosting_decoupled.pkl"   # overwrite prod if better

# ═══════════════════════════════════════════════════════════════════════════════
# ЧАСТЬ 1: НОРМАЛИЗОВАННАЯ СХЕМА СОБЫТИЯ
# ═══════════════════════════════════════════════════════════════════════════════

UNIFIED_SCHEMA = {
    # ── Идентификаторы ─────────────────────────────────────────────────────
    "event_id":          None,   # UUID или хэш события
    "source_type":       None,   # windows_security | sysmon | ad | linux | kaspersky | firewall
    "timestamp":         None,   # ISO-8601

    # ── Хост ──────────────────────────────────────────────────────────────
    "hostname":          None,
    "domain":            None,
    "os_platform":       None,   # windows | linux

    # ── Событие ───────────────────────────────────────────────────────────
    "event_type":        None,   # process_create | network | auth | registry | file | alert
    "raw_event_id":      None,   # Windows EID / Linux audit type / Kaspersky event code
    "severity":          None,   # info | low | medium | high | critical

    # ── Процесс ───────────────────────────────────────────────────────────
    "process_name":      None,
    "process_path":      None,
    "process_pid":       None,
    "parent_process":    None,
    "parent_pid":        None,
    "command_line":      None,
    "process_hash_md5":  None,
    "process_hash_sha256": None,
    "process_signed":    None,   # bool
    "process_signature": None,   # publisher name

    # ── Пользователь/аутентификация ────────────────────────────────────────
    "user":              None,
    "user_domain":       None,
    "user_sid":          None,
    "logon_type":        None,   # interactive | network | service | batch
    "auth_package":      None,   # NTLM | Kerberos | Negotiate
    "privilege_list":    None,

    # ── Сеть ──────────────────────────────────────────────────────────────
    "src_ip":            None,
    "src_port":          None,
    "dst_ip":            None,
    "dst_port":          None,
    "protocol":          None,
    "dns_query":         None,
    "bytes_sent":        None,
    "bytes_recv":        None,

    # ── Файл/реестр ───────────────────────────────────────────────────────
    "file_path":         None,
    "file_hash":         None,
    "registry_key":      None,
    "registry_value":    None,

    # ── AD-специфичные ────────────────────────────────────────────────────
    "target_user":       None,
    "target_computer":   None,
    "kerberos_ticket_type": None,  # TGT | TGS
    "ticket_encryption": None,     # 0x17=RC4 (Kerberoasting), 0x12=AES
    "service_name":      None,
    "group_name":        None,

    # ── Kaspersky-специфичные ─────────────────────────────────────────────
    "threat_name":       None,
    "threat_category":   None,   # Trojan | Exploit | Backdoor | etc.
    "detection_result":  None,   # Detected | Blocked | Disinfected | Not_Found
    "kaspersky_action":  None,

    # ── Linux-специфичные ─────────────────────────────────────────────────
    "syscall":           None,   # execve | connect | open | read | write
    "linux_uid":         None,
    "linux_euid":        None,
    "linux_auid":        None,   # audit UID (session originator)
    "sudo_command":      None,
    "ssh_key_type":      None,

    # ── Метка (для обучения) ───────────────────────────────────────────────
    "label":             None,   # 0=benign, 1=malicious, None=unknown
    "label_source":      None,   # ground_truth | rule_based | kaspersky | manual
}


# ═══════════════════════════════════════════════════════════════════════════════
# ЧАСТЬ 2: ПАРСЕРЫ / НОРМАЛИЗАТОРЫ ДЛЯ КАЖДОГО ИСТОЧНИКА
# ═══════════════════════════════════════════════════════════════════════════════

class BaseNormalizer:
    source_type: str = "unknown"

    def normalize(self, raw: dict) -> dict:
        ev = dict(UNIFIED_SCHEMA)
        ev["source_type"] = self.source_type
        ev["event_id"]    = self._make_id(raw)
        ev["timestamp"]   = raw.get("timestamp") or raw.get("TimeCreated") or raw.get("time")
        ev["hostname"]    = raw.get("hostname") or raw.get("Computer") or raw.get("host")
        return ev

    @staticmethod
    def _make_id(raw: dict) -> str:
        return hashlib.md5(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()[:16]


# ── Windows Security Events ────────────────────────────────────────────────────
class WindowsSecurityNormalizer(BaseNormalizer):
    """
    Источник: Windows Security Event Log (EVTX → JSON через python-evtx, EvtxECmd)
    Ключевые Event IDs:
        4624  Logon success       4625  Logon failure
        4648  Explicit credentials 4672  Special privileges
        4688  Process creation    4698  Scheduled task
        4720  Account created     4728  Group membership
        4740  Account lockout     4776  NTLM auth
        5140  Share access        7045  Service installed
    """
    source_type = "windows_security"

    # EIDs высокого риска
    HIGH_RISK_EIDS = {4648, 4672, 4698, 4720, 4728, 4732, 4756, 7045}
    # EIDs умеренного риска
    MED_RISK_EIDS  = {4688, 4625, 4740, 5140, 5145}

    def normalize(self, raw: dict) -> dict:
        ev = super().normalize(raw)
        ev["os_platform"]    = "windows"
        ev["raw_event_id"]   = int(raw.get("EventID", raw.get("event_id", 0)))
        ev["user"]           = raw.get("SubjectUserName") or raw.get("TargetUserName") or raw.get("user")
        ev["user_domain"]    = raw.get("SubjectDomainName") or raw.get("TargetDomainName")
        ev["user_sid"]       = raw.get("SubjectUserSid") or raw.get("TargetSid")
        ev["logon_type"]     = self._logon_type(raw.get("LogonType"))
        ev["auth_package"]   = raw.get("AuthenticationPackageName") or raw.get("PackageName")
        ev["privilege_list"] = raw.get("PrivilegeList", "")
        ev["src_ip"]         = raw.get("IpAddress") or raw.get("src_ip")
        ev["src_port"]       = raw.get("IpPort")
        ev["target_user"]    = raw.get("TargetUserName")
        ev["target_computer"]= raw.get("TargetServerName") or raw.get("WorkstationName")
        ev["process_name"]   = raw.get("ProcessName") or raw.get("NewProcessName", "")
        ev["command_line"]   = raw.get("CommandLine", "")
        ev["service_name"]   = raw.get("ServiceName") or raw.get("TaskName")

        eid = ev["raw_event_id"]
        if eid in self.HIGH_RISK_EIDS:
            ev["severity"] = "high"
        elif eid in self.MED_RISK_EIDS:
            ev["severity"] = "medium"
        else:
            ev["severity"] = "info"

        ev["event_type"] = self._classify_event_type(eid)
        return ev

    @staticmethod
    def _logon_type(code) -> str | None:
        mapping = {2:"interactive",3:"network",4:"batch",5:"service",7:"unlock",
                   8:"network_cleartext",9:"new_credentials",10:"remote_interactive",11:"cached"}
        try:    return mapping.get(int(code))
        except: return None

    @staticmethod
    def _classify_event_type(eid: int) -> str:
        if eid in (4624,4625,4634,4647,4648,4672,4776,4768,4769,4771): return "auth"
        if eid in (4688,4689,7045,4698):     return "process_create"
        if eid in (4720,4722,4725,4726,4728,4732,4756,4757): return "account_change"
        if eid in (5140,5145,5136,5137):     return "object_access"
        if eid in (4740,):                   return "account_lockout"
        return "other"


# ── Sysmon Events ─────────────────────────────────────────────────────────────
class SysmonNormalizer(BaseNormalizer):
    """
    Источник: Sysinternals Sysmon (Microsoft) → Windows Event Log → JSON
    Ключевые EID:
        1   Process Create          2  File creation time
        3   Network connection      5  Process terminate
        6   Driver load             7  Image load
        8   CreateRemoteThread      10 ProcessAccess (lsass dump!)
        11  FileCreate              12 RegKey create/delete
        13  RegValue set            15 FileCreateStreamHash
        17  PipeCreated             22 DNS query
        23  FileDelete              25 ProcessTampering
    """
    source_type = "sysmon"

    CRITICAL_EIDS = {8, 10, 25}   # remote thread, process access, tampering
    HIGH_EIDS     = {1, 6, 7}     # process create, driver, image load
    MED_EIDS      = {3, 11, 12, 13, 17, 22}

    def normalize(self, raw: dict) -> dict:
        ev = super().normalize(raw)
        ev["os_platform"]     = "windows"
        ev["raw_event_id"]    = int(raw.get("EventID", raw.get("event_id", 0)))
        ev["process_name"]    = self._basename(raw.get("Image") or raw.get("process_name",""))
        ev["process_path"]    = raw.get("Image") or raw.get("process_path")
        ev["process_pid"]     = raw.get("ProcessId") or raw.get("pid")
        ev["parent_process"]  = self._basename(raw.get("ParentImage",""))
        ev["parent_pid"]      = raw.get("ParentProcessId")
        ev["command_line"]    = raw.get("CommandLine") or raw.get("command_line","")
        ev["process_hash_md5"]= self._extract_hash(raw.get("Hashes",""), "MD5")
        ev["process_hash_sha256"] = self._extract_hash(raw.get("Hashes",""), "SHA256")
        ev["process_signed"]  = raw.get("Signed") == "true"
        ev["process_signature"] = raw.get("Signature")
        ev["user"]            = raw.get("User") or raw.get("user")
        ev["dst_ip"]          = raw.get("DestinationIp") or raw.get("destination_ip")
        ev["dst_port"]        = raw.get("DestinationPort") or raw.get("destination_port")
        ev["src_ip"]          = raw.get("SourceIp") or raw.get("source_ip")
        ev["dns_query"]       = raw.get("QueryName") or raw.get("dns_query")
        ev["file_path"]       = raw.get("TargetFilename") or raw.get("file_path")
        ev["registry_key"]    = raw.get("TargetObject")
        ev["registry_value"]  = raw.get("Details")

        eid = ev["raw_event_id"]
        if eid in self.CRITICAL_EIDS:     ev["severity"] = "critical"
        elif eid in self.HIGH_EIDS:       ev["severity"] = "high"
        elif eid in self.MED_EIDS:        ev["severity"] = "medium"
        else:                             ev["severity"] = "info"

        ev["event_type"] = self._classify_sysmon(eid)
        return ev

    @staticmethod
    def _basename(path: str) -> str:
        return Path(path).name if path else ""

    @staticmethod
    def _extract_hash(hashes: str, algo: str) -> str | None:
        m = re.search(rf"{algo}=([0-9A-Fa-f]+)", hashes)
        return m.group(1) if m else None

    @staticmethod
    def _classify_sysmon(eid: int) -> str:
        mapping = {
            1:"process_create", 2:"file_modify", 3:"network_connection",
            5:"process_end",    6:"driver_load",  7:"image_load",
            8:"remote_thread",  10:"process_access", 11:"file_create",
            12:"registry_add",  13:"registry_set",   15:"file_stream",
            17:"pipe_create",   22:"dns_query",       23:"file_delete",
            25:"process_tamper"
        }
        return mapping.get(eid, "other")


# ── Active Directory Events ────────────────────────────────────────────────────
class ActiveDirectoryNormalizer(BaseNormalizer):
    """
    Источник: Domain Controller Security Log (EVTX → JSON)
    Ключевые EIDs для обнаружения атак:
        4768  Kerberos TGT request      (AS-REP Roasting: без preauthentication)
        4769  Kerberos TGS request      (Kerberoasting: enc=0x17/RC4)
        4771  Kerberos pre-auth failed  (brute force)
        4648  Explicit credentials      (Pass-the-Hash / lateral movement)
        4662  Directory access          (DCSync: Access Mask 0x100)
        4776  NTLM auth                 (Pass-the-Hash indicator)
        4720  User created
        4726  User deleted
        4728  Added to global group     (privilege escalation)
        4756  Added to universal group
        4769 + 4648 → Golden Ticket если необычный источник
    """
    source_type = "active_directory"

    # Известные опасные комбинации
    KERBEROAST_ENC = {0x17, 0x18, 23, 24}   # RC4-HMAC → Kerberoasting
    DCSYNC_MASK    = {"0x100", "0x40100"}    # replication permissions

    def normalize(self, raw: dict) -> dict:
        ev = super().normalize(raw)
        ev["os_platform"]        = "windows"
        ev["raw_event_id"]       = int(raw.get("EventID", 0))
        ev["user"]               = raw.get("SubjectUserName") or raw.get("user")
        ev["user_domain"]        = raw.get("SubjectDomainName")
        ev["target_user"]        = raw.get("TargetUserName") or raw.get("ServiceName")
        ev["target_computer"]    = raw.get("ServiceName") or raw.get("TargetServerName")
        ev["src_ip"]             = raw.get("IpAddress") or raw.get("src_ip")
        ev["auth_package"]       = raw.get("AuthenticationPackageName")
        ev["service_name"]       = raw.get("ServiceName")
        ev["group_name"]         = raw.get("GroupName") or raw.get("TargetUserName")
        ev["privilege_list"]     = raw.get("PrivilegeList","")
        ev["logon_type"]         = WindowsSecurityNormalizer._logon_type(raw.get("LogonType"))

        # Kerberos-специфичные
        ticket_enc = raw.get("TicketEncryptionType") or raw.get("ticket_encryption")
        try:    ticket_enc_int = int(str(ticket_enc), 16) if str(ticket_enc).startswith("0x") else int(ticket_enc)
        except: ticket_enc_int = 0
        ev["ticket_encryption"]  = ticket_enc
        ev["kerberos_ticket_type"] = "TGT" if ev["raw_event_id"] == 4768 else "TGS"

        # Severity по логике обнаружения
        eid = ev["raw_event_id"]
        ev["severity"] = self._ad_severity(eid, ticket_enc_int, raw)
        ev["event_type"] = "auth" if eid in (4768,4769,4771,4648,4776) else "account_change"
        return ev

    def _ad_severity(self, eid: int, enc: int, raw: dict) -> str:
        # DCSync
        if eid == 4662 and raw.get("AccessMask","") in self.DCSYNC_MASK:
            return "critical"
        # Kerberoasting (RC4 TGS)
        if eid == 4769 and enc in self.KERBEROAST_ENC:
            return "critical"
        # AS-REP Roasting (TGT без preauth)
        if eid == 4768 and raw.get("PreAuthType","") in ("0","0x0"):
            return "critical"
        # Pass-the-Hash indicators
        if eid == 4648:
            return "high"
        # Brute force
        if eid == 4771:
            return "high"
        # Group changes
        if eid in (4728, 4732, 4756, 4757):
            return "high"
        # Account creation/deletion
        if eid in (4720, 4726):
            return "medium"
        return "info"


# ── Linux auditd Events ────────────────────────────────────────────────────────
class LinuxAuditdNormalizer(BaseNormalizer):
    """
    Источник: Linux auditd → /var/log/audit/audit.log → JSON
    Типы записей (type=):
        EXECVE    Выполнение команды (argc, a0, a1...)
        SYSCALL   Системный вызов (syscall number, process info)
        CONNECT   Сетевое подключение
        OPEN/OPENAT Открытие файла
        WRITE     Запись в файл
        PROCTITLE Имя процесса
        PATH      Путь файла в событии
        CWD       Рабочая директория
        USER_AUTH / USER_LOGIN Аутентификация
        SUDO_CMD  Команда через sudo
        CRED_ACQ  Получение привилегий
    Подозрительные паттерны:
        uid=0 euid=0 из неожиданного процесса
        EXECVE с /tmp, /dev/shm
        CONNECT к внешним IP из серверного процесса
        Изменение /etc/passwd, /etc/shadow, crontab
        Загрузка ядерного модуля (insmod, modprobe)
    """
    source_type = "linux_auditd"

    SENSITIVE_PATHS = {"/etc/passwd", "/etc/shadow", "/etc/sudoers",
                       "/root/.ssh", "/etc/crontab", "/etc/ld.so.preload"}
    SUSPICIOUS_DIRS = {"/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"}
    DANGEROUS_CMDS  = {"nc","ncat","netcat","wget","curl","bash","sh","python",
                       "perl","ruby","php","socat","nmap","masscan","hydra",
                       "mimikatz","msfconsole","msfvenom","empire","cobalt"}

    def normalize(self, raw: dict) -> dict:
        ev = super().normalize(raw)
        ev["os_platform"]  = "linux"
        ev["raw_event_id"] = raw.get("type") or raw.get("event_type","UNKNOWN")
        ev["linux_uid"]    = raw.get("uid") or raw.get("auid")
        ev["linux_euid"]   = raw.get("euid")
        ev["linux_auid"]   = raw.get("auid")
        ev["user"]         = raw.get("acct") or raw.get("user") or f"uid:{ev['linux_uid']}"
        ev["process_name"] = raw.get("comm") or raw.get("process_name","")
        ev["process_path"] = raw.get("exe")  or raw.get("process_path")
        ev["process_pid"]  = raw.get("pid")
        ev["parent_pid"]   = raw.get("ppid")
        ev["command_line"] = self._reconstruct_cmdline(raw)
        ev["syscall"]      = raw.get("syscall") or raw.get("SYSCALL")
        ev["file_path"]    = raw.get("name")  or raw.get("file_path")
        ev["dst_ip"]       = raw.get("addr")  or raw.get("dst_ip")
        ev["dst_port"]     = raw.get("port")  or raw.get("dst_port")
        ev["sudo_command"] = raw.get("cmd")   or raw.get("sudo_command")

        ev["event_type"] = self._classify_linux(raw)
        ev["severity"]   = self._linux_severity(ev)
        return ev

    def _reconstruct_cmdline(self, raw: dict) -> str:
        """Собрать командную строку из полей argc/a0/a1/... auditd"""
        args = []
        for i in range(20):
            arg = raw.get(f"a{i}")
            if arg is None: break
            # auditd кодирует hex если есть спецсимволы
            if re.fullmatch(r"[0-9A-Fa-f]{2,}", arg) and len(arg) % 2 == 0:
                try:    arg = bytes.fromhex(arg).decode("utf-8", errors="replace")
                except: pass
            args.append(arg)
        return " ".join(args) if args else (raw.get("cmd") or raw.get("command_line",""))

    def _classify_linux(self, raw: dict) -> str:
        t = str(raw.get("type","")).upper()
        if "AUTH" in t or "LOGIN" in t or "CRED" in t: return "auth"
        if "EXEC" in t:                                 return "process_create"
        if "CONNECT" in t or "BIND" in t:               return "network_connection"
        if "OPEN" in t or "WRITE" in t or "PATH" in t:  return "file_access"
        if "SYSCALL" in t:                               return "syscall"
        return "other"

    def _linux_severity(self, ev: dict) -> str:
        cmd  = (ev.get("command_line") or "").lower()
        path = (ev.get("file_path")    or "").lower()
        uid  = str(ev.get("linux_uid",""))
        euid = str(ev.get("linux_euid",""))

        # UID 0 или EUID 0 при подозрительном процессе
        if (uid == "0" or euid == "0") and any(d in cmd for d in ["/tmp","/dev/shm"]):
            return "critical"
        # Sensitive file access
        if any(path.startswith(p) for p in self.SENSITIVE_PATHS):
            return "critical"
        # Dangerous commands
        proc = (ev.get("process_name") or "").lower()
        if any(d == proc for d in self.DANGEROUS_CMDS):
            return "high"
        # Execution from suspicious dirs
        if any(d in (ev.get("process_path") or "") for d in self.SUSPICIOUS_DIRS):
            return "high"
        # Sudo
        if ev.get("sudo_command"):
            return "medium"
        return "info"


# ── Linux auth.log ─────────────────────────────────────────────────────────────
class LinuxAuthNormalizer(BaseNormalizer):
    """
    Источник: /var/log/auth.log или /var/log/secure (sshd, sudo, PAM, su)
    Формат: syslog JSON или pre-parsed dict
    Ключевые паттерны:
        sshd: Accepted/Failed password|publickey
        sudo: command run as root
        su: session opened for user root
        PAM: authentication failure
    """
    source_type = "linux_auth"

    def normalize(self, raw: dict) -> dict:
        ev = super().normalize(raw)
        ev["os_platform"]  = "linux"
        ev["user"]         = raw.get("user") or raw.get("account")
        ev["src_ip"]       = raw.get("src_ip") or raw.get("remote_host")
        ev["src_port"]     = raw.get("src_port")
        ev["sudo_command"] = raw.get("command") or raw.get("sudo_command")
        ev["ssh_key_type"] = raw.get("key_type") or raw.get("ssh_key_type")
        ev["process_name"] = raw.get("process") or "sshd"
        msg = (raw.get("message") or raw.get("msg","")).lower()

        if "accepted" in msg:
            ev["event_type"] = "auth"; ev["severity"] = "info"
        elif "failed" in msg or "failure" in msg:
            ev["event_type"] = "auth_failure"; ev["severity"] = "medium"
        elif "invalid user" in msg:
            ev["event_type"] = "auth_failure"; ev["severity"] = "high"
        elif "sudo" in msg:
            ev["event_type"] = "privilege_escalation"
            ev["severity"]   = "medium" if "root" not in msg else "high"
        else:
            ev["event_type"] = "auth"; ev["severity"] = "info"

        # Brute force: много Failed с одного IP → повышаем у вызывающего
        raw_count = raw.get("fail_count", 0)
        if int(raw_count) > 10:
            ev["severity"] = "high"
        if int(raw_count) > 50:
            ev["severity"] = "critical"

        return ev


# ── Kaspersky Endpoint Security ────────────────────────────────────────────────
class KasperskyNormalizer(BaseNormalizer):
    """
    Источник: Kaspersky Endpoint Security (KES) / Kaspersky Security Center (KSC)
    Экспорт: через KSC API, syslog CEF, или KLAUD (Kaspersky Lab AUDit)
    Ключевые события:
        GNRL_EV_DETECT           Обнаружена угроза
        GNRL_EV_OBJ_BLOCKED      Объект заблокирован
        GNRL_EV_OBJ_DELETED      Объект удалён
        GNRL_EV_OBJ_DISINFECTED  Объект вылечен
        GNRL_EV_OBJ_NOT_CURED    Объект не вылечен
        NET_ATTACK               Сетевая атака
        APP_LAUNCH_BLOCKED       Запуск приложения заблокирован
        WEB_CATEGORY_BLOCKED     URL заблокирован
        EXPLOIT_DETECTED         Эксплоит обнаружен
        RANSOMWARE_DETECTED      Ransomware поведение
    Категории угроз:
        Trojan, Backdoor, Exploit, Worm, Virus, Adware, Riskware
        PDM:Trojan (поведенческий детект)
        HEUR:Trojan (эвристика)
        Backdoor.Win32.Agent
        Trojan-Ransom.Win32.*
    """
    source_type = "kaspersky"

    # Паттерны опасных угроз
    CRITICAL_PATTERNS = [
        r"trojan",r"backdoor",r"exploit",r"rootkit",
        r"ransomware",r"trojan-ransom",r"pdm:",r"heur:",
        r"mimikatz",r"meterpreter",r"cobalt",r"empire",
    ]
    HIGH_PATTERNS     = [r"worm",r"virus",r"downloader",r"dropper",r"spyware"]
    MED_PATTERNS      = [r"adware",r"riskware",r"not-a-virus",r"hacktool"]

    def normalize(self, raw: dict) -> dict:
        ev = super().normalize(raw)
        ev["os_platform"]     = raw.get("os_platform","windows")
        ev["threat_name"]     = raw.get("threat_name") or raw.get("VirusName") or raw.get("ThreatName","")
        ev["threat_category"] = raw.get("category") or self._categorize(ev["threat_name"])
        ev["detection_result"]= raw.get("result") or raw.get("DetectionResult","Detected")
        ev["kaspersky_action"]= raw.get("action") or raw.get("Action","")
        ev["file_path"]       = raw.get("object_path") or raw.get("ObjectPath") or raw.get("file_path","")
        ev["process_name"]    = self._basename(ev["file_path"])
        ev["process_hash_md5"]= raw.get("md5") or raw.get("ObjectMD5")
        ev["user"]            = raw.get("user") or raw.get("UserName")
        ev["src_ip"]          = raw.get("src_ip") or raw.get("RemoteHost")
        ev["raw_event_id"]    = raw.get("event_type") or raw.get("EventType","GNRL_EV_DETECT")
        ev["event_type"]      = "threat_detection"
        ev["severity"]        = self._kaspersky_severity(ev["threat_name"], ev["raw_event_id"])

        # Kaspersky → автоматическая метка: Detected = malicious, Disinfected = тоже
        result = (ev["detection_result"] or "").lower()
        if result in ("detected","blocked","not_cured","not_disinfected"):
            ev["label"] = 1
            ev["label_source"] = "kaspersky"

        return ev

    def _categorize(self, name: str) -> str:
        if not name: return "unknown"
        n = name.lower()
        for cat in ["trojan","backdoor","exploit","ransomware","worm","virus","adware","riskware","rootkit","spy"]:
            if cat in n: return cat.capitalize()
        return "Other"

    def _kaspersky_severity(self, name: str, event_type: str) -> str:
        n = (name or "").lower()
        if any(re.search(p, n) for p in self.CRITICAL_PATTERNS): return "critical"
        if any(re.search(p, n) for p in self.HIGH_PATTERNS):     return "high"
        if "ransomware" in (event_type or "").lower():            return "critical"
        if "exploit" in (event_type or "").lower():               return "critical"
        if any(re.search(p, n) for p in self.MED_PATTERNS):      return "medium"
        return "info"

    @staticmethod
    def _basename(path: str) -> str:
        return Path(path).name if path else ""


# ── Firewall / Proxy Events ────────────────────────────────────────────────────
class FirewallNormalizer(BaseNormalizer):
    """
    Источник: Firewall logs (Cisco ASA, PaloAlto, CheckPoint, Windows Firewall, pfSense)
              Proxy logs (Squid, BlueCoat, Zscaler)
    Форматы: CEF, LEEF, syslog, JSON
    Ключевые поля: src_ip, dst_ip, dst_port, action, bytes, url
    """
    source_type = "firewall"

    SUSPICIOUS_PORTS = {4444,4445,1337,31337,8080,8443,9001,9050,6667,1080,
                        3389,5985,5986,22,23,21,2375,2376}

    def normalize(self, raw: dict) -> dict:
        ev = super().normalize(raw)
        ev["src_ip"]    = raw.get("src") or raw.get("src_ip") or raw.get("sourceAddress")
        ev["src_port"]  = raw.get("spt") or raw.get("src_port") or raw.get("sourcePort")
        ev["dst_ip"]    = raw.get("dst") or raw.get("dst_ip") or raw.get("destinationAddress")
        ev["dst_port"]  = self._int(raw.get("dpt") or raw.get("dst_port") or raw.get("destinationPort"))
        ev["protocol"]  = raw.get("proto") or raw.get("protocol","tcp")
        ev["bytes_sent"]= self._int(raw.get("out") or raw.get("bytes_out") or raw.get("bytesSent"))
        ev["bytes_recv"]= self._int(raw.get("in")  or raw.get("bytes_in")  or raw.get("bytesReceived"))
        ev["raw_event_id"] = raw.get("action") or raw.get("act","ALLOW")
        ev["event_type"]   = "network_connection"

        # Severity
        action = str(ev["raw_event_id"]).upper()
        port   = ev["dst_port"] or 0
        sent   = ev["bytes_sent"] or 0
        if action in ("BLOCK","DENY","DROP","REJECT"):
            ev["severity"] = "medium"
        elif port in self.SUSPICIOUS_PORTS:
            ev["severity"] = "high"
        elif sent > 50_000_000:   # > 50MB исходящий трафик
            ev["severity"] = "high"
        elif sent > 10_000_000:
            ev["severity"] = "medium"
        else:
            ev["severity"] = "info"
        return ev

    @staticmethod
    def _int(v) -> int | None:
        try: return int(v)
        except: return None


# ═══════════════════════════════════════════════════════════════════════════════
# ЧАСТЬ 3: FEATURE ENGINEERING (90 признаков для enterprise)
# ═══════════════════════════════════════════════════════════════════════════════

# ── Вспомогательные словари ────────────────────────────────────────────────────

SUSPICIOUS_PROCS = {
    "mimikatz.exe","wce.exe","pwdump.exe","fgdump.exe","procdump.exe",
    "vssadmin.exe","bcdedit.exe","wbadmin.exe","net.exe","net1.exe",
    "psexec.exe","psexecsvc","wmic.exe","mshta.exe","regsvr32.exe",
    "rundll32.exe","certutil.exe","bitsadmin.exe","msiexec.exe",
    "installutil.exe","regasm.exe","regsvcs.exe","csc.exe","cmstp.exe",
    "mavinject.exe","microsoft.workflow.compiler.exe","aspnet_compiler.exe",
    "nc.exe","ncat.exe","socat","xterm","nmap","masscan","sqlmap",
    "cobalt","beacon","meterpreter","empire.exe","pupy","lsass",
}

LOLBAS = {          # Living-off-the-Land Binaries (двойное использование)
    "certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe","rundll32.exe",
    "installutil.exe","csc.exe","msiexec.exe","wmic.exe","cmstp.exe",
    "mavinject.exe","infdefaultinstall.exe","pcwrun.exe","syncappvpublishingserver.exe",
    "appsyncpublishingserver.exe","expand.exe","extrac32.exe","findstr.exe",
    "hh.exe","makecab.exe","odbcconf.exe","pcalua.exe","regasm.exe","regsvc.exe",
    "regsvcs.exe","replace.exe","msdeploy.exe","msdt.exe","nltest.exe",
}

SYSTEM_PATHS = {
    r"c:\windows\system32", r"c:\windows\syswow64",
    r"c:\windows\sysnative", r"c:\program files",
    r"c:\windows\winsxs",
}

SUSPICIOUS_EXTENSIONS = {".vbs",".js",".jse",".wsf",".wsh",".ps1",".bat",
                          ".cmd",".hta",".scr",".pif",".com",".lnk"}

BENIGN_REGISTRY_ROOTS = {
    "hklm\\software\\microsoft\\windows\\currentversion\\run",
    "hklm\\system\\currentcontrolset\\services",
    "hkcu\\software\\microsoft\\windows\\currentversion\\run",
}

SUSPICIOUS_REGISTRY = {
    "winlogon","userinit","shell","appinit_dlls","load","run","runonce",
    "lsa","security packages","notification packages","image file execution",
    "servicedll","grouppolicy","svchost",
}

CRITICAL_LINUX_PATHS = {
    "/etc/passwd","/etc/shadow","/etc/sudoers","/root/.ssh/authorized_keys",
    "/etc/crontab","/etc/cron.d","/etc/ld.so.preload",
    "/proc/sys/kernel","/.bashrc","/.bash_profile","/home/",
}

EXTERNAL_RANGES = [         # RFC 1918 внутренние диапазоны (не внешние)
    re.compile(r"^10\."), re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."), re.compile(r"^127\."), re.compile(r"^::1$"),
]


def is_external_ip(ip: str) -> bool:
    if not ip: return False
    return not any(p.match(ip) for p in EXTERNAL_RANGES)

def is_base64_encoded(s: str) -> bool:
    if not s or len(s) < 20: return False
    b64 = re.search(r"(?:[-]enc(?:oded)?(?:command)?|[- ][Ee])[\s]+([A-Za-z0-9+/=]{20,})", s)
    return bool(b64)

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v/total)*math.log2(v/total) for v in freq.values())

def extract_features_enterprise(ev: dict) -> list[float]:
    """
    Извлечь 90 признаков из нормализованного события.
    Возвращает вектор float[90].
    """
    f = []

    proc    = (ev.get("process_name")  or "").lower().strip()
    path    = (ev.get("process_path")  or "").lower()
    parent  = (ev.get("parent_process")or "").lower().strip()
    cmd     = (ev.get("command_line")  or "").lower()
    etype   = (ev.get("event_type")    or "")
    src     = ev.get("source_type","")
    eid     = ev.get("raw_event_id")
    dst_ip  = ev.get("dst_ip","") or ""
    src_ip  = ev.get("src_ip","") or ""
    dst_port= ev.get("dst_port") or 0
    user    = (ev.get("user")          or "").lower()
    threat  = (ev.get("threat_name")   or "").lower()
    fpath   = (ev.get("file_path")     or "").lower()
    regkey  = (ev.get("registry_key")  or "").lower()
    sev     = ev.get("severity","info")
    linux_uid  = str(ev.get("linux_uid",""))
    linux_euid = str(ev.get("linux_euid",""))

    # ── [1-8] Источник события ──────────────────────────────────────────────
    f.append(float(src == "windows_security"))
    f.append(float(src == "sysmon"))
    f.append(float(src == "active_directory"))
    f.append(float(src == "linux_auditd"))
    f.append(float(src == "linux_auth"))
    f.append(float(src == "kaspersky"))
    f.append(float(src == "firewall"))
    f.append(float(src not in ("windows_security","sysmon","active_directory",
                               "linux_auditd","linux_auth","kaspersky","firewall")))

    # ── [9-14] Тип события ───────────────────────────────────────────────────
    f.append(float(etype == "process_create"))
    f.append(float(etype == "network_connection"))
    f.append(float(etype == "auth"))
    f.append(float(etype == "threat_detection"))
    f.append(float(etype in ("registry_add","registry_set")))
    f.append(float(etype in ("file_create","file_access","file_modify","file_delete")))

    # ── [15-20] Severity ─────────────────────────────────────────────────────
    f.append(float(sev == "critical"))
    f.append(float(sev == "high"))
    f.append(float(sev == "medium"))
    f.append(float(sev == "low"))
    f.append(float(sev == "info"))
    f.append(float(sev in ("critical","high")))

    # ── [21-30] Процесс (Windows + Linux) ───────────────────────────────────
    f.append(float(proc in SUSPICIOUS_PROCS))
    f.append(float(any(proc == p for p in LOLBAS)))
    f.append(float(any(path.startswith(sp) for sp in SYSTEM_PATHS)))
    f.append(float(bool(ev.get("process_signed"))))
    f.append(float(any(cmd.endswith(ext) or f" {ext}" in cmd for ext in SUSPICIOUS_EXTENSIONS)))
    f.append(float("appdata" in path or "temp" in path or "/tmp" in path))
    f.append(float(any(d in path for d in ("/dev/shm",r"c:\users\public",r"c:\windows\temp"))))
    f.append(float(bool(ev.get("process_hash_md5")) or bool(ev.get("process_hash_sha256"))))
    # Parent-child suspicious pairs
    susp_pairs = {("winword.exe","cmd.exe"),("excel.exe","cmd.exe"),
                  ("outlook.exe","powershell.exe"),("explorer.exe","wmic.exe"),
                  ("svchost.exe","powershell.exe"),("lsass.exe","cmd.exe")}
    f.append(float((parent, proc) in susp_pairs))
    # Masquerading: process name close to system process but misspelled
    MASQUERADE = {"svch0st","svchost32","lsas","csrss32","explorer32","rundl132","noteapd","lsaas","wmiprvs"}
    f.append(float(any(m in proc for m in MASQUERADE)))

    # ── [31-40] Командная строка ─────────────────────────────────────────────
    f.append(float(is_base64_encoded(cmd)))
    f.append(float("sekurlsa" in cmd or "logonpasswords" in cmd or "lsadump" in cmd))
    f.append(float("delete shadows" in cmd or "vss" in cmd))
    f.append(float("-nop" in cmd or "-noninteractive" in cmd or "-w hidden" in cmd or "-windowstyle" in cmd))
    f.append(float("downloadstring" in cmd or "downloadfile" in cmd or "invoke-webrequest" in cmd))
    f.append(float("invoke-expression" in cmd or " iex" in cmd or "iex(" in cmd))
    f.append(float("net user" in cmd or "net localgroup" in cmd or "net group" in cmd))
    f.append(float("reg add" in cmd or "reg delete" in cmd or "regedit" in cmd))
    f.append(float("schtasks" in cmd or "taskschd" in cmd or "at " in cmd))
    f.append(float(shannon_entropy(cmd) > 4.5 if len(cmd) > 30 else False))

    # ── [41-50] Сеть ─────────────────────────────────────────────────────────
    f.append(float(is_external_ip(dst_ip)))
    f.append(float(is_external_ip(src_ip)))
    f.append(float(int(dst_port or 0) in (4444,4445,1337,31337,9001,9050,6667,1080)))
    f.append(float(int(dst_port or 0) in (80,443,8080,8443)))
    f.append(float(int(dst_port or 0) in (22,3389,5985,5986,445,135,139)))
    f.append(float(int(dst_port or 0) in (21,25,53,110,143,993,995)))
    # Bytes
    sent = ev.get("bytes_sent") or 0
    f.append(float(int(sent) > 10_000_000))   # > 10MB outbound
    f.append(float(int(sent) > 100_000_000))  # > 100MB outbound (exfil)
    f.append(float(bool(ev.get("dns_query")) and is_external_ip(dst_ip or "1.1.1.1")))
    f.append(float(proc in ("nc.exe","ncat.exe","socat") and etype == "network_connection"))

    # ── [51-60] Аутентификация и пользователи ───────────────────────────────
    f.append(float(ev.get("logon_type") == "network"))
    f.append(float(ev.get("logon_type") == "new_credentials"))
    f.append(float((ev.get("auth_package") or "").upper() == "NTLM"))
    f.append(float("administrator" in user or "admin" in user))
    f.append(float("service" in user or "svc_" in user or "$" in user))
    f.append(float(user in ("","-") or user is None))
    f.append(float("seDebug" in (ev.get("privilege_list") or "")))
    f.append(float("seTakeOwnership" in (ev.get("privilege_list") or "") or
                   "seTcb" in (ev.get("privilege_list") or "")))
    f.append(float(etype == "account_lockout"))
    f.append(float(etype == "auth_failure"))

    # ── [61-70] Active Directory специфичные ────────────────────────────────
    enc = ev.get("ticket_encryption") or ""
    try:   enc_int = int(str(enc),16) if str(enc).startswith("0x") else int(enc)
    except: enc_int = 0
    f.append(float(enc_int in (0x17,0x18,23,24)))  # RC4 — Kerberoasting
    f.append(float(enc_int in (0x11,0x12,17,18)))  # AES — нормальный Kerberos
    f.append(float(ev.get("kerberos_ticket_type") == "TGT"))
    f.append(float(ev.get("kerberos_ticket_type") == "TGS"))
    tgt_user = (ev.get("target_user") or "").lower()
    f.append(float("krbtgt" in tgt_user))           # Golden Ticket
    f.append(float(bool(ev.get("target_computer")) and is_external_ip(src_ip)))
    f.append(float(eid == 4662 and "0x100" in str(ev.get("registry_value",""))))  # DCSync
    f.append(float(eid == 4648))                    # Explicit credentials
    f.append(float(eid in (4728,4732,4756,4757)))   # Group membership change
    f.append(float(eid in (4720,4726)))             # Account create/delete

    # ── [71-80] Linux специфичные ───────────────────────────────────────────
    f.append(float(linux_uid == "0" or linux_euid == "0"))
    f.append(float(linux_uid != linux_euid and linux_euid == "0"))  # SUID escalation
    f.append(float(ev.get("linux_auid","") in ("-1","4294967295","unset")))
    f.append(float(any(fpath.startswith(p) for p in CRITICAL_LINUX_PATHS)))
    f.append(float("/tmp/" in (ev.get("process_path") or "") or
                   "/dev/shm" in (ev.get("process_path") or "")))
    f.append(float(bool(ev.get("sudo_command"))))
    f.append(float("crontab" in cmd or "cron" in fpath))
    f.append(float("insmod" in cmd or "modprobe" in cmd or "rmmod" in cmd))
    f.append(float(ev.get("syscall") in ("execve","execveat")))
    f.append(float(ev.get("syscall") in ("connect","bind","accept")))

    # ── [81-90] Kaspersky + общие угрозы ────────────────────────────────────
    # kas_labeled_malicious: только для событий, размеченных Kaspersky-ом напрямую
    # (НЕ читаем поле label — это был бы label leakage!)
    f.append(float(
        ev.get("source_type") == "kaspersky" and
        (ev.get("detection_result") or "").lower() in ("detected","blocked","not_cured","disinfected")
    ))
    f.append(float(any(p in threat for p in ("trojan","backdoor","ransomware","exploit"))))
    f.append(float("pdm:" in threat or "heur:" in threat))  # Behavioral/heuristic detect
    f.append(float("ransom" in threat))
    f.append(float((ev.get("detection_result") or "").lower() in ("detected","blocked","not_cured")))
    f.append(float("cobalt" in cmd or "beacon" in cmd or "meterpreter" in cmd))
    f.append(float("empire" in cmd or "powersploit" in cmd or "invoke-mimikatz" in cmd))
    f.append(float("psexec" in cmd or "wmiexec" in cmd or "dcomexec" in cmd))
    f.append(float("scheduled task" in etype.lower() or eid == 4698))
    # Lateral movement combination
    f.append(float(
        is_external_ip(dst_ip) and etype == "network_connection" and
        proc not in ("chrome.exe","firefox.exe","msedge.exe","svchost.exe","wuauclt.exe")
    ))

    assert len(f) == 90, f"Feature count error: {len(f)}"
    return f


FEATURE_NAMES = [
    # Source [1-8]
    "src_windows_security","src_sysmon","src_active_directory","src_linux_auditd",
    "src_linux_auth","src_kaspersky","src_firewall","src_other",
    # Event type [9-14]
    "etype_process_create","etype_network","etype_auth","etype_threat_detection",
    "etype_registry","etype_file",
    # Severity [15-20]
    "sev_critical","sev_high","sev_medium","sev_low","sev_info","sev_high_or_critical",
    # Process [21-30]
    "proc_suspicious_exact","proc_lolbas","proc_system_path","proc_signed",
    "proc_suspicious_ext","proc_appdata_temp","proc_suspicious_dir","proc_has_hash",
    "proc_parent_child_susp","proc_masquerade",
    # Cmdline [31-40]
    "cmd_base64_encoded","cmd_lsass_cred","cmd_vss_delete","cmd_ps_hidden",
    "cmd_download","cmd_invoke_expression","cmd_net_user_group","cmd_registry_modify",
    "cmd_schtasks","cmd_high_entropy",
    # Network [41-50]
    "net_dst_external","net_src_external","net_c2_port","net_http_port",
    "net_rdp_smb_port","net_common_svc_port","net_large_transfer_10mb",
    "net_huge_transfer_100mb","net_dns_external","net_netcat",
    # Auth [51-60]
    "auth_network_logon","auth_new_creds","auth_ntlm","auth_admin_user",
    "auth_service_account","auth_empty_user","priv_sedebug","priv_high_privs",
    "auth_lockout","auth_failure",
    # AD [61-70]
    "ad_kerberos_rc4","ad_kerberos_aes","ad_tgt_request","ad_tgs_request",
    "ad_krbtgt_target","ad_cross_domain_access","ad_dcsync","ad_explicit_creds",
    "ad_group_membership_change","ad_account_created_deleted",
    # Linux [71-80]
    "linux_root_uid","linux_suid_escalation","linux_unset_auid","linux_critical_path",
    "linux_tmp_execution","linux_sudo","linux_cron","linux_kernel_module",
    "linux_execve","linux_network_syscall",
    # Kaspersky [81-90]
    "kas_labeled_malicious","kas_major_threat","kas_behavioral_heuristic","kas_ransomware",
    "kas_detection_confirmed","cmd_cobalt_beacon","cmd_empire_powersploit",
    "cmd_psexec_wmi","etype_scheduled_task","net_external_unusual_proc",
]
assert len(FEATURE_NAMES) == 90


# ═══════════════════════════════════════════════════════════════════════════════
# ЧАСТЬ 4: АВТОМАТИЧЕСКАЯ РАЗМЕТКА (rule-based labeling)
# ═══════════════════════════════════════════════════════════════════════════════

def auto_label(ev: dict) -> tuple[int | None, str]:
    """
    Автоматическая разметка если ground_truth не доступна.
    Возвращает (label, reason).

    Приоритет источников меток:
        1. Kaspersky (уже проставлена детектом AV)
        2. Ground truth из labels.json
        3. Правила (rule-based):
           - Критические паттерны → 1 (malicious)
           - Явно безопасные паттерны → 0 (benign)
           - Иначе → None (uncertain, исключаем из обучения)
    """
    # 1. Уже помечено Kaspersky
    if ev.get("label") == 1:
        return 1, "kaspersky_detection"
    if (ev.get("detection_result") or "").lower() in ("disinfected","deleted"):
        return 1, "kaspersky_disinfected"

    cmd    = (ev.get("command_line") or "").lower()
    proc   = (ev.get("process_name") or "").lower()
    threat = (ev.get("threat_name")  or "").lower()
    path   = (ev.get("process_path") or "").lower()
    fpath  = (ev.get("file_path")    or "").lower()
    sev    = ev.get("severity","info")
    uid    = str(ev.get("linux_uid",""))
    euid   = str(ev.get("linux_euid",""))

    # 2. Правила: MALICIOUS ──────────────────────────────────────────────────
    malicious_rules = [
        # Credential theft
        ("sekurlsa" in cmd or "logonpasswords" in cmd,  "rule_lsass_dump"),
        ("lsadump::dcsync" in cmd or "lsadump::sam" in cmd, "rule_dcsync"),
        # Shadow deletion (ransomware)
        ("delete shadows" in cmd and "vssadmin" in proc, "rule_vss_delete"),
        ("recoveryenabled no" in cmd and "bcdedit" in proc, "rule_bcdedit_recovery"),
        # Encoded/obfuscated PS
        (is_base64_encoded(cmd) and "powershell" in proc, "rule_ps_base64"),
        (("-nop" in cmd or "-noninteractive" in cmd) and "-w hidden" in cmd, "rule_ps_hidden"),
        # Download & execute
        ("downloadstring" in cmd or "downloadfile" in cmd, "rule_ps_download"),
        ("iex(" in cmd or " iex " in cmd, "rule_ps_iex"),
        # Suspicious process from temp
        (proc in SUSPICIOUS_PROCS and proc not in ("net.exe","net1.exe"), "rule_susp_proc"),
        # LOLBAS abuse
        ("certutil" in proc and ("-decode" in cmd or "-urlcache" in cmd or "-encode" in cmd), "rule_certutil_abuse"),
        ("mshta" in proc and ("http://" in cmd or "javascript:" in cmd), "rule_mshta_remote"),
        ("regsvr32" in proc and "/s" in cmd and "/u" in cmd, "rule_regsvr32_scrobj"),
        # Kaspersky threat name
        (bool(threat) and any(p in threat for p in ("trojan","backdoor","ransomware","exploit","worm")), "rule_kaspersky_threat"),
        # AD attacks
        (ev.get("raw_event_id") == 4769 and ev.get("ticket_encryption") in ("0x17","0x18","23","24"), "rule_kerberoasting"),
        (ev.get("raw_event_id") == 4648, "rule_pass_the_hash"),
        # Linux privesc
        (uid != "0" and euid == "0" and proc not in ("sudo","su"), "rule_linux_suid"),
        (any(fpath.startswith(p) for p in ("/tmp/","/dev/shm/")), "rule_linux_tmp_exec"),
    ]

    for condition, reason in malicious_rules:
        if condition:
            return 1, reason

    # 3. Правила: BENIGN ─────────────────────────────────────────────────────
    known_benign_procs = {
        "explorer.exe","taskhostw.exe","svchost.exe","lsass.exe",
        "services.exe","wininit.exe","winlogon.exe","csrss.exe",
        "smss.exe","system","idle","spoolsv.exe","fontdrvhost.exe",
        "notepad.exe","wordpad.exe","chrome.exe","firefox.exe",
        "msedge.exe","outlook.exe","winword.exe","excel.exe",
        "wuauclt.exe","msiexec.exe","conhost.exe",
    }

    benign_rules = [
        # Signed system process from system path, no network, no suspicious cmd
        (proc in known_benign_procs and bool(ev.get("process_signed"))
         and not any(s in cmd for s in ("base64","encode","-enc","hidden")),
         "rule_known_signed_proc"),
        # Auth success, normal logon type
        (ev.get("event_type") == "auth" and ev.get("logon_type") == "interactive"
         and sev == "info", "rule_normal_interactive_logon"),
        # Linux system daemon, uid 0, known path
        (uid == "0" and proc in ("sshd","cron","systemd","init","journald","rsyslogd")
         and not any(d in fpath for d in ("/tmp","/dev/shm")), "rule_linux_daemon"),
    ]

    for condition, reason in benign_rules:
        if condition:
            return 0, reason

    return None, "uncertain"


# ═══════════════════════════════════════════════════════════════════════════════
# ЧАСТЬ 5: ЗАГРУЗКА ДАННЫХ
# ═══════════════════════════════════════════════════════════════════════════════

class PassThroughNormalizer(BaseNormalizer):
    """
    'Нормализатор' для событий, уже приведённых к UNIFIED_SCHEMA
    (например, real_attack_events.json от download_real_datasets.py).
    Просто копирует поля 1:1, без дополнительной обработки.
    """
    source_type = "passthrough"

    def normalize(self, raw: dict) -> dict:
        ev = dict(UNIFIED_SCHEMA)
        # Копируем все поля, которые есть в UNIFIED_SCHEMA
        for key in UNIFIED_SCHEMA:
            if key in raw:
                ev[key] = raw[key]
        # Поля которых нет в схеме — игнорируем
        if not ev.get("source_type"):
            ev["source_type"] = raw.get("source_type", "sysmon")
        if not ev.get("event_id"):
            ev["event_id"] = self._make_id(raw)
        return ev


class SplunkXMLNormalizer(BaseNormalizer):
    """
    Парсер Windows Event XML (формат Splunk attack_data / .log файлы).
    Каждая строка = одно событие в XML формате.
    """
    source_type = "sysmon"

    def normalize(self, raw: dict) -> dict:
        """raw уже разобран из XML в dict via xml_log_to_events()"""
        ev = super().normalize(raw)
        eid = int(raw.get("EventID", 0))
        ev["os_platform"]    = "windows"
        ev["raw_event_id"]   = eid
        # EID 10 (ProcessAccess): SourceImage/TargetImage; EID 1: Image/ParentImage
        image = (raw.get("Image") or raw.get("SourceImage") or
                 raw.get("NewProcessName") or "")
        parent= (raw.get("ParentImage") or raw.get("SourceImage") or "")
        ev["process_name"]   = self._basename(image)
        ev["process_path"]   = image
        ev["parent_process"] = self._basename(parent)
        ev["command_line"]   = raw.get("CommandLine") or ""
        ev["user"]           = (raw.get("User") or raw.get("SubjectUserName") or
                                raw.get("SourceUser") or "")
        ev["dst_ip"]         = (raw.get("DestinationIp") or
                                raw.get("DestinationIpAddress") or "")
        ev["dst_port"]       = self._safe_int(raw.get("DestinationPort"))
        ev["src_ip"]         = raw.get("SourceIp") or ""
        # ProcessAccess target (e.g., lsass.exe for T1003)
        if eid == 10:
            ev["target_user"] = self._basename(raw.get("TargetImage") or "")
        hashes               = raw.get("Hashes") or ""
        md5m = re.search(r"MD5=([0-9A-Fa-f]+)", hashes)
        if md5m: ev["process_hash_md5"] = md5m.group(1)
        ev["process_signed"] = str(raw.get("Signed","")).lower() == "true"
        ev["file_path"]      = raw.get("TargetFilename") or raw.get("TargetObject") or ""
        ev["severity"]       = "high" if raw.get("label") == 1 else "info"
        ev["event_type"]     = SysmonNormalizer._classify_sysmon(ev["raw_event_id"])
        ev["label"]          = raw.get("label")
        ev["label_source"]   = raw.get("label_source", "splunk_xml")
        return ev

    @staticmethod
    def _basename(path: str) -> str:
        return Path(path).name.lower() if path else ""

    @staticmethod
    def _safe_int(v) -> int | None:
        try: return int(v)
        except: return None


def xml_log_to_events(fpath: Path, label: int = 1) -> list[dict]:
    """
    Парсить файл из Splunk attack_data (Windows Event XML, одно событие = одна строка).
    Возвращает список словарей с полями из EventData + label.
    """
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        log.warning("xml.etree.ElementTree недоступен")
        return []

    events = []
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    text = fpath.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("<Event"):
            continue
        try:
            root = ET.fromstring(line)
            ev = {"label": label, "label_source": "splunk_xml"}

            # System fields
            sys_node = root.find("e:System", ns) or root.find("System")
            if sys_node is not None:
                eid_node = sys_node.find("e:EventID", ns) or sys_node.find("EventID")
                if eid_node is not None:
                    try: ev["EventID"] = int(eid_node.text.strip())
                    except: pass
                comp = sys_node.find("e:Computer", ns) or sys_node.find("Computer")
                if comp is not None: ev["Computer"] = comp.text

            # EventData fields
            edata = root.find("e:EventData", ns) or root.find("EventData")
            if edata is not None:
                for data in edata:
                    name = data.get("Name")
                    if name and data.text:
                        ev[name] = data.text.strip()
            events.append(ev)
        except ET.ParseError:
            pass

    return events


NORMALIZERS = {
    # Синтетические данные (baseline)
    "windows_security_events.json": WindowsSecurityNormalizer(),
    "sysmon_events.json":           SysmonNormalizer(),
    "active_directory_events.json": ActiveDirectoryNormalizer(),
    "linux_auditd_events.json":     LinuxAuditdNormalizer(),
    "linux_auth_events.json":       LinuxAuthNormalizer(),
    "kaspersky_events.json":        KasperskyNormalizer(),
    "firewall_events.json":         FirewallNormalizer(),
    # ── РЕАЛЬНЫЕ ДАННЫЕ (приоритет) ────────────────────────────────────────────
    # OTRF Security-Datasets + existing training data → уже в UNIFIED_SCHEMA
    # Содержит ALL события: OTRF attacks + real benign sysmon + existing training
    "real_attack_events.json":      PassThroughNormalizer(),
    # sysmon_real_attacks.json и windows_security_real.json — ПОДМНОЖЕСТВА
    # real_attack_events.json, поэтому НЕ грузим их отдельно (дублирование)
    # "sysmon_real_attacks.json":   PassThroughNormalizer(),  # ← subset
    # "windows_security_real.json": PassThroughNormalizer(),  # ← subset
    # Дополнительные реальные benign Sysmon события (из EVTX дампа системы)
    "real_benign_sysmon.json":      SysmonNormalizer(),
}

def load_dataset() -> tuple[list[dict], dict[str, int]]:
    """Загрузить все JSON-датасеты и XML-логи, нормализовать, вернуть события + статистику."""
    events = []
    stats  = {}

    # ── JSON датасеты ─────────────────────────────────────────────────────────
    for fname, normalizer in NORMALIZERS.items():
        fpath = DATASETS / fname
        if not fpath.exists():
            log.warning("Файл не найден: %s (пропускаем)", fname)
            continue

        log.info("Загружаем %s ...", fname)
        try:
            raw_data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            log.error("Ошибка чтения %s: %s", fname, e)
            continue

        if isinstance(raw_data, dict):
            raw_data = list(raw_data.values())
        if not isinstance(raw_data, list):
            log.warning("Неожиданный формат в %s", fname)
            continue

        count = 0
        for raw in raw_data:
            if not isinstance(raw, dict):
                continue
            try:
                ev = normalizer.normalize(raw)
                if ev["label"] is None:
                    ev["label"], ev["label_source"] = auto_label(ev)
                events.append(ev)
                count += 1
            except Exception as e:
                log.debug("Ошибка нормализации события: %s", e)

        stats[fname] = count
        log.info("  → загружено %d событий", count)

    # ── Splunk XML-логи (Windows Event XML, malicious=1) ─────────────────────
    xml_normalizer = SplunkXMLNormalizer()
    splunk_files = {
        "splunk_t1003_sysmon.log":  1,  # T1003 — Credential Dumping
        "splunk_t1059_ps_sysmon.log": 1, # T1059.001 — PowerShell
        "splunk_t1547_sysmon.log":  1,  # T1547.001 — Registry Run Keys
        "splunk_t1136_sysmon.log":  1,  # T1136.001 — Create Account
    }
    for fname, label in splunk_files.items():
        fpath = DATASETS / fname
        if not fpath.exists():
            continue
        log.info("Загружаем Splunk XML %s ...", fname)
        raw_xml_events = xml_log_to_events(fpath, label=label)
        count = 0
        for raw in raw_xml_events:
            try:
                ev = xml_normalizer.normalize(raw)
                if ev["label"] is None:
                    ev["label"], ev["label_source"] = auto_label(ev)
                events.append(ev)
                count += 1
            except Exception as e:
                log.debug("Splunk normalize error: %s", e)
        stats[fname] = count
        log.info("  → загружено %d событий", count)

    return events, stats


# ═══════════════════════════════════════════════════════════════════════════════
# ЧАСТЬ 6: ОБУЧЕНИЕ МОДЕЛИ
# ═══════════════════════════════════════════════════════════════════════════════

def build_xy(events: list[dict]) -> tuple[np.ndarray, np.ndarray, list[int]]:
    """Построить матрицу признаков X и вектор меток y."""
    X_rows, y_rows, indices = [], [], []

    for i, ev in enumerate(events):
        if ev.get("label") is None:
            continue
        try:
            feat = extract_features_enterprise(ev)
            X_rows.append(feat)
            y_rows.append(int(ev["label"]))
            indices.append(i)
        except Exception as e:
            log.debug("Feature extraction error at event %d: %s", i, e)

    return np.array(X_rows, dtype=np.float32), np.array(y_rows, dtype=np.int32), indices


def train_enterprise_model(X: np.ndarray, y: np.ndarray) -> dict:
    """Обучить ансамбль классификаторов с cross-validation."""
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing   import StandardScaler
    from sklearn.ensemble        import HistGradientBoostingClassifier
    from sklearn.calibration     import CalibratedClassifierCV
    from sklearn.metrics         import (roc_auc_score, accuracy_score,
                                         precision_score, recall_score,
                                         f1_score, brier_score_loss,
                                         confusion_matrix)

    log.info("=" * 55)
    log.info("ОБУЧЕНИЕ ENTERPRISE ML МОДЕЛИ")
    log.info("Событий: %d  |  Признаков: %d", len(X), X.shape[1])
    log.info("Malicious: %d (%.1f%%)  Benign: %d (%.1f%%)",
             y.sum(), 100*y.mean(), (y==0).sum(), 100*(1-y.mean()))
    log.info("=" * 55)

    # Масштабирование (нужно для Platt calibration, HistGBM не требует)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/val split (стратифицированный)
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_scaled, y, test_size=0.25, random_state=42, stratify=y
    )

    # ── Алгоритм: HistGradientBoosting (50x быстрее GBM на больших датасетах) ─
    # Аналог LightGBM — обрабатывает 500k событий за минуты вместо часов
    log.info("Обучаем HistGradientBoostingClassifier (fast, large-scale) ...")
    n = len(X_tr)
    gb = HistGradientBoostingClassifier(
        max_iter=300,             # количество деревьев
        max_depth=6,              # глубина
        learning_rate=0.07,
        min_samples_leaf=20,
        l2_regularization=0.1,
        max_bins=255,             # макс. бинов для гистограмм
        class_weight="balanced" if y.mean() < 0.2 else None,
        random_state=42,
        early_stopping=True,      # автостоп если нет прогресса
        n_iter_no_change=20,
        validation_fraction=0.1,
        verbose=0,
    )
    gb.fit(X_tr, y_tr)
    log.info("  Деревьев обучено: %d", gb.n_iter_)

    # ── Калибровка (Platt Scaling, cv=3 для скорости на большом датасете) ────
    log.info("Калибруем вероятности (Platt scaling, cv=3) ...")
    calibrated = CalibratedClassifierCV(gb, cv=3, method="sigmoid")
    calibrated.fit(X_tr, y_tr)

    # ── Метрики ──────────────────────────────────────────────────────────────
    y_pred  = calibrated.predict(X_val)
    y_prob  = calibrated.predict_proba(X_val)[:,1]

    # Youden-J оптимальный порог
    from sklearn.metrics import roc_curve
    fpr_curve, tpr_curve, thresholds = roc_curve(y_val, y_prob)
    j_scores  = tpr_curve - fpr_curve
    best_thresh = float(thresholds[np.argmax(j_scores)])
    y_pred_opt  = (y_prob >= best_thresh).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_val, y_pred_opt).ravel()
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr  = fn / (fn + tp) if (fn + tp) > 0 else 0
    tpr  = tp / (fn + tp) if (fn + tp) > 0 else 0
    auc  = roc_auc_score(y_val, y_prob)
    acc  = accuracy_score(y_val, y_pred_opt)
    prec = precision_score(y_val, y_pred_opt, zero_division=0)
    rec  = recall_score(y_val, y_pred_opt, zero_division=0)
    f1   = f1_score(y_val, y_pred_opt, zero_division=0)
    brier= brier_score_loss(y_val, y_prob)

    log.info("")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("РЕЗУЛЬТАТЫ ОЦЕНКИ (validation set)")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("  Accuracy:          %.4f  (%.2f%%)", acc,  acc*100)
    log.info("  ROC-AUC:           %.4f", auc)
    log.info("  Precision:         %.4f", prec)
    log.info("  Recall / TPR:      %.4f  (%.2f%%)", rec,  rec*100)
    log.info("  F1-Score:          %.4f", f1)
    log.info("  Brier Score:       %.4f  (0=идеал)", brier)
    log.info("  ─────────────────────────────────────────────────────")
    log.info("  FPR (false alarm): %.4f  (%.2f%%)", fpr,  fpr*100)
    log.info("  FNR (missed):      %.4f  (%.2f%%)", fnr,  fnr*100)
    log.info("  TNR (specificity): %.4f  (%.2f%%)", 1-fpr, (1-fpr)*100)
    log.info("  Optimal threshold: %.4f  (Youden-J)", best_thresh)
    log.info("  ─────────────────────────────────────────────────────")
    log.info("  TP=%d  FP=%d  TN=%d  FN=%d", tp, fp, tn, fn)
    log.info("  На 1000 событий:  %d ложных тревог, %d пропущенных атак",
             int(fpr*1000), int(fnr*1000))
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # ── Top feature importances ──────────────────────────────────────────────
    log.info("\nТОП-15 ПРИЗНАКОВ:")
    fi = None
    # HistGBM имеет feature_importances_ в sklearn >= 1.2; fallback на permutation
    if hasattr(gb, 'feature_importances_'):
        fi = gb.feature_importances_
    else:
        try:
            from sklearn.inspection import permutation_importance
            log.info("  (вычисляем permutation importance на подвыборке 10k ...)")
            idx_sub = np.random.default_rng(42).choice(len(X_val),
                          min(10000, len(X_val)), replace=False)
            perm = permutation_importance(calibrated, X_val[idx_sub], y_val[idx_sub],
                                          n_repeats=5, random_state=42, n_jobs=-1)
            fi = perm.importances_mean
        except Exception as e:
            log.warning("  feature importance недоступна: %s", e)

    if fi is not None:
        top_idx = np.argsort(fi)[::-1][:15]
        for rank, i in enumerate(top_idx, 1):
            bar = "█" * int(fi[i]*100)
            log.info("  %2d. %-35s %.4f %s", rank, FEATURE_NAMES[i], fi[i], bar)
    else:
        log.info("  (feature importance недоступна для этого алгоритма)")

    metrics = {
        "accuracy": float(acc), "roc_auc": float(auc),
        "precision": float(prec), "recall": float(rec),
        "f1": float(f1), "brier": float(brier),
        "fpr": float(fpr), "fnr": float(fnr),
        "threshold": float(best_thresh),
        "train_n": len(X_tr), "val_n": len(X_val),
        "n_features": 90,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "note": "Enterprise v1: Windows Security + Sysmon + AD + Linux + Kaspersky + Firewall. 90 features.",
    }

    return {
        "model":          calibrated,
        "base_model":     gb,
        "scaler":         scaler,
        "feature_names":  FEATURE_NAMES,
        "n_features":     90,
        "threshold":      best_thresh,
        "metrics":        metrics,
        "split_strategy": "stratified_25pct_val",
        "train_sources":  list(NORMALIZERS.keys()),
        "version":        "enterprise_v1",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ГЛАВНАЯ ФУНКЦИЯ
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║  IR-Agent Enterprise ML Training Pipeline                            ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print()

    # 1. Загружаем данные
    log.info("Шаг 1/5: Загрузка датасетов из %s ...", DATASETS)
    events, stats = load_dataset()

    if not events:
        log.error("Нет событий для обучения.")
        log.error("Поместите файлы в %s", DATASETS)
        log.error("Поддерживаемые файлы: %s", list(NORMALIZERS.keys()))
        sys.exit(1)

    log.info("Загружено %d событий из %d файлов", len(events), len(stats))
    for fname, cnt in stats.items():
        log.info("  %-40s  %d событий", fname, cnt)

    # 2. Статистика разметки
    labeled   = [e for e in events if e.get("label") is not None]
    malicious = [e for e in labeled if e.get("label") == 1]
    benign    = [e for e in labeled if e.get("label") == 0]
    uncertain = [e for e in events  if e.get("label") is None]

    print()
    log.info("Шаг 2/5: Статистика разметки:")
    log.info("  Всего событий:   %d", len(events))
    log.info("  Размечено:       %d  (%.1f%%)", len(labeled), 100*len(labeled)/max(len(events),1))
    log.info("  └─ Malicious:    %d  (%.1f%%)", len(malicious), 100*len(malicious)/max(len(labeled),1))
    log.info("  └─ Benign:       %d  (%.1f%%)", len(benign),    100*len(benign)/max(len(labeled),1))
    log.info("  Неопределённые:  %d  (исключены)", len(uncertain))

    if len(labeled) < 100:
        log.warning("Слишком мало данных (%d). Нужно минимум 1000 событий.", len(labeled))
        log.warning("Используем существующие датасеты проекта для демонстрации...")
        # Загружаем train_events.json как fallback
        fallback = DATASETS / "train_events.json"
        if fallback.exists():
            _run_on_existing_data(fallback)
        return

    # 3. Построить X, y
    log.info("Шаг 3/5: Извлечение признаков (%d features) ...", 90)
    X, y, _ = build_xy(labeled)
    log.info("  Матрица признаков: %s", X.shape)

    # 4. Обучить
    log.info("Шаг 4/5: Обучение модели ...")
    bundle = train_enterprise_model(X, y)

    # 5. Сохранить
    log.info("Шаг 5/5: Сохранение модели ...")
    with open(OUTPUT_MODEL, "wb") as f:
        pickle.dump(bundle, f)
    log.info("  Сохранено: %s", OUTPUT_MODEL)

    # Сравниваем с текущей prod-моделью и перезаписываем если лучше
    if PROD_MODEL.exists():
        with open(PROD_MODEL, "rb") as f:
            old_bundle = pickle.load(f)
        old_auc  = old_bundle.get("metrics", {}).get("roc_auc", 0)
        new_auc  = bundle["metrics"]["roc_auc"]
        if new_auc > old_auc:
            with open(PROD_MODEL, "wb") as f:
                pickle.dump(bundle, f)
            log.info("  PROD модель ОБНОВЛЕНА: %.4f → %.4f (+%.4f)", old_auc, new_auc, new_auc-old_auc)
        else:
            log.info("  PROD модель НЕ обновлена (%.4f >= %.4f)", old_auc, new_auc)
    else:
        with open(PROD_MODEL, "wb") as f:
            pickle.dump(bundle, f)
        log.info("  PROD модель создана: %s", PROD_MODEL)

    print()
    print("═" * 55)
    print("  ОБУЧЕНИЕ ЗАВЕРШЕНО")
    m = bundle["metrics"]
    print(f"  ROC-AUC:   {m['roc_auc']:.4f}")
    print(f"  Accuracy:  {m['accuracy']:.4f}")
    print(f"  FPR:       {m['fpr']*100:.2f}%")
    print(f"  FNR:       {m['fnr']*100:.2f}%")
    print(f"  F1:        {m['f1']:.4f}")
    print("═" * 55)


def _run_on_existing_data(fpath: Path):
    """Демо-режим: проверить pipeline на существующих данных."""
    log.info("Демо на существующих данных: %s", fpath)
    raw = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
    if isinstance(raw, dict): raw = list(raw.values())
    norm = SysmonNormalizer()
    events = []
    for r in raw[:5000]:
        if isinstance(r, dict):
            ev = norm.normalize(r)
            if ev["label"] is None:
                ev["label"], ev["label_source"] = auto_label(ev)
            events.append(ev)
    labeled = [e for e in events if e["label"] is not None]
    mal = sum(1 for e in labeled if e["label"] == 1)
    log.info("  %d событий загружено, %d размечено, %d malicious", len(events), len(labeled), mal)
    if len(labeled) >= 100:
        X, y, _ = build_xy(labeled)
        bundle   = train_enterprise_model(X, y)
        with open(OUTPUT_MODEL, "wb") as f:
            pickle.dump(bundle, f)
        log.info("  Сохранено: %s", OUTPUT_MODEL)


if __name__ == "__main__":
    main()
