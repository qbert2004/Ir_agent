# -*- coding: utf-8 -*-
"""
Скачивает реальные датасеты кибербезопасности и конвертирует их
в формат, совместимый с enterprise ML pipeline.

Источники:
  1. OTRF Security-Datasets (Windows Sysmon / Security Events JSON)
     https://github.com/OTRF/Security-Datasets
  2. Существующие данные проекта (training/data/train_events.json — 132k событий)
  3. Splunk attack_data (отдельные техники ATT&CK)
"""
import sys, os, json, zipfile, io, pathlib, urllib.request, urllib.error
import time, re, hashlib, logging
sys.stdout.reconfigure(encoding='utf-8')
os.chdir(os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format='%(levelname)s  %(message)s')
log = logging.getLogger('downloader')

ROOT     = pathlib.Path(__file__).parent.parent
DATASETS = ROOT / 'datasets'
DATASETS.mkdir(exist_ok=True)

# ── OTRF datasets ──────────────────────────────────────────────────────────────
OTRF_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

# (local_name, remote_path, mitre_technique, label)
OTRF_DATASETS = [
    # CREDENTIAL ACCESS — mimikatz, dcsync, lsass
    ("otrf_mimikatz_logonpasswords.zip",      "credential_access/host/empire_mimikatz_logonpasswords.zip",       "T1003.001", 1),
    ("otrf_mimikatz_lsadump.zip",             "credential_access/host/empire_mimikatz_lsadump_patch.zip",        "T1003.002", 1),
    ("otrf_dcsync.zip",                       "credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip", "T1003.006", 1),
    ("otrf_lsass_comsvcs.zip",                "credential_access/host/psh_lsass_memory_dump_comsvcs.zip",        "T1003.001", 1),
    ("otrf_lsass_dumpert.zip",                "credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip",    "T1003.001", 1),
    ("otrf_ntds_shadow_copy.zip",             "credential_access/host/cmd_dumping_ntds_dit_file_volume_shadow_copy.zip", "T1003.003", 1),
    ("otrf_rubeus_asktgt.zip",                "credential_access/host/empire_shell_rubeus_asktgt_ptt.zip",       "T1558.003", 1),
    ("otrf_sam_access.zip",                   "credential_access/host/empire_mimikatz_sam_access.zip",           "T1003.002", 1),
    # LATERAL MOVEMENT — psexec, wmi, dcom, psremoting
    ("otrf_psexec.zip",                       "lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",       "T1021.002", 1),
    ("otrf_wmi_exec.zip",                     "lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip", "T1047", 1),
    ("otrf_psremoting.zip",                   "lateral_movement/host/empire_psremoting_stager.zip",              "T1021.006", 1),
    ("otrf_wmic_adduser.zip",                 "lateral_movement/host/empire_wmic_add_user_backdoor.zip",         "T1136.001", 1),
    ("otrf_ad_playbook.zip",                  "lateral_movement/host/purplesharp_ad_playbook_I.zip",             "T1021",     1),
    # EXECUTION — powershell, vbs, shellcode
    ("otrf_ps_launcher_vbs.zip",              "execution/host/empire_launcher_vbs.zip",                          "T1059.005", 1),
    # PERSISTENCE — schtasks, services
    ("otrf_schtask_create.zip",               "lateral_movement/host/schtask_create.zip",                        "T1053.005", 1),
]

# ── Splunk attack_data — отдельные техники (NDJSON, gzip) ─────────────────────
SPLUNK_BASE = "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques"

SPLUNK_DATASETS = [
    # T1003 — Credential Dumping
    ("splunk_t1003_sysmon.log",    f"{SPLUNK_BASE}/T1003.001/atomic_red_team/windows-sysmon.log",     "T1003.001", 1),
    # T1059.001 — PowerShell
    ("splunk_t1059_ps_sysmon.log", f"{SPLUNK_BASE}/T1059.001/atomic_red_team/windows-sysmon.log",    "T1059.001", 1),
    # T1055 — Process Injection
    ("splunk_t1055_sysmon.log",    f"{SPLUNK_BASE}/T1055/atomic_red_team/windows-sysmon.log",         "T1055",     1),
    # T1547.001 — Registry Run Keys
    ("splunk_t1547_sysmon.log",    f"{SPLUNK_BASE}/T1547.001/atomic_red_team/windows-sysmon.log",    "T1547.001", 1),
    # T1136 — Create Account
    ("splunk_t1136_sysmon.log",    f"{SPLUNK_BASE}/T1136.001/atomic_red_team/windows-sysmon.log",    "T1136.001", 1),
]

def download_bytes(url: str, timeout=60) -> bytes | None:
    """Скачать URL → bytes. Возвращает None при ошибке."""
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (IR-Agent Dataset Downloader)',
            'Accept': '*/*'
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        log.warning("  Ошибка скачивания %s: %s", url, e)
        return None


def extract_json_from_zip(data: bytes) -> list[dict]:
    """Извлечь все JSON-записи из ZIP архива OTRF."""
    events = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                if not name.endswith('.json'):
                    continue
                log.info("    Парсим %s ...", name)
                content = z.read(name).decode('utf-8', errors='replace')
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            events.append(obj)
                        elif isinstance(obj, list):
                            events.extend([e for e in obj if isinstance(e, dict)])
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        log.warning("  ZIP parse error: %s", e)
    return events


def parse_splunk_log(data: bytes) -> list[dict]:
    """Парсить NDJSON-лог из Splunk attack_data."""
    events = []
    text = data.decode('utf-8', errors='replace')
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        except json.JSONDecodeError:
            pass
    return events


def otrf_to_normalized(raw: dict, label: int, technique: str) -> dict:
    """
    Конвертировать OTRF/Splunk event в наш UNIFIED_SCHEMA формат.
    OTRF использует WinEvent-style: EventID, Channel, Computer, EventData.*
    """
    # Определяем поля в зависимости от структуры события
    event_data = raw.get('EventData', raw.get('event_data', raw.get('winlog', {}).get('event_data', {})))
    system     = raw.get('System', raw.get('system', {}))

    # EventID
    eid_raw = (raw.get('EventID') or raw.get('event_id') or
               system.get('EventID') or raw.get('winlog', {}).get('event_id'))
    try:
        eid = int(str(eid_raw).split('.')[0]) if eid_raw else 0
    except:
        eid = 0

    # Channel → source_type
    channel = (raw.get('Channel') or raw.get('channel') or
               raw.get('winlog', {}).get('channel') or
               system.get('Channel') or '').lower()
    if 'sysmon' in channel:
        source_type = 'sysmon'
    elif 'security' in channel:
        source_type = 'windows_security'
    elif 'powershell' in channel:
        source_type = 'sysmon'
    else:
        source_type = 'sysmon'  # OTRF datasets are mostly Sysmon

    # Process fields
    proc_name = (event_data.get('Image') or event_data.get('NewProcessName') or
                 raw.get('process_name') or raw.get('Image') or '')
    proc_name_base = pathlib.Path(proc_name).name.lower() if proc_name else ''

    parent = (event_data.get('ParentImage') or raw.get('parent_image') or '')
    parent_base = pathlib.Path(parent).name.lower() if parent else ''

    cmd = (event_data.get('CommandLine') or event_data.get('ProcessCommandLine') or
           raw.get('command_line') or raw.get('CommandLine') or '')

    # Target/destination for network events
    dst_ip   = event_data.get('DestinationIp') or event_data.get('DestinationIpAddress') or ''
    dst_port = event_data.get('DestinationPort') or event_data.get('DestPort')

    # Hashes
    hashes = event_data.get('Hashes') or raw.get('hashes') or ''
    md5_m  = re.search(r'MD5=([0-9A-Fa-f]+)', hashes)
    sha256_m = re.search(r'SHA256=([0-9A-Fa-f]+)', hashes)

    # Signed
    signed = str(event_data.get('Signed', '')).lower() == 'true'

    # User
    user = (event_data.get('User') or event_data.get('SubjectUserName') or
            event_data.get('TargetUserName') or raw.get('user') or '')

    # Timestamp
    ts = (raw.get('TimeCreated') or raw.get('@timestamp') or
          system.get('TimeCreated', {}).get('@SystemTime') or
          raw.get('timestamp') or '')

    # Host
    host = (raw.get('Computer') or raw.get('hostname') or
            system.get('Computer') or raw.get('winlog', {}).get('computer_name') or '')

    # File/target paths for other event types
    target_filename = event_data.get('TargetFilename') or event_data.get('TargetObject') or ''

    # Severity heuristic
    sev = 'info'
    if eid in (10, 8, 25):      sev = 'critical'
    elif eid in (1, 7) and proc_name_base in {
        'mimikatz.exe','vssadmin.exe','wce.exe','procdump.exe','wmic.exe',
        'certutil.exe','mshta.exe','regsvr32.exe','rundll32.exe','bitsadmin.exe',
        'cscript.exe','wscript.exe','powershell.exe','cmd.exe',
    }:                           sev = 'high'
    elif eid in (3,) and dst_ip: sev = 'medium'
    elif label == 1:             sev = 'high'

    # Event type
    etype_map = {
        1:'process_create', 2:'file_modify', 3:'network_connection',
        5:'process_end',    6:'driver_load', 7:'image_load',
        8:'remote_thread',  10:'process_access', 11:'file_create',
        12:'registry_add',  13:'registry_set',  15:'file_stream',
        17:'pipe_create',   22:'dns_query',      23:'file_delete',
        25:'process_tamper',
        # Windows Security
        4624:'auth', 4625:'auth_failure', 4648:'auth', 4688:'process_create',
        4698:'process_create', 4720:'account_change', 4728:'account_change',
    }
    event_type = etype_map.get(eid, 'other')

    ev = {
        'source_type':        source_type,
        'event_id':           hashlib.md5(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()[:16],
        'timestamp':          ts,
        'hostname':           host,
        'os_platform':        'windows',
        'raw_event_id':       eid,
        'event_type':         event_type,
        'severity':           sev,
        'process_name':       proc_name_base,
        'process_path':       proc_name,
        'process_hash_md5':   md5_m.group(1) if md5_m else None,
        'process_hash_sha256':sha256_m.group(1) if sha256_m else None,
        'process_signed':     signed,
        'parent_process':     parent_base,
        'command_line':       cmd,
        'user':               user,
        'user_domain':        None,
        'user_sid':           None,
        'user_email':         None,
        'logon_type':         None,
        'auth_package':       event_data.get('AuthenticationPackageName'),
        'privilege_list':     event_data.get('PrivilegeList', '') or '',
        'src_ip':             event_data.get('SourceIp') or event_data.get('SourceAddress') or '',
        'src_port':           event_data.get('SourcePort'),
        'dst_ip':             dst_ip,
        'dst_port':           int(dst_port) if dst_port else None,
        'bytes_sent':         None,
        'bytes_recv':         None,
        'file_path':          target_filename,
        'file_hash':          None,
        'registry_key':       event_data.get('TargetObject'),
        'registry_value':     event_data.get('Details'),
        'target_user':        event_data.get('TargetImage') or event_data.get('TargetUserName'),
        'target_computer':    None,
        'kerberos_ticket_type': None,
        'ticket_encryption':  None,
        'service_name':       None,
        'group_name':         None,
        'threat_name':        None,
        'threat_category':    None,
        'detection_result':   None,
        'kaspersky_action':   None,
        'syscall':            None,
        'linux_uid':          None,
        'linux_euid':         None,
        'linux_auid':         None,
        'sudo_command':       None,
        'ssh_key_type':       None,
        'label':              label,
        'label_source':       f'otrf_{technique}',
        '_mitre_technique':   technique,
    }
    return ev


def adapt_existing_training_data() -> list[dict]:
    """
    Адаптировать существующий train_events.json (132k событий) из training/data/
    в наш UNIFIED_SCHEMA формат.
    """
    train_path  = ROOT / 'training' / 'data' / 'train_events.json'
    labels_path = ROOT / 'training' / 'data' / 'train_labels.json'

    if not train_path.exists():
        log.warning("training/data/train_events.json не найден")
        return []

    log.info("Загружаем training/data/train_events.json ...")
    events = json.loads(train_path.read_text(encoding='utf-8'))
    labels = json.loads(labels_path.read_text(encoding='utf-8')) if labels_path.exists() else None

    log.info("  → %d событий, %d меток", len(events), len(labels) if labels else 0)

    result = []
    for i, raw in enumerate(events):
        label = labels[i] if labels and i < len(labels) else None

        proc_full = raw.get('process_name', '') or ''
        proc_base = pathlib.Path(proc_full).name.lower() if proc_full else ''
        parent_full = raw.get('parent_image', '') or ''
        parent_base = pathlib.Path(parent_full).name.lower() if parent_full else ''
        cmd = raw.get('command_line', '') or ''
        hashes = raw.get('hashes', '') or ''
        md5_m   = re.search(r'MD5=([0-9A-Fa-f]+)', hashes)
        sha256_m= re.search(r'SHA256=([0-9A-Fa-f]+)', hashes)
        signed  = raw.get('signed', False)

        # EID
        eid_raw = raw.get('event_id', 0)
        try:    eid = int(str(eid_raw).split('.')[0])
        except: eid = 0

        channel = (raw.get('channel') or '').lower()
        if 'sysmon' in channel:
            source_type = 'sysmon'
        elif 'security' in channel:
            source_type = 'windows_security'
        else:
            source_type = 'sysmon'

        etype_map = {
            1:'process_create',2:'file_modify',3:'network_connection',
            5:'process_end',6:'driver_load',7:'image_load',8:'remote_thread',
            10:'process_access',11:'file_create',12:'registry_add',13:'registry_set',
            15:'file_stream',17:'pipe_create',22:'dns_query',23:'file_delete',25:'process_tamper',
        }
        event_type = etype_map.get(eid, 'other')

        sev = 'info'
        if label == 1:
            tactic = raw.get('source_tactic', '')
            if 'lateral' in tactic or 'credential' in tactic: sev = 'critical'
            else: sev = 'high'

        ev = {
            'source_type':        source_type,
            'event_id':           hashlib.md5(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()[:16],
            'timestamp':          raw.get('timestamp'),
            'hostname':           raw.get('hostname'),
            'os_platform':        'windows',
            'raw_event_id':       eid,
            'event_type':         event_type,
            'severity':           sev,
            'process_name':       proc_base,
            'process_path':       proc_full,
            'process_hash_md5':   md5_m.group(1) if md5_m else None,
            'process_hash_sha256':sha256_m.group(1) if sha256_m else None,
            'process_signed':     bool(signed),
            'parent_process':     parent_base,
            'command_line':       cmd,
            'user':               raw.get('user', ''),
            'user_domain':        None, 'user_sid': None, 'user_email': None,
            'logon_type':         None, 'auth_package': None, 'privilege_list': '',
            'src_ip': None, 'src_port': None, 'dst_ip': None, 'dst_port': None,
            'bytes_sent': None, 'bytes_recv': None,
            'file_path':          raw.get('image_loaded'),
            'file_hash': None, 'registry_key': None, 'registry_value': None,
            'target_user':        None, 'target_computer': None,
            'kerberos_ticket_type': None, 'ticket_encryption': None,
            'service_name': None, 'group_name': None,
            'threat_name': None, 'threat_category': None,
            'detection_result': None, 'kaspersky_action': None,
            'syscall': None, 'linux_uid': None, 'linux_euid': None,
            'linux_auid': None, 'sudo_command': None, 'ssh_key_type': None,
            'label':              label,
            'label_source':       raw.get('source_type', 'existing_training'),
        }
        result.append(ev)

    return result


def download_otrf() -> list[dict]:
    """Скачать и распарсить OTRF datasets."""
    all_events = []

    for fname, rel_path, technique, label in OTRF_DATASETS:
        url = f"{OTRF_BASE}/{rel_path}"
        cached = DATASETS / fname
        log.info("OTRF [%s] %s ...", technique, fname)

        if cached.exists():
            log.info("  (кэш)")
            data = cached.read_bytes()
        else:
            data = download_bytes(url)
            if data:
                cached.write_bytes(data)
                log.info("  → скачано %d KB", len(data) // 1024)
            else:
                log.warning("  → пропускаем (ошибка скачивания)")
                continue

        events = extract_json_from_zip(data)
        if not events:
            log.warning("  → 0 событий в архиве")
            continue

        normalized = []
        for raw in events:
            try:
                ev = otrf_to_normalized(raw, label, technique)
                normalized.append(ev)
            except Exception as e:
                pass

        log.info("  → %d событий (техника %s, label=%d)", len(normalized), technique, label)
        all_events.extend(normalized)
        time.sleep(0.3)  # rate limit

    return all_events


def download_splunk() -> list[dict]:
    """Скачать и распарсить Splunk attack_data."""
    all_events = []

    for fname, url, technique, label in SPLUNK_DATASETS:
        cached = DATASETS / fname
        log.info("Splunk [%s] %s ...", technique, fname)

        if cached.exists():
            log.info("  (кэш)")
            data = cached.read_bytes()
        else:
            data = download_bytes(url, timeout=30)
            if data:
                cached.write_bytes(data)
                log.info("  → скачано %d KB", len(data) // 1024)
            else:
                log.warning("  → пропускаем")
                continue

        raw_events = parse_splunk_log(data)
        if not raw_events:
            continue

        normalized = []
        for raw in raw_events:
            try:
                ev = otrf_to_normalized(raw, label, technique)
                normalized.append(ev)
            except:
                pass

        log.info("  → %d событий (техника %s)", len(normalized), technique)
        all_events.extend(normalized)
        time.sleep(0.3)

    return all_events


def main():
    log.info("=" * 60)
    log.info("IR-Agent Dataset Downloader")
    log.info("=" * 60)

    all_events = []
    stats = {}

    # 1. OTRF Security Datasets (реальные атаки)
    log.info("\n[1/3] Скачиваем OTRF Security-Datasets ...")
    otrf_events = download_otrf()
    all_events.extend(otrf_events)
    stats['otrf'] = len(otrf_events)
    log.info("OTRF итого: %d событий", len(otrf_events))

    # 2. Splunk attack_data
    log.info("\n[2/3] Скачиваем Splunk attack_data ...")
    splunk_events = download_splunk()
    all_events.extend(splunk_events)
    stats['splunk'] = len(splunk_events)
    log.info("Splunk итого: %d событий", len(splunk_events))

    # 3. Существующие данные проекта (132k событий)
    log.info("\n[3/3] Адаптируем существующие training данные ...")
    existing = adapt_existing_training_data()
    all_events.extend(existing)
    stats['existing'] = len(existing)
    log.info("Existing итого: %d событий", len(existing))

    # Сводка
    log.info("\n" + "=" * 60)
    log.info("ИТОГО СОБЫТИЙ: %d", len(all_events))
    mal = sum(1 for e in all_events if e.get('label') == 1)
    ben = sum(1 for e in all_events if e.get('label') == 0)
    unk = sum(1 for e in all_events if e.get('label') is None)
    log.info("  Malicious:  %d  (%.1f%%)", mal, 100*mal/max(len(all_events),1))
    log.info("  Benign:     %d  (%.1f%%)", ben, 100*ben/max(len(all_events),1))
    log.info("  Uncertain:  %d  (%.1f%%)", unk, 100*unk/max(len(all_events),1))

    # MITRE coverage
    techniques = {}
    for e in all_events:
        t = e.get('_mitre_technique')
        if t:
            techniques[t] = techniques.get(t, 0) + 1
    if techniques:
        log.info("\nMITRE ATT&CK покрытие:")
        for t, cnt in sorted(techniques.items(), key=lambda x: -x[1]):
            log.info("  %s  %d событий", t, cnt)

    # Разбить по источникам для enterprise pipeline
    # Сохраняем атаки как sysmon_events.json (реальные, с меткой 1)
    # и windows_security_events.json

    sysmon_mal  = [e for e in all_events if e.get('source_type') == 'sysmon' and e.get('label') == 1]
    winsec_mal  = [e for e in all_events if e.get('source_type') == 'windows_security' and e.get('label') == 1]
    sysmon_ben  = [e for e in all_events if e.get('source_type') == 'sysmon' and e.get('label') == 0]
    winsec_ben  = [e for e in all_events if e.get('source_type') == 'windows_security' and e.get('label') == 0]
    uncertain   = [e for e in all_events if e.get('label') is None]

    # Сохранить объединённый файл для прямого использования
    out_path = DATASETS / 'real_attack_events.json'
    labeled = [e for e in all_events if e.get('label') is not None]
    out_path.write_text(json.dumps(labeled, ensure_ascii=False, indent=2), encoding='utf-8')
    log.info("\nСохранено: %s (%d размеченных событий)", out_path, len(labeled))

    # Разделить: sysmon_real_attacks.json, windows_security_real.json
    if sysmon_mal:
        p = DATASETS / 'sysmon_real_attacks.json'
        combined_sysmon = sysmon_mal + sysmon_ben
        p.write_text(json.dumps(combined_sysmon, ensure_ascii=False, indent=2), encoding='utf-8')
        log.info("Сохранено: sysmon_real_attacks.json (%d events, %d malicious)",
                 len(combined_sysmon), len(sysmon_mal))

    if winsec_mal or winsec_ben:
        p = DATASETS / 'windows_security_real.json'
        combined_ws = winsec_mal + winsec_ben
        p.write_text(json.dumps(combined_ws, ensure_ascii=False, indent=2), encoding='utf-8')
        log.info("Сохранено: windows_security_real.json (%d events)", len(combined_ws))

    log.info("\n" + "=" * 60)
    log.info("ГОТОВО. Следующий шаг:")
    log.info("  python scripts/retrain_enterprise.py")
    log.info("=" * 60)

    return all_events


if __name__ == '__main__':
    main()
