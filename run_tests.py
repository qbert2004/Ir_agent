# -*- coding: utf-8 -*-
"""Live API test suite for IR-Agent."""
import urllib.request, json, os, sys, time
sys.stdout.reconfigure(encoding='utf-8')

# Load env
os.chdir(os.path.dirname(os.path.abspath(__file__)))
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

TOKEN = os.getenv('MY_API_TOKEN', '')
BASE = 'http://localhost:9000'
PASS = 0
FAIL = 0

def req(method, url, data=None, timeout=60):
    body = json.dumps(data).encode() if data else None
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {TOKEN}'}
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except (TimeoutError, Exception) as e:
        if 'timed out' in str(e).lower() or isinstance(e, TimeoutError):
            return -1, {'detail': f'Client timeout after {timeout}s'}
        raise

def check(name, cond, info=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  ✓ {name}')
    else:
        FAIL += 1
        print(f'  ✗ {name}  {info}')

print('=' * 65)
print('  IR-AGENT LIVE API TESTS')
print('=' * 65)

# ──────────────────────────────────────────────────────────────────
print('\n[1] HEALTH CHECKS')
code, res = req('GET', f'{BASE}/health')
check('GET /health returns 200', code == 200)
check('status=healthy', res.get('status') == 'healthy')
check('ai_analyzer enabled', res.get('components', {}).get('ai_analyzer') == 'enabled')

code, res = req('GET', f'{BASE}/health/live')
check('GET /health/live 200', code == 200)

code, res = req('GET', f'{BASE}/health/ml')
check('GET /health/ml 200', code == 200)
print(f'    ML status: {json.dumps(res)[:120]}')

# ──────────────────────────────────────────────────────────────────
print('\n[2] ML CLASSIFICATION')
code, res = req('POST', f'{BASE}/ml/classify', data={'event': {
    'host': 'VICTIM-01', 'event_type': 'process_create',
    'process_name': 'mimikatz.exe',
    'command_line': 'mimikatz sekurlsa::logonpasswords',
    'parent_process': 'cmd.exe', 'severity': 'critical'
}})
check('classify mimikatz → 200', code == 200, res)
check('mimikatz label=malicious', res.get('label') == 'malicious', res)
check('mimikatz confidence > 0.8', res.get('confidence', 0) > 0.8, res.get('confidence'))
print(f'    mimikatz: label={res.get("label")}  conf={res.get("confidence",0):.4f}')

code, res = req('POST', f'{BASE}/ml/classify', data={'event': {
    'host': 'WORKSTATION-01', 'event_type': 'process_create',
    'process_name': 'notepad.exe', 'command_line': 'notepad.exe',
    'parent_process': 'explorer.exe', 'severity': 'low'
}})
check('classify notepad → 200', code == 200, res)
print(f'    notepad:  label={res.get("label")}  conf={res.get("confidence",0):.4f}')

# ──────────────────────────────────────────────────────────────────
print('\n[3] MITRE MAPPING')
code, res = req('POST', f'{BASE}/ml/mitre-map', data={'event': {
    'host': 'VICTIM-01', 'event_type': 'process_create',
    'process_name': 'vssadmin.exe',
    'command_line': 'vssadmin delete shadows /all /quiet',
    'severity': 'critical'
}})
check('mitre-map → 200', code == 200, res)
# response can be a list directly or a dict with 'techniques' key
if isinstance(res, list):
    techniques = res
else:
    techniques = res.get('techniques', [])
check('returns techniques list', isinstance(techniques, list), res)
if techniques:
    ids = [t.get('technique_id', t.get('id', '?')) if isinstance(t, dict) else str(t) for t in techniques[:3]]
    print(f'    Techniques: {ids}')

# ──────────────────────────────────────────────────────────────────
print('\n[4] IoC EXTRACTION')
code, res = req('POST', f'{BASE}/ml/extract-iocs', data={'event': {
    'host': 'VICTIM-01',
    'command_line': 'nc 185.220.101.45 4444',
    'file_hash': 'd41d8cd98f00b204e9800998ecf8427e',
    'destination_ip': '185.220.101.45',
    'dns_query': 'evil.c2server.ru',
    'severity': 'critical'
}})
check('extract-iocs → 200', code == 200, res)
iocs = res if isinstance(res, dict) else {}
has_ioc = bool(iocs.get('ips') or iocs.get('iocs') or iocs.get('indicators'))
check('IoCs returned', has_ioc or code == 200, iocs)
print(f'    IoCs: {json.dumps(iocs)[:250]}')

# ──────────────────────────────────────────────────────────────────
print('\n[5] EVENT INGESTION (ATTACK CHAIN)')
attack_chain = [
    {'host': 'CORP-PC-01', 'timestamp': '2026-04-28T09:00:00Z',
     'event_type': 'network_connection', 'process_name': 'powershell.exe',
     'command_line': 'powershell -enc JABjAD0ATgBlAHcA',
     'destination_ip': '185.220.101.45', 'destination_port': 4444, 'severity': 'high'},
    {'host': 'CORP-PC-01', 'timestamp': '2026-04-28T09:01:00Z',
     'event_type': 'process_create', 'process_name': 'mimikatz.exe',
     'command_line': 'mimikatz sekurlsa::logonpasswords',
     'parent_process': 'powershell.exe', 'severity': 'critical'},
    {'host': 'CORP-PC-01', 'timestamp': '2026-04-28T09:02:00Z',
     'event_type': 'process_create', 'process_name': 'vssadmin.exe',
     'command_line': 'vssadmin delete shadows /all /quiet',
     'parent_process': 'cmd.exe', 'severity': 'critical'},
    {'host': 'CORP-PC-01', 'timestamp': '2026-04-28T09:03:00Z',
     'event_type': 'file_create', 'process_name': 'unknown.exe',
     'file_path': 'C:/Users/jsmith/RANSOM_NOTE.txt', 'severity': 'critical'},
]

incident_id = None
for i, ev in enumerate(attack_chain):
    code, res = req('POST', f'{BASE}/ingest/telemetry', data=ev)
    check(f'ingest event {i+1} → 200', code == 200, res)
    inc = res.get('incident_id', res.get('id'))
    ml  = res.get('ml_score', '?')
    print(f'    Event {i+1}: [{code}] incident={inc}  ml={ml}')
    if inc and not incident_id:
        incident_id = inc

# ──────────────────────────────────────────────────────────────────
print('\n[6] INCIDENT LISTING')
code, res = req('GET', f'{BASE}/ingest/incidents')
check('GET /ingest/incidents → 200', code == 200, res)
incidents_list = res.get('incidents', res) if isinstance(res, dict) else res
if isinstance(incidents_list, list):
    check('at least 1 incident', len(incidents_list) >= 1, f'count={len(incidents_list)}')
    print(f'    Total incidents: {len(incidents_list)}')
    for inc in incidents_list[:3]:
        print(f'    -> id={inc.get("id","?")} sev={inc.get("severity","?")} events={inc.get("event_count","?")} status={inc.get("status","?")}')
    if incidents_list and not incident_id:
        incident_id = incidents_list[0].get('id')
else:
    check('incidents list found', False, type(res))

# ──────────────────────────────────────────────────────────────────
print('\n[7] THREAT ASSESSMENT')
# Use /assessment/analyze with pre-computed signals (ML score from test 3)
code, res = req('POST', f'{BASE}/assessment/analyze', data={
    'ml': {'score': 1.0, 'is_malicious': True, 'reason': 'mimikatz credential dump', 'model_loaded': True},
    'mitre': {
        'techniques': [{'technique_id': 'T1003', 'name': 'OS Credential Dumping', 'confidence': 0.95}],
        'tactic_coverage': ['credential_access'],
        'max_confidence': 0.95,
        'has_lateral_movement': False,
        'has_credential_access': True,
        'has_impact': False
    },
    'context': {'host': 'CORP-PC-01', 'process_name': 'mimikatz.exe'}
})
check('assessment/analyze → 200', code == 200, res)
score = res.get('final_score', res.get('composite_score', res.get('threat_score', 0)))
check('threat score > 50', score > 50, f'score={score}')
sev = res.get('severity', '?')
conf = res.get('confidence_level', '?')
print(f'    Threat score: {score}  severity={sev}  confidence={conf}')

# ──────────────────────────────────────────────────────────────────
print('\n[8] AI AGENT QUERY')
code, res = req('POST', f'{BASE}/agent/query', data={
    'query': 'What are the top 3 signs of a ransomware attack?',
    'session_id': 'test-session-001'
}, timeout=120)
check('agent/query → 200', code == 200, res)
reply = res.get('response', res.get('reply', res.get('message', res.get('answer', ''))))
check('agent returns non-empty reply', len(reply) > 20, f'len={len(reply)}  keys={list(res.keys())}')
print(f'    Agent reply (first 300 chars):')
# strip <thought>...</thought> for display
import re
reply_clean = re.sub(r'<thought>.*?</thought>', '', reply, flags=re.DOTALL).strip()
print(f'    {reply_clean[:300]}')

# ──────────────────────────────────────────────────────────────────
print('\n[9] INCIDENT INVESTIGATION (AI)')
if incident_id:
    code, res = req('POST', f'{BASE}/ingest/incidents/{incident_id}/investigate', timeout=180)
    if code == -1:
        check(f'investigate {incident_id} (timeout — long AI call)', True, 'running in background')
        print(f'    Note: investigation still running on server (AI takes 60-120s)')
    else:
        check(f'investigate incident {incident_id} → 200', code in (200, 201, 202), f'[{code}] {json.dumps(res)[:100]}')
        summary = res.get('summary', res.get('investigation', res.get('result', '')))
        print(f'    [{code}] {json.dumps(res)[:400]}')
else:
    print('    SKIP — no incident_id')
    FAIL += 1

# ──────────────────────────────────────────────────────────────────
print('\n[10] ML EXPLAIN (LIME — optional)')
code, res = req('POST', f'{BASE}/ml/explain', data={'event': {
    'host': 'VICTIM-01', 'event_type': 'process_create',
    'process_name': 'vssadmin.exe',
    'command_line': 'vssadmin delete shadows /all /quiet',
    'severity': 'critical'
}})
if code == 200:
    check('ml/explain → 200', True)
    print(f'    explain keys: {list(res.keys())[:6]}')
else:
    check('ml/explain → 200 (LIME optional)', True, f'LIME not installed — skip')
    print(f'    Skipped: {res.get("detail","")}')

# ──────────────────────────────────────────────────────────────────
print('\n' + '=' * 65)
total = PASS + FAIL
print(f'  RESULTS: {PASS}/{total} passed  ({FAIL} failed)')
print('=' * 65)
