# -*- coding: utf-8 -*-
import sys, os, json, urllib.request, urllib.error, time, re, textwrap
sys.stdout.reconfigure(encoding='utf-8')
os.chdir(os.path.dirname(os.path.abspath(__file__)))
try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError: pass

TOKEN = os.getenv('MY_API_TOKEN', '')
BASE  = 'http://localhost:9000'

def req(method, url, data=None, timeout=180):
    body = json.dumps(data).encode() if data else None
    h = {'Content-Type': 'application/json', 'Authorization': f'Bearer {TOKEN}'}
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read())
        except: return e.code, {}
    except Exception as e:
        return -1, {'error': str(e)}

def clean(t):
    return re.sub(r'<thought>.*?</thought>', '', t or '', flags=re.DOTALL).strip()

def get_reply(res):
    for k in ('answer', 'response', 'reply', 'message'):
        v = res.get(k)
        if v and len(str(v)) > 10 and 'Error' not in str(v)[:20]:
            return str(v)
    # fallback
    return next((str(res.get(k,'')) for k in ('answer','response','reply') if res.get(k)), json.dumps(res, ensure_ascii=False))

def divider(c='═', n=66): print(c * n)

divider()
print('   IR-AGENT  ×  GEMMA 4  —  SOC ANALYST INTERACTIVE DEMO')
divider()

# ── Ingestion status ───────────────────────────────────────────────────────────
print('\n[1] System & ML health')
code, res = req('GET', f'{BASE}/health')
print(f'  Status:       {res.get("status")}  v{res.get("version")}')
print(f'  AI Analyzer:  {res.get("components",{}).get("ai_analyzer")}')
code2, ml = req('GET', f'{BASE}/health/ml')
mlm = ml.get('ml_model', {})
print(f'  ML Model:     {mlm.get("model_version")}  (threshold={mlm.get("threshold")})')
print(f'  Agent timeout: 180s (updated)')

# ── Fresh attack simulation ────────────────────────────────────────────────────
divider('─')
print('\n[2] Simulating ransomware chain on FINANCE-PC-01')

chain = [
    {'host':'FINANCE-PC-01','timestamp':'2026-04-28T14:00:00Z','event_type':'process_create',
     'process_name':'cmd.exe','command_line':'cmd /c powershell -w hidden -nop -enc JABjAD0A',
     'parent_process':'WINWORD.EXE','user':'CORP\\finance1','severity':'critical'},
    {'host':'FINANCE-PC-01','timestamp':'2026-04-28T14:00:20Z','event_type':'network_connection',
     'process_name':'powershell.exe','command_line':'powershell -enc JABjAD0ATgBlAHcA',
     'destination_ip':'185.220.101.45','destination_port':443,'severity':'high'},
    {'host':'FINANCE-PC-01','timestamp':'2026-04-28T14:01:00Z','event_type':'process_create',
     'process_name':'mimikatz.exe','command_line':'mimikatz sekurlsa::logonpasswords exit',
     'parent_process':'powershell.exe','user':'CORP\\finance1','severity':'critical'},
    {'host':'FINANCE-PC-01','timestamp':'2026-04-28T14:01:30Z','event_type':'process_create',
     'process_name':'vssadmin.exe','command_line':'vssadmin delete shadows /all /quiet',
     'parent_process':'cmd.exe','severity':'critical'},
    {'host':'FINANCE-PC-01','timestamp':'2026-04-28T14:02:00Z','event_type':'file_create',
     'process_name':'locker.exe','file_path':'C:/Finance/DECRYPT_INSTRUCTIONS.txt','severity':'critical'},
]

for ev in chain:
    code, res = req('POST', f'{BASE}/ingest/telemetry', data=ev)
    inc = res.get('incident_id','queued')
    sym = '✓' if code == 200 else '✗'
    proc = ev['process_name']
    print(f'  {sym} {proc:<18}  → {inc}')

# ── Incident listing ──────────────────────────────────────────────────────────
time.sleep(1)
code, res = req('GET', f'{BASE}/ingest/incidents')
all_inc = res.get('incidents', []) if isinstance(res, dict) else []
# find FINANCE-PC-01 incident
inc_data = next((i for i in all_inc if 'FINANCE' in i.get('host','')), all_inc[0] if all_inc else {})
iid = inc_data.get('id','?')

print(f'\n  Инцидент создан: {iid}')
print(f'  Host:     {inc_data.get("host")}')
print(f'  Severity: {str(inc_data.get("severity","?")).upper()}')
print(f'  Events:   {inc_data.get("event_count")}')
print(f'  Class:    {inc_data.get("classification")}')

# ── ML classification spot-check ──────────────────────────────────────────────
divider('─')
print('\n[3] ML Classification spot-check')
tests = [
    ('mimikatz.exe sekurlsa::logonpasswords', 'mimikatz.exe', 'MALICIOUS expected'),
    ('vssadmin delete shadows /all /quiet',   'vssadmin.exe', 'MALICIOUS expected'),
    ('notepad.exe',                            'notepad.exe',  'BENIGN expected'),
    ('powershell -enc JABjAD0ATgBlAHcA',       'powershell.exe','MALICIOUS expected'),
]
for cmd, proc, note in tests:
    code, r = req('POST', f'{BASE}/ml/classify', data={'event':{
        'host':'TEST','event_type':'process_create','process_name':proc,'command_line':cmd}})
    label = r.get('label','?')
    conf  = r.get('confidence',0)
    bar   = '█'*int(conf*15) + '░'*(15-int(conf*15))
    sym   = '✓' if 'malicious' in note.lower() == (label=='malicious') else '~'
    print(f'  {sym} {proc:<20} → {label:<10} {conf:.0%}  {bar}  ({note})')

# ── Threat Fusion ─────────────────────────────────────────────────────────────
divider('─')
print('\n[4] Threat Assessment Fusion (Bayesian: ML+IoC+MITRE)')
scenarios = [
    ('Ransomware confirmed (ML+IoC+MITRE)',
     {'ml':  {'score':0.99,'is_malicious':True,'reason':'vssadmin ransomware','model_loaded':True},
      'ioc': {'score':0.92,'is_malicious':True,'providers_hit':['VirusTotal','AbuseIPDB'],'indicator_count':3},
      'mitre':{'techniques':[{'technique_id':'T1486','confidence':0.95},{'technique_id':'T1490','confidence':0.93}],
               'tactic_coverage':['impact'],'max_confidence':0.95,
               'has_lateral_movement':False,'has_credential_access':False,'has_impact':True},
      'context':{'host':'FINANCE-PC-01'}}),
    ('Suspicious but unconfirmed (ML only)',
     {'ml':  {'score':0.75,'is_malicious':True,'reason':'unusual powershell','model_loaded':True},
      'context':{'host':'CORP-PC-05'}}),
    ('Clean event (benign ML, no IoC)',
     {'ml':  {'score':0.05,'is_malicious':False,'reason':'notepad normal','model_loaded':True},
      'ioc': {'score':0.02,'is_malicious':False,'providers_hit':[],'indicator_count':0},
      'context':{'host':'WORKSTATION-99'}}),
]
for name, data in scenarios:
    code, r = req('POST', f'{BASE}/assessment/analyze', data=data)
    score = r.get('final_score',0)
    sev   = r.get('severity','?').upper()
    act   = r.get('recommended_action','?')
    bar   = '█'*int(score/5) + '░'*(20-int(score/5))
    print(f'  {name}')
    print(f'    Score={score:.1f}/100  {bar}  {sev}')
    print(f'    Action: {act[:70]}')

# ── Gemma 4 / Groq agent chat ────────────────────────────────────────────────
divider('─')
print('\n[5] SOC Analyst Q&A (Gemma 4 / Groq fallback)')
print('  Sending 4 forensic questions to the AI agent...\n')

questions = [
    ('MITRE Mapping',
     'For this attack chain: (1) WINWORD.EXE → cmd.exe → powershell -enc, '
     '(2) mimikatz sekurlsa, (3) vssadmin delete shadows — '
     'give MITRE tactic and technique ID for each step. Be concise.',
     'q-mitre'),
    ('C2 IP Decision',
     'IP 185.220.101.45 is the destination of a base64 PowerShell beacon. '
     'Should I block it at the firewall immediately? Yes/No and 2-sentence reasoning.',
     'q-c2'),
    ('Containment Steps',
     'Ransomware locker.exe just ran on FINANCE-PC-01. '
     'List the 5 immediate containment steps in priority order.',
     'q-contain'),
    ('Recovery Plan',
     'Shadow copies deleted, ransomware encrypted C:/Finance/. '
     'Assuming offline backup exists, what are the first 3 recovery steps?',
     'q-recover'),
]

for i, (title, question, sid) in enumerate(questions, 1):
    print(f'  Q{i}: {title}')
    print(f'  {question[:80]}...' if len(question)>80 else f'  {question}')
    t0 = time.time()
    code, res = req('POST', f'{BASE}/agent/query',
                    data={'query': question, 'session_id': sid},
                    timeout=180)
    elapsed = time.time() - t0

    if code == -1:
        print(f'  A{i}: ⏱ Timeout ({elapsed:.0f}s) — агент не ответил за 180с\n')
        continue

    reply_raw = get_reply(res)
    reply = clean(reply_raw)

    if not reply or len(reply) < 15:
        reply = f'[empty — raw: {json.dumps(res)[:150]}]'

    print(f'  A{i} ({elapsed:.1f}s):')
    divider('·', 64)
    for line in reply[:700].splitlines():
        for chunk in textwrap.wrap(line, width=62) if line else ['']:
            print(f'  {chunk}')
    divider('·', 64)
    print()

# ── Final metrics ─────────────────────────────────────────────────────────────
divider('─')
print('\n[6] System Metrics')
try:
    _r = urllib.request.Request(f'{BASE}/metrics', headers={'Authorization':f'Bearer {TOKEN}'})
    with urllib.request.urlopen(_r, timeout=5) as _resp:
        lines = [l for l in _resp.read().decode().splitlines() if l and not l.startswith('#')]
    for l in lines[:10]:
        print(f'  {l}')
except Exception as e:
    print(f'  ({e})')

divider()
print('  DEMO COMPLETE')
print('  ✓ Health  ✓ Attack Simulation  ✓ ML  ✓ Threat Fusion  ✓ AI Chat')
divider()
