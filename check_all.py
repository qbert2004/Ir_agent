"""Comprehensive project health check."""
import sys, os
sys.path.insert(0, '.')
os.environ.setdefault('ENVIRONMENT', 'development')

results = []

def check(name, fn):
    try:
        r = fn()
        results.append(('OK', name, r))
        print(f'  OK  {name}: {r}')
    except Exception as e:
        results.append(('FAIL', name, str(e)))
        print(f'  FAIL {name}: {e}')

print('=' * 60)
print('  IR-Agent Full Health Check')
print('=' * 60)

# 1. ML Model
print('\n--- ML Model ---')
def _ml():
    from app.ml.cyber_ml_engine import CyberMLEngine
    e = CyberMLEngine()
    ev = {'event_id':4688,'hostname':'t','process_name':'mimikatz.exe','command_line':'sekurlsa::logonpasswords','user':'a'}
    r = e.classify_event(ev)
    ev2 = {'event_id':4624,'hostname':'t','process_name':'explorer.exe','command_line':'','user':'u'}
    r2 = e.classify_event(ev2)
    return f"loaded, mimikatz={r.confidence:.2f}/{r.label}, benign={r2.confidence:.2f}/{r2.label}"
check('ML Engine', _ml)

# 2. Agent tools
print('\n--- Agent ---')
def _agent():
    from app.services.agent_service import AgentService
    svc = AgentService()
    tools = svc._tool_registry.list_tools()
    names = [t.name if hasattr(t, 'name') else str(t) for t in tools]
    return f'{len(tools)} tools: {", ".join(names)}'
check('Agent Tools', _agent)

# 3. LLM Client
print('\n--- LLM Client ---')
def _llm():
    from app.core.llm_client import LLMClient
    c = LLMClient()
    providers = [p.name for p in c._providers if p.is_available()]
    return f'providers: {providers}'
check('LLM Client', _llm)

# 4. Groq model fix
print('\n--- Groq Model ---')
def _groq():
    from app.core.llm_client import _GroqProvider
    p = _GroqProvider()
    return f'model={p._DEFAULT_MODEL}, available={p.is_available()}'
check('Groq Provider', _groq)

# 5. Config
print('\n--- Config ---')
def _config():
    from app.core.config import settings
    return f'env={settings.environment}, port={settings.api_port}, token={"set" if settings.api_token else "empty"}'
check('Config', _config)

# 6. Vector DB
print('\n--- Vector DB ---')
def _vdb():
    vdb = 'vector_db'
    if not os.path.exists(vdb):
        return 'NOT FOUND'
    files = os.listdir(vdb)
    total = sum(os.path.getsize(os.path.join(vdb,f)) for f in files if os.path.isfile(os.path.join(vdb,f)))
    return f'{len(files)} files, {total/1024:.0f} KB'
check('Vector DB', _vdb)

# 7. Knowledge Base
print('\n--- Knowledge Base ---')
def _kb():
    kb = 'knowledge_base'
    if not os.path.exists(kb):
        return 'NOT FOUND'
    files = os.listdir(kb)
    return f'{len(files)} files'
check('Knowledge Base', _kb)

# 8. Models directory
print('\n--- Models ---')
def _models():
    d = 'models'
    items = []
    for f in os.listdir(d):
        fp = os.path.join(d, f)
        if os.path.isfile(fp):
            s = os.path.getsize(fp)
            items.append(f'{f} ({s/1024/1024:.1f}MB)' if s > 1024*1024 else f'{f} ({s/1024:.0f}KB)')
    return ', '.join(items) if items else 'empty'
check('Models dir', _models)

# 9. Database
print('\n--- Database ---')
def _db():
    if os.path.exists('ir_agent.db'):
        s = os.path.getsize('ir_agent.db')
        return f'ir_agent.db exists ({s/1024:.0f} KB)'
    return 'ir_agent.db not found (will be created on first run)'
check('Database', _db)

# 10. .env check
print('\n--- Environment ---')
def _env():
    if not os.path.exists('.env'):
        return 'MISSING .env file'
    from app.core.config import settings
    issues = []
    if not settings.google_api_key and not settings.groq_api_key:
        issues.append('no LLM API key')
    if settings.api_token:
        issues.append(f'auth enabled (token set)')
    else:
        issues.append('auth disabled (no token)')
    return '; '.join(issues) if issues else 'OK'
check('Environment', _env)

# 11. Incident Manager
print('\n--- Incident Manager ---')
def _inc():
    from app.services.incident_manager import IncidentManager
    mgr = IncidentManager()
    ev = {'event_id':4688,'hostname':'WS-TEST','process_name':'powershell.exe','command_line':'test','user':'u','timestamp':'2026-01-01T00:00:00Z'}
    iid = mgr.correlate_event(ev, 0.8, 'test')
    inc = mgr.get_incident(iid)
    return f'correlation OK, incident={iid}, events={inc["event_count"]}'
check('Incident Manager', _inc)

# 12. ThreatAssessment
print('\n--- Threat Assessment ---')
def _ta():
    from app.assessment.threat_assessment import ThreatAssessmentEngine, MLSignal, IoCSignal, MITRESignal, AgentSignal
    eng = ThreatAssessmentEngine()
    r = eng.assess(
        ml=MLSignal(score=0.9, is_malicious=True, reason='lsass dump'),
        ioc=IoCSignal(score=0.7, is_malicious=True, providers_hit=['VirusTotal']),
        mitre=MITRESignal(techniques=[{'id':'T1003.001','tactic':'credential_access'}], has_credential_access=True),
        agent=AgentSignal(verdict='MALICIOUS', confidence=0.95),
    )
    return f'score={r.final_score:.0f}, severity={r.severity.value}'
check('Threat Assessment', _ta)

# 13. Docker
print('\n--- Docker ---')
def _docker():
    if not os.path.exists('Dockerfile'):
        return 'Dockerfile missing'
    if not os.path.exists('docker-compose.yml'):
        return 'docker-compose.yml missing'
    return 'Dockerfile + docker-compose.yml present'
check('Docker files', _docker)

# Summary
print(f'\n{"=" * 60}')
ok = sum(1 for s,_,_ in results if s == 'OK')
fail = sum(1 for s,_,_ in results if s == 'FAIL')
print(f'  SUMMARY: {ok} OK, {fail} FAIL out of {len(results)} checks')
if fail:
    print('  FAILURES:')
    for s, n, r in results:
        if s == 'FAIL':
            print(f'    - {n}: {r}')
print('=' * 60)
