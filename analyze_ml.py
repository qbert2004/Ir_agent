"""Analyze BOTH ML classifiers — CyberMLEngine (old, 18 feat) vs MLAttackDetector (production)."""
import sys, os
sys.path.insert(0, '.')
os.environ.setdefault('ENVIRONMENT', 'development')

tests = [
    ('mimikatz', {'event_id':4688,'hostname':'WS01','process_name':'mimikatz.exe','command_line':'sekurlsa::logonpasswords','user':'admin'}),
    ('powershell -enc', {'event_id':4688,'hostname':'WS01','process_name':'powershell.exe','command_line':'powershell -enc aQBuAHYAbwBrAGUALQBl','user':'admin'}),
    ('psexec lateral', {'event_id':4688,'hostname':'WS01','process_name':'psexec.exe','command_line':'psexec \\\\dc01 cmd.exe','user':'admin'}),
    ('explorer benign', {'event_id':4624,'hostname':'DC01','process_name':'explorer.exe','command_line':'','user':'user1'}),
    ('notepad benign', {'event_id':4688,'hostname':'WS01','process_name':'notepad.exe','command_line':'C:\\Windows\\notepad.exe','user':'user1'}),
    ('svchost benign', {'event_id':4688,'hostname':'DC01','process_name':'svchost.exe','command_line':'C:\\Windows\\System32\\svchost.exe -k netsvcs','user':'SYSTEM'}),
    ('cmd dir benign', {'event_id':4688,'hostname':'WS01','process_name':'cmd.exe','command_line':'cmd /c dir','user':'user1'}),
    ('logon benign', {'event_id':4624,'hostname':'WS01','process_name':'lsass.exe','command_line':'','user':'user1'}),
    ('chrome benign', {'event_id':4688,'hostname':'WS01','process_name':'chrome.exe','command_line':'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe','user':'user1'}),
]

# ── 1. CyberMLEngine (app.ml.cyber_ml_engine — 18 features, old model) ──────
print("=" * 90)
print("  1. CyberMLEngine (app.ml.cyber_ml_engine, 18 features)")
print("=" * 90)
from app.ml.cyber_ml_engine import CyberMLEngine
engine1 = CyberMLEngine()
print(f"  Model: {type(engine1.event_classifier).__name__}, metrics: {engine1.model_metrics.get('n_features','?')} features")
print(f"  {'Event':<20} {'Score':>6} {'Label':<10}")
print(f"  {'-'*46}")
for name, ev in tests:
    r = engine1.classify_event(ev)
    print(f"  {name:<20} {r.confidence:>6.3f} {r.label:<10}")

# ── 2. MLAttackDetector (app.services.ml_detector — production model) ────────
print(f"\n{'=' * 90}")
print("  2. MLAttackDetector (app.services.ml_detector, production)")
print("=" * 90)
from app.services.ml_detector import get_detector
det = get_detector(threshold=0.5)
print(f"  Version: {det._model_version}, features: {len(det._feature_names)}")
print(f"  Model type: {type(det.model).__name__}" if det.model else "  No model")
print(f"  {'Event':<20} {'Score':>6} {'Malicious':>9} {'Reason'}")
print(f"  {'-'*70}")
for name, ev in tests:
    is_mal, conf, reason = det.predict(ev)
    print(f"  {name:<20} {conf:>6.3f} {'YES' if is_mal else 'no':>9}  {reason[:40]}")

# ── 3. Vector DB check ──────────────────────────────────────────────────────
print(f"\n{'=' * 90}")
print("  3. Vector DB / Knowledge Base")
print("=" * 90)
vdb = 'vector_db'
for f in os.listdir(vdb):
    fp = os.path.join(vdb, f)
    s = os.path.getsize(fp) if os.path.isfile(fp) else 0
    print(f"  {f}: {s} bytes")
kb = 'knowledge_base'
for f in os.listdir(kb):
    fp = os.path.join(kb, f)
    s = os.path.getsize(fp) if os.path.isfile(fp) else 0
    print(f"  {f}: {s} bytes ({s/1024:.1f} KB)")
