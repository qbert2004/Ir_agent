"""
Train GradientBoosting model for ML attack detector.

Uses existing training data in training/data/
Saves model to models/gradient_boosting_model.pkl

Usage:
    py scripts/train_gb_model.py
"""
from __future__ import annotations

import json
import os
import pickle
import re
import unicodedata
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    roc_auc_score,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
TRAIN_EVENTS = ROOT / "training" / "data" / "train_events.json"
TRAIN_LABELS = ROOT / "training" / "data" / "train_labels.json"
VAL_EVENTS   = ROOT / "training" / "data" / "val_events.json"
VAL_LABELS   = ROOT / "training" / "data" / "val_labels.json"
MODEL_OUT    = ROOT / "models" / "gradient_boosting_model.pkl"

# ── Feature extraction (mirrors MLAttackDetector.extract_features) ────────────
SUSPICIOUS_KEYWORDS = [
    'mimikatz', 'sekurlsa', 'lsadump', 'lsass', 'procdump', 'comsvcs',
    'ntds.dit', 'sam', 'dumpcreds',
    'invoke-', 'iex', 'invoke-expression', 'downloadstring', 'downloadfile',
    'webclient', 'frombase64', 'reflection', 'assembly',
    'powersploit', 'empire', 'nishang',
    'bypass', 'hidden', 'encoded', '-enc', 'base64',
    '-nop', 'noprofile', '-windowstyle', '-w hidden',
    'amsi', 'etw',
    'cobalt', 'meterpreter', 'reverse', 'payload', 'exploit',
    'beacon', 'stager', 'shellcode',
    'nc.exe', 'netcat', 'ncat', 'socat',
    'psexec', 'winrs', 'wmic process', 'wmiprvse',
    'schtasks', '/create', 'onstart', 'onlogon',
    'sc create', 'sc config', 'reg add',
    'certutil', 'urlcache', 'bitsadmin', '/transfer',
    'mshta', 'javascript:', 'vbscript:',
    'rundll32', 'regsvr32', 'cmstp', 'installutil', 'msbuild',
    'socket', 'subprocess', 'os.dup2', 'connect(',
    '/bin/sh', '/bin/bash', 'chr(',
]

SUSPICIOUS_PROCESSES = [
    'powershell', 'pwsh', 'cmd.exe', 'wscript', 'cscript',
    'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
    'msiexec', 'cmstp', 'installutil', 'msbuild',
    'schtasks', 'at.exe', 'sc.exe', 'reg.exe',
    'python', 'python3', 'python.exe',
    'java', 'java.exe', 'javaw.exe',
    'wmic', 'wmic.exe', 'wmiprvse',
    'psexec', 'psexec64',
    'mimikatz', 'procdump', 'processhacker',
]

HIGH_RISK_EVENT_IDS = {
    4688, 4689, 4624, 4625, 4648, 4672,
    4698, 4699, 4700, 4701, 4702,
    7045, 7036,
    4104, 4103,
    1, 3, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25,
    4720, 4726, 4732, 4756,
}

_HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
}


def _normalize(text: str) -> str:
    chars = [_HOMOGLYPH_MAP.get(c, c) for c in str(text)]
    text = "".join(chars)
    normalized = unicodedata.normalize("NFKD", text)
    return normalized.encode("ascii", "ignore").decode("ascii").lower()


def extract_features(event: dict) -> list[float]:
    """Extract numeric feature vector from a raw event dict."""
    cmdline = _normalize(event.get("command_line", "") or "")
    process = _normalize(event.get("process_name", "") or "")
    script   = _normalize(event.get("script_block_text", "") or "")
    parent   = _normalize(event.get("parent_image", event.get("parent_process", "")) or "")
    user     = _normalize(event.get("user", "") or "")
    image_loaded = _normalize(event.get("image_loaded", "") or "")

    try:
        event_id = int(event.get("event_id", 0) or 0)
    except (ValueError, TypeError):
        event_id = 0

    all_text = f"{cmdline} {script} {process} {image_loaded}"

    features = [
        # 0: high-risk event_id
        float(event_id in HIGH_RISK_EVENT_IDS),
        # 1: suspicious keyword count
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in all_text),
        # 2: suspicious process
        float(any(sp in process for sp in SUSPICIOUS_PROCESSES)),
        # 3: base64 encoded content
        float("-enc" in cmdline or "base64" in cmdline or "frombase64" in all_text),
        # 4: LSASS / credential access
        float("lsass" in all_text or "sekurlsa" in all_text or "procdump" in all_text),
        # 5: PowerShell with bypass flags
        float("powershell" in process and any(f in cmdline for f in ["-enc", "-nop", "bypass", "hidden"])),
        # 6: cmdline length (normalized 0-1, cap at 1000)
        min(len(cmdline) / 1000.0, 1.0),
        # 7: network indicators
        float(any(kw in all_text for kw in ["socket", "connect", "webclient", "downloadstring"])),
        # 8: persistence indicators
        float(any(kw in all_text for kw in ["schtasks", "reg add", "sc create", "runonce", "onlogon"])),
        # 9: defense evasion
        float(any(kw in all_text for kw in ["bypass", "amsi", "etw", "-nop", "hidden", "mshta"])),
        # 10: lateral movement
        float(any(kw in all_text for kw in ["psexec", "winrs", "wmic process"])),
        # 11: C2 indicators
        float(any(kw in all_text for kw in ["cobalt", "beacon", "meterpreter", "shellcode"])),
        # 12: suspicious parent process
        float(any(sp in parent for sp in ["outlook", "winword", "excel", "powerpnt", "iexplore", "firefox"])),
        # 13: Sysmon event
        float(event_id in {1, 3, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25}),
        # 14: privilege-related event
        float(event_id in {4672, 4648, 4624}),
        # 15: script content length (normalized)
        min(len(script) / 2000.0, 1.0),
        # 16: DLL sideloading (suspicious path)
        float(any(p in image_loaded for p in ["users/public", "appdata/local/temp", "downloads"])),
        # 17: logon type 3 or 10 (network/RDP)
        float(str(event.get("logon_type", "")) in ("3", "10")),
    ]

    return features


# ── Load data ─────────────────────────────────────────────────────────────────

def load_dataset(events_path: Path, labels_path: Path):
    print(f"Loading {events_path.name} + {labels_path.name} ...")
    with open(events_path, encoding="utf-8") as f:
        events = json.load(f)

    with open(labels_path, encoding="utf-8") as f:
        labels_raw = json.load(f)

    # Labels can be: int, dict, or string (e.g. "malicious_critical" / "benign")
    def _to_int(l) -> int:
        if isinstance(l, int):
            return l
        if isinstance(l, dict):
            return int(l.get("label", l.get("is_malicious", 0)))
        # string labels
        s = str(l).lower()
        return 0 if s.startswith("benign") else 1

    labels = [_to_int(l) for l in labels_raw]

    print(f"  Events: {len(events)}, Labels: {len(labels)}")
    assert len(events) == len(labels), "Mismatch between events and labels count!"

    X = [extract_features(e) for e in events]
    y = labels
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


# ── Train ──────────────────────────────────────────────────────────────────────

def train():
    print("=" * 60)
    print("IR-Agent GradientBoosting Model Training")
    print("=" * 60)

    X_train, y_train = load_dataset(TRAIN_EVENTS, TRAIN_LABELS)
    X_val, y_val = load_dataset(VAL_EVENTS, VAL_LABELS)

    print(f"\nTrain: {X_train.shape}, Val: {X_val.shape}")
    print(f"Train class distribution: {np.bincount(y_train)}")
    print(f"Val   class distribution: {np.bincount(y_val)}")

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled   = scaler.transform(X_val)

    # Train GradientBoosting
    print("\nTraining GradientBoostingClassifier ...")
    model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
        verbose=1,
    )
    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_val_scaled)
    y_prob = model.predict_proba(X_val_scaled)[:, 1]

    acc = accuracy_score(y_val, y_pred)
    auc = roc_auc_score(y_val, y_prob)

    print(f"\nValidation Results:")
    print(f"  Accuracy: {acc:.4f}")
    print(f"  ROC-AUC:  {auc:.4f}")
    print()
    print(classification_report(y_val, y_pred, target_names=["benign", "malicious"]))

    # Save model
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": model,
        "scaler": scaler,
        "metrics": {
            "accuracy": float(acc),
            "roc_auc": float(auc),
            "train_samples": len(y_train),
            "val_samples": len(y_val),
            "n_features": X_train.shape[1],
            "model_type": "GradientBoostingClassifier",
        },
    }
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)

    print(f"\nModel saved: {MODEL_OUT}")
    print(f"File size: {MODEL_OUT.stat().st_size / 1024:.1f} KB")
    print("=" * 60)


if __name__ == "__main__":
    train()
