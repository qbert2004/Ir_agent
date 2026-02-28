"""
ML Model Validation — Cross-Validation, Confusion Matrix, Leakage Check

Diagnoses the suspicious 99.78% accuracy result from train_gb_model.py.

Tests:
    1. Cross-validation on full dataset (5-fold, stratified)
    2. Holdout validation on val set with class-level metrics
    3. Data leakage check — detect feature overlap between train/val
    4. Class distribution analysis — detect imbalance / synthetic bias
    5. Feature importance analysis — detect dominant features
    6. Calibration check — predicted probabilities vs actual
    7. Source-based split validation (train on real, validate on synthetic)

Usage:
    py scripts/validate_ml_model.py
    py scripts/validate_ml_model.py --full     # includes calibration plot data
    py scripts/validate_ml_model.py --report   # save JSON report
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT         = Path(__file__).parent.parent
TRAIN_EVENTS = ROOT / "training" / "data" / "train_events.json"
TRAIN_LABELS = ROOT / "training" / "data" / "train_labels.json"
VAL_EVENTS   = ROOT / "training" / "data" / "val_events.json"
VAL_LABELS   = ROOT / "training" / "data" / "val_labels.json"
DATA_STATS   = ROOT / "training" / "data" / "data_stats.json"
MODEL_PATH   = ROOT / "models" / "gradient_boosting_model.pkl"
REPORT_OUT   = ROOT / "reports" / "ml_validation_report.json"


# ── Feature extraction (copy from train_gb_model.py) ─────────────────────────

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

FEATURE_NAMES = [
    "high_risk_event_id",
    "suspicious_keyword_count",
    "suspicious_process",
    "base64_encoded",
    "lsass_credential_access",
    "powershell_bypass_flags",
    "cmdline_length_norm",
    "network_indicators",
    "persistence_indicators",
    "defense_evasion",
    "lateral_movement",
    "c2_indicators",
    "suspicious_parent_process",
    "sysmon_event",
    "privilege_event_id",
    "script_length_norm",
    "dll_sideloading",
    "network_logon_type",
]


def _normalize(text: str) -> str:
    chars = [_HOMOGLYPH_MAP.get(c, c) for c in str(text)]
    text = "".join(chars)
    normalized = unicodedata.normalize("NFKD", text)
    return normalized.encode("ascii", "ignore").decode("ascii").lower()


def extract_features(event: dict) -> list:
    cmdline = _normalize(event.get("command_line", "") or "")
    process = _normalize(event.get("process_name", "") or "")
    script   = _normalize(event.get("script_block_text", "") or "")
    parent   = _normalize(event.get("parent_image", event.get("parent_process", "")) or "")
    image_loaded = _normalize(event.get("image_loaded", "") or "")

    try:
        event_id = int(event.get("event_id", 0) or 0)
    except (ValueError, TypeError):
        event_id = 0

    all_text = f"{cmdline} {script} {process} {image_loaded}"

    return [
        float(event_id in HIGH_RISK_EVENT_IDS),
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in all_text),
        float(any(sp in process for sp in SUSPICIOUS_PROCESSES)),
        float("-enc" in cmdline or "base64" in cmdline or "frombase64" in all_text),
        float("lsass" in all_text or "sekurlsa" in all_text or "procdump" in all_text),
        float("powershell" in process and any(f in cmdline for f in ["-enc", "-nop", "bypass", "hidden"])),
        min(len(cmdline) / 1000.0, 1.0),
        float(any(kw in all_text for kw in ["socket", "connect", "webclient", "downloadstring"])),
        float(any(kw in all_text for kw in ["schtasks", "reg add", "sc create", "runonce", "onlogon"])),
        float(any(kw in all_text for kw in ["bypass", "amsi", "etw", "-nop", "hidden", "mshta"])),
        float(any(kw in all_text for kw in ["psexec", "winrs", "wmic process"])),
        float(any(kw in all_text for kw in ["cobalt", "beacon", "meterpreter", "shellcode"])),
        float(any(sp in parent for sp in ["outlook", "winword", "excel", "powerpnt", "iexplore", "firefox"])),
        float(event_id in {1, 3, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25}),
        float(event_id in {4672, 4648, 4624}),
        min(len(script) / 2000.0, 1.0),
        float(any(p in image_loaded for p in ["users/public", "appdata/local/temp", "downloads"])),
        float(str(event.get("logon_type", "")) in ("3", "10")),
    ]


def _to_int(label) -> int:
    if isinstance(label, int):
        return label
    if isinstance(label, dict):
        return int(label.get("label", label.get("is_malicious", 0)))
    s = str(label).lower()
    return 0 if s.startswith("benign") else 1


def load_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_dataset(events_path: Path, labels_path: Path) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    events = load_json(events_path)
    labels_raw = load_json(labels_path)
    labels = [_to_int(l) for l in labels_raw]
    # Keep original string labels for analysis
    raw_str = [str(l).lower() if not isinstance(l, dict) else str(l.get("label", "")) for l in labels_raw]
    X = np.array([extract_features(e) for e in events], dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    return X, y, raw_str


# ── Validation Sections ───────────────────────────────────────────────────────

def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def subsection(title: str):
    print(f"\n── {title} ──")


# ── 1. Dataset Analysis ───────────────────────────────────────────────────────

def analyze_dataset(
    X_train: np.ndarray, y_train: np.ndarray, y_raw_train: List[str],
    X_val: np.ndarray,   y_val: np.ndarray,   y_raw_val: List[str],
) -> Dict[str, Any]:
    section("1. Dataset Analysis")

    train_dist = Counter(y_raw_train)
    val_dist   = Counter(y_raw_val)

    print(f"\nTraining set: {len(y_train)} samples")
    for label, count in sorted(train_dist.items(), key=lambda x: -x[1]):
        pct = count / len(y_train) * 100
        print(f"  {label:30s} {count:6d} ({pct:.1f}%)")

    print(f"\nValidation set: {len(y_val)} samples")
    for label, count in sorted(val_dist.items(), key=lambda x: -x[1]):
        pct = count / len(y_val) * 100
        print(f"  {label:30s} {count:6d} ({pct:.1f}%)")

    # Class imbalance
    n_pos_train = int(np.sum(y_train))
    n_neg_train = int(len(y_train) - n_pos_train)
    ratio = n_pos_train / n_neg_train if n_neg_train > 0 else float("inf")
    print(f"\nClass balance (train): malicious={n_pos_train}, benign={n_neg_train}, ratio={ratio:.2f}")

    imbalance_warning = abs(ratio - 1.0) > 0.3
    if imbalance_warning:
        print(f"  ⚠ WARNING: Class imbalance ratio={ratio:.2f} — accuracy metric may be misleading!")
    else:
        print(f"  ✓ Class balance is acceptable ({ratio:.2f})")

    # Check data stats file
    stats_info = {}
    if DATA_STATS.exists():
        stats = load_json(DATA_STATS)
        synthetic_n = stats.get("sources", {}).get("synthetic", 0)
        total = stats.get("total_events", 1)
        synthetic_pct = synthetic_n / total * 100
        print(f"\nData sources: {stats.get('sources', {})}")
        print(f"Synthetic data: {synthetic_n:,} / {total:,} = {synthetic_pct:.1f}%")
        stats_info["synthetic_pct"] = synthetic_pct
        if synthetic_pct > 40:
            print(f"  ⚠ WARNING: {synthetic_pct:.0f}% synthetic data — HIGH leakage risk!")
            print(f"    Synthetic events may be generated by same keywords used in features,")
            print(f"    leading to artificially perfect separation.")
        else:
            print(f"  ✓ Synthetic data ratio is acceptable")

    return {
        "train_size": len(y_train),
        "val_size": len(y_val),
        "train_distribution": dict(train_dist),
        "val_distribution": dict(val_dist),
        "class_ratio": ratio,
        "imbalance_warning": imbalance_warning,
        **stats_info,
    }


# ── 2. Feature Analysis ───────────────────────────────────────────────────────

def analyze_features(
    X_train: np.ndarray, y_train: np.ndarray,
    X_val: np.ndarray, y_val: np.ndarray,
) -> Dict[str, Any]:
    section("2. Feature Analysis")

    n_features = X_train.shape[1]

    # Feature means per class
    print("\nFeature means by class (train):")
    print(f"  {'Feature':35s} {'Benign':>8} {'Malicious':>10} {'Separation':>12}")
    print(f"  {'-'*70}")

    feature_stats = []
    dominant_features = []

    for i in range(n_features):
        name = FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"feature_{i}"
        benign_mean = float(np.mean(X_train[y_train == 0, i]))
        malicious_mean = float(np.mean(X_train[y_train == 1, i]))
        separation = abs(malicious_mean - benign_mean)

        print(f"  {name:35s} {benign_mean:8.3f} {malicious_mean:10.3f} {separation:12.3f}")

        feature_stats.append({
            "name": name,
            "benign_mean": round(benign_mean, 4),
            "malicious_mean": round(malicious_mean, 4),
            "separation": round(separation, 4),
        })

        # Highly discriminative features (>0.7 separation) are leakage suspects
        if separation > 0.7:
            dominant_features.append((name, separation))

    if dominant_features:
        print(f"\n  ⚠ Highly discriminative features (separation > 0.7):")
        for name, sep in sorted(dominant_features, key=lambda x: -x[1]):
            print(f"    {name}: {sep:.3f}")
        print(f"\n  These features may be used both for data generation AND classification,")
        print(f"  causing inflated accuracy. This is the primary leakage vector.")

    # Feature variance check — zero-variance features are useless
    variances = np.var(X_train, axis=0)
    zero_var = [FEATURE_NAMES[i] for i in range(n_features) if variances[i] < 1e-6]
    if zero_var:
        print(f"\n  ⚠ Zero-variance features (useless): {zero_var}")
    else:
        print(f"\n  ✓ All features have non-zero variance")

    return {
        "feature_stats": feature_stats,
        "dominant_features": [f[0] for f in dominant_features],
        "zero_variance_features": zero_var,
        "leakage_risk": "HIGH" if len(dominant_features) >= 3 else "MEDIUM" if dominant_features else "LOW",
    }


# ── 3. Model Loading and Basic Eval ──────────────────────────────────────────

def load_model(model_path: Path):
    if not model_path.exists():
        print(f"  ✗ Model not found at {model_path}")
        print("  Run: py scripts/train_gb_model.py")
        return None, None

    with open(model_path, "rb") as f:
        payload = pickle.load(f)

    model = payload["model"]
    scaler = payload.get("scaler")
    saved_metrics = payload.get("metrics", {})

    print(f"  Model: {saved_metrics.get('model_type', 'unknown')}")
    print(f"  Saved metrics: accuracy={saved_metrics.get('accuracy', '?'):.4f}, "
          f"roc_auc={saved_metrics.get('roc_auc', '?'):.4f}")
    print(f"  Train samples: {saved_metrics.get('train_samples', '?')}")
    print(f"  Features: {saved_metrics.get('n_features', '?')}")

    return model, scaler


# ── 4. Holdout Validation ─────────────────────────────────────────────────────

def holdout_validation(
    model, scaler,
    X_val: np.ndarray, y_val: np.ndarray,
) -> Dict[str, Any]:
    section("3. Holdout Validation (val set)")

    try:
        from sklearn.metrics import (
            accuracy_score, roc_auc_score, classification_report,
            confusion_matrix, precision_score, recall_score, f1_score,
        )
    except ImportError:
        print("  sklearn not installed, skipping")
        return {}

    X_scaled = scaler.transform(X_val) if scaler else X_val

    y_pred = model.predict(X_scaled)
    y_prob = model.predict_proba(X_scaled)[:, 1]

    acc  = accuracy_score(y_val, y_pred)
    auc  = roc_auc_score(y_val, y_prob)
    prec = precision_score(y_val, y_pred, zero_division=0)
    rec  = recall_score(y_val, y_pred, zero_division=0)
    f1   = f1_score(y_val, y_pred, zero_division=0)

    cm = confusion_matrix(y_val, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print(f"\n  Accuracy:  {acc:.4f}")
    print(f"  ROC-AUC:   {auc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1-Score:  {f1:.4f}")

    print(f"\n  Confusion Matrix:")
    print(f"                 Predicted")
    print(f"                 Benign  Malicious")
    print(f"  Actual Benign  {tn:6d}  {fp:9d}")
    print(f"  Actual Malic.  {fn:6d}  {tp:9d}")

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    print(f"\n  False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"  False Negative Rate: {fnr:.4f} ({fnr*100:.2f}%)")

    print(f"\n  Per-class report:")
    print(classification_report(y_val, y_pred, target_names=["benign", "malicious"]))

    # Suspicion flags
    if acc > 0.99:
        print(f"  ⚠ SUSPICIOUS: Accuracy {acc:.4f} > 99% is extremely high")
        print(f"    Possible causes:")
        print(f"    a) Data leakage — features are same as used to generate synthetic data")
        print(f"    b) Train/val split is from same synthetic distribution (not independent)")
        print(f"    c) Val set is too similar to train (e.g. same augmented events)")
    if auc > 0.999:
        print(f"  ⚠ SUSPICIOUS: ROC-AUC {auc:.4f} ≈ 1.0 — near-perfect discrimination")

    return {
        "accuracy": float(acc),
        "roc_auc": float(auc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "false_positive_rate": float(fpr),
        "false_negative_rate": float(fnr),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "suspicious_accuracy": acc > 0.99,
        "suspicious_auc": auc > 0.999,
    }


# ── 5. Cross-Validation ───────────────────────────────────────────────────────

def cross_validate(
    X: np.ndarray, y: np.ndarray,
    n_folds: int = 5,
) -> Dict[str, Any]:
    section(f"4. {n_folds}-Fold Stratified Cross-Validation")

    try:
        from sklearn.model_selection import StratifiedKFold, cross_val_score
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
    except ImportError:
        print("  sklearn not installed, skipping")
        return {}

    print(f"\n  Running {n_folds}-fold CV on {len(y)} samples...")
    print(f"  (This may take 1-2 minutes)")

    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GradientBoostingClassifier(
            n_estimators=100,  # reduced for CV speed
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
        )),
    ])

    cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

    scores_acc = cross_val_score(pipe, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
    scores_auc = cross_val_score(pipe, X, y, cv=cv, scoring="roc_auc", n_jobs=-1)
    scores_f1  = cross_val_score(pipe, X, y, cv=cv, scoring="f1", n_jobs=-1)

    print(f"\n  {'Metric':12s}  {'Mean':>8}  {'Std':>8}  {'Min':>8}  {'Max':>8}")
    print(f"  {'-'*55}")
    for name, scores in [("Accuracy", scores_acc), ("ROC-AUC", scores_auc), ("F1", scores_f1)]:
        print(f"  {name:12s}  {np.mean(scores):8.4f}  {np.std(scores):8.4f}  "
              f"{np.min(scores):8.4f}  {np.max(scores):8.4f}")

    # Detect high variance (overfitting signal)
    acc_cv_std = float(np.std(scores_acc))
    if acc_cv_std > 0.02:
        print(f"\n  ⚠ High accuracy variance across folds: std={acc_cv_std:.4f}")
        print(f"    This may indicate the model is sensitive to train/val split choice.")
    elif np.mean(scores_acc) > 0.99 and acc_cv_std < 0.005:
        print(f"\n  ⚠ Very high mean accuracy ({np.mean(scores_acc):.4f}) with low variance ({acc_cv_std:.4f})")
        print(f"    This suggests the dataset itself is too easy — features perfectly separate classes.")
        print(f"    Root cause: synthetic data generation uses the same keyword lists as features.")
    else:
        print(f"\n  ✓ Cross-validation scores look consistent")

    return {
        "accuracy": {"mean": float(np.mean(scores_acc)), "std": float(np.std(scores_acc)),
                     "min": float(np.min(scores_acc)), "max": float(np.max(scores_acc))},
        "roc_auc":  {"mean": float(np.mean(scores_auc)), "std": float(np.std(scores_auc)),
                     "min": float(np.min(scores_auc)), "max": float(np.max(scores_auc))},
        "f1":       {"mean": float(np.mean(scores_f1)),  "std": float(np.std(scores_f1)),
                     "min": float(np.min(scores_f1)),  "max": float(np.max(scores_f1))},
        "suspicious": np.mean(scores_acc) > 0.99 and float(np.std(scores_acc)) < 0.005,
    }


# ── 6. Leakage Check ──────────────────────────────────────────────────────────

def leakage_check(
    X_train: np.ndarray, y_train: np.ndarray,
    X_val: np.ndarray,   y_val: np.ndarray,
) -> Dict[str, Any]:
    section("5. Data Leakage Check")

    subsection("5a. Feature distribution similarity (train vs val)")

    print(f"\n  {'Feature':35s}  {'Train Mean':>10}  {'Val Mean':>10}  {'Diff':>8}")
    print(f"  {'-'*70}")

    distribution_diffs = []
    high_similarity_count = 0

    for i in range(X_train.shape[1]):
        name = FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"f{i}"
        tm = float(np.mean(X_train[:, i]))
        vm = float(np.mean(X_val[:, i]))
        diff = abs(tm - vm)
        distribution_diffs.append(diff)

        flag = "⚠" if diff < 0.001 else " "  # suspiciously similar
        if diff < 0.001:
            high_similarity_count += 1
        print(f"  {flag} {name:33s}  {tm:10.4f}  {vm:10.4f}  {diff:8.4f}")

    if high_similarity_count > len(FEATURE_NAMES) * 0.6:
        print(f"\n  ⚠ LEAKAGE WARNING: {high_similarity_count}/{len(FEATURE_NAMES)} features have")
        print(f"    near-identical distributions in train and val sets.")
        print(f"    This strongly suggests train/val were split from the same synthetic pool.")
    else:
        print(f"\n  ✓ Feature distributions differ between train and val (normal leakage level)")

    subsection("5b. Duplicate events check (exact feature vector overlap)")

    # Check for exact feature vector duplicates between train and val
    train_set = set(map(tuple, X_train.tolist()))
    val_set   = set(map(tuple, X_val.tolist()))
    overlap   = train_set & val_set

    overlap_pct = len(overlap) / len(val_set) * 100 if val_set else 0
    print(f"\n  Unique train feature vectors: {len(train_set):,}")
    print(f"  Unique val feature vectors:   {len(val_set):,}")
    print(f"  Overlapping vectors:          {len(overlap):,} ({overlap_pct:.1f}%)")

    if overlap_pct > 30:
        print(f"  ⚠ HIGH LEAKAGE: {overlap_pct:.1f}% of val feature vectors appear in train!")
        print(f"    The model has seen these exact feature patterns during training.")
    elif overlap_pct > 10:
        print(f"  ⚠ MODERATE leakage: {overlap_pct:.1f}% overlap. May inflate metrics.")
    else:
        print(f"  ✓ Low feature vector overlap ({overlap_pct:.1f}%)")

    subsection("5c. Class distribution consistency check")

    train_pos_ratio = float(np.mean(y_train))
    val_pos_ratio   = float(np.mean(y_val))
    ratio_diff = abs(train_pos_ratio - val_pos_ratio)

    print(f"\n  Train malicious ratio: {train_pos_ratio:.4f}")
    print(f"  Val   malicious ratio: {val_pos_ratio:.4f}")
    print(f"  Difference: {ratio_diff:.4f}")

    if ratio_diff < 0.005:
        print(f"  ⚠ Near-identical class ratios — likely stratified split from same pool")
        print(f"    This means train and val are NOT independent datasets.")
    else:
        print(f"  ✓ Class ratios differ ({ratio_diff:.4f}) — reasonable split")

    return {
        "feature_distribution_similarity": high_similarity_count,
        "feature_overlap_pct": round(overlap_pct, 2),
        "class_ratio_diff": round(ratio_diff, 4),
        "leakage_verdict": (
            "HIGH"   if overlap_pct > 30 or high_similarity_count > len(FEATURE_NAMES) * 0.6
            else "MEDIUM" if overlap_pct > 10
            else "LOW"
        ),
    }


# ── 7. Feature Importance ─────────────────────────────────────────────────────

def feature_importance(model, scaler, X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, Any]:
    section("6. Feature Importance (Permutation)")

    try:
        from sklearn.inspection import permutation_importance
    except ImportError:
        print("  sklearn.inspection not available, skipping")
        return {}

    X_scaled = scaler.transform(X_val) if scaler else X_val

    print("\n  Computing permutation importance on val set (n_repeats=5)...")
    result = permutation_importance(
        model, X_scaled, y_val,
        n_repeats=5, random_state=42, n_jobs=-1
    )

    importance_mean = result.importances_mean
    importance_std  = result.importances_std

    # Sort by importance
    indices = np.argsort(importance_mean)[::-1]

    print(f"\n  {'Rank':>4}  {'Feature':35s}  {'Importance':>12}  {'±Std':>8}")
    print(f"  {'-'*65}")

    top_features = []
    for rank, idx in enumerate(indices[:10], 1):
        name = FEATURE_NAMES[idx] if idx < len(FEATURE_NAMES) else f"f{idx}"
        imp  = float(importance_mean[idx])
        std  = float(importance_std[idx])
        print(f"  {rank:4d}  {name:35s}  {imp:12.4f}  {std:8.4f}")
        top_features.append({"rank": rank, "name": name, "importance": round(imp, 4), "std": round(std, 4)})

    # Check if one feature dominates
    if len(indices) > 0 and importance_mean[indices[0]] > 0.5:
        dominant = FEATURE_NAMES[indices[0]] if indices[0] < len(FEATURE_NAMES) else f"f{indices[0]}"
        print(f"\n  ⚠ DOMINANT FEATURE: '{dominant}' accounts for >{importance_mean[indices[0]]*100:.0f}% of model performance")
        print(f"    This suggests the model relies heavily on one feature — fragile in real-world use.")

    return {"top_features": top_features}


# ── 8. Calibration Check ──────────────────────────────────────────────────────

def calibration_check(model, scaler, X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, Any]:
    section("7. Probability Calibration Check")

    X_scaled = scaler.transform(X_val) if scaler else X_val
    y_prob = model.predict_proba(X_scaled)[:, 1]

    # Bucket probabilities and check actual positive rate
    n_bins = 10
    print(f"\n  {'Bucket':20s}  {'Predicted':>10}  {'Actual':>10}  {'Count':>8}  {'Calibrated?':>12}")
    print(f"  {'-'*70}")

    calibration_errors = []
    bucket_stats = []

    for i in range(n_bins):
        low  = i / n_bins
        high = (i + 1) / n_bins
        mask = (y_prob >= low) & (y_prob < high)
        if mask.sum() == 0:
            continue

        predicted_mean = float(np.mean(y_prob[mask]))
        actual_rate    = float(np.mean(y_val[mask]))
        count          = int(mask.sum())
        error          = abs(predicted_mean - actual_rate)
        calibrated     = "✓" if error < 0.1 else "⚠"

        calibration_errors.append(error)
        bucket_stats.append({
            "bucket": f"{low:.1f}-{high:.1f}",
            "predicted": round(predicted_mean, 3),
            "actual": round(actual_rate, 3),
            "count": count,
            "error": round(error, 3),
        })

        print(f"  {low:.1f}-{high:.1f}:              {predicted_mean:10.3f}  {actual_rate:10.3f}  "
              f"{count:8d}  {calibrated:>12}")

    mean_calib_error = float(np.mean(calibration_errors)) if calibration_errors else 0
    print(f"\n  Mean Calibration Error: {mean_calib_error:.4f}")

    if mean_calib_error > 0.15:
        print(f"  ⚠ Poorly calibrated: probabilities don't reflect actual frequencies")
    else:
        print(f"  ✓ Model probabilities are reasonably calibrated")

    # Check for probability concentration
    extreme_pct = float(np.mean((y_prob < 0.05) | (y_prob > 0.95)) * 100)
    print(f"\n  Events with extreme probabilities (< 5% or > 95%): {extreme_pct:.1f}%")
    if extreme_pct > 90:
        print(f"  ⚠ Model is extremely overconfident — nearly all predictions are near 0 or 1")
        print(f"    This is consistent with data leakage (perfect feature separation)")

    return {
        "mean_calibration_error": mean_calib_error,
        "extreme_probability_pct": round(extreme_pct, 1),
        "bucket_stats": bucket_stats,
    }


# ── 9. Summary and Verdict ────────────────────────────────────────────────────

def print_verdict(
    holdout: Dict, cv: Dict, leakage: Dict,
    dataset: Dict, features: Dict,
):
    section("VALIDATION SUMMARY AND VERDICT")

    issues = []
    recommendations = []

    acc = holdout.get("accuracy", 0)
    auc = holdout.get("roc_auc", 0)
    cv_acc = cv.get("accuracy", {}).get("mean", 0)
    leakage_verdict = leakage.get("leakage_verdict", "UNKNOWN")
    overlap_pct = leakage.get("feature_overlap_pct", 0)
    synthetic_pct = dataset.get("synthetic_pct", 0)
    dominant = features.get("dominant_features", [])

    print(f"\n  Accuracy:        {acc:.4f}")
    print(f"  ROC-AUC:         {auc:.4f}")
    print(f"  CV Accuracy:     {cv_acc:.4f}")
    print(f"  Leakage Level:   {leakage_verdict}")
    print(f"  Feature Overlap: {overlap_pct:.1f}%")
    print(f"  Synthetic Data:  {synthetic_pct:.1f}%")

    print(f"\n  ISSUES IDENTIFIED:")

    if synthetic_pct > 40:
        issues.append(f"[CRITICAL] {synthetic_pct:.0f}% synthetic data contamination")
        recommendations.append(
            "Collect more real-world event data (EVTX logs, Sysmon, real SIEM data)"
        )
        recommendations.append(
            "Use stratified split by SOURCE — train on real events, validate on synthetic (not random split)"
        )

    if leakage_verdict in ("HIGH", "MEDIUM") or overlap_pct > 20:
        issues.append(f"[HIGH] Feature leakage: {overlap_pct:.1f}% feature vector overlap")
        recommendations.append(
            "Data generation (augment_data.py) uses same keyword patterns as feature extraction — "
            "synthetic malicious events are trivially separable. Use adversarial examples or vary syntax."
        )

    if acc > 0.99:
        issues.append(f"[HIGH] Accuracy {acc:.4f} > 99% — unrealistically high for real-world threat detection")
        recommendations.append(
            "Expected realistic accuracy on production data: 85-95%"
        )

    if dominant:
        issues.append(f"[MEDIUM] Dominant features (high separation): {', '.join(dominant[:3])}")
        recommendations.append(
            "Adversarial robustness: attackers can evade detection by avoiding trigger keywords"
        )

    if not issues:
        print(f"  ✓ No critical issues found")
    else:
        for issue in issues:
            print(f"  ✗ {issue}")

    print(f"\n  RECOMMENDATIONS:")
    if not recommendations:
        print(f"  ✓ Model appears production-ready")
    else:
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

    # Overall verdict
    if len([i for i in issues if "CRITICAL" in i]) > 0:
        verdict = "NOT PRODUCTION READY — Critical leakage detected"
    elif len([i for i in issues if "HIGH" in i]) >= 2:
        verdict = "CAUTIOUS — High leakage risk, metrics inflated in lab, likely lower in production"
    elif issues:
        verdict = "ACCEPTABLE for prototype — monitor performance on real events"
    else:
        verdict = "PRODUCTION READY"

    print(f"\n  VERDICT: {verdict}")
    return {"verdict": verdict, "issues": issues, "recommendations": recommendations}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Validate ML model for IR-Agent")
    parser.add_argument("--full",   action="store_true", help="Include calibration check")
    parser.add_argument("--report", action="store_true", help="Save JSON report")
    parser.add_argument("--no-cv",  action="store_true", help="Skip cross-validation (faster)")
    args = parser.parse_args()

    print("=" * 60)
    print("  IR-Agent ML Model Validation")
    print("=" * 60)

    # Check data files
    for path in [TRAIN_EVENTS, TRAIN_LABELS, VAL_EVENTS, VAL_LABELS]:
        if not path.exists():
            print(f"ERROR: {path} not found")
            sys.exit(1)

    print("\nLoading datasets...")
    X_train, y_train, y_raw_train = load_dataset(TRAIN_EVENTS, TRAIN_LABELS)
    X_val,   y_val,   y_raw_val   = load_dataset(VAL_EVENTS,   VAL_LABELS)
    print(f"  Train: {X_train.shape}, Val: {X_val.shape}")

    # Load model
    section("0. Model Info")
    model, scaler = load_model(MODEL_PATH)

    report = {}

    # Run all checks
    report["dataset"]  = analyze_dataset(X_train, y_train, y_raw_train, X_val, y_val, y_raw_val)
    report["features"] = analyze_features(X_train, y_train, X_val, y_val)

    if model is not None:
        report["holdout"] = holdout_validation(model, scaler, X_val, y_val)

        if not args.no_cv:
            # Combine train+val for CV (use full dataset)
            X_all = np.vstack([X_train, X_val])
            y_all = np.concatenate([y_train, y_val])
            report["cross_validation"] = cross_validate(X_all, y_all)
        else:
            print("\n  [Cross-validation skipped with --no-cv]")
            report["cross_validation"] = {}

        report["leakage"]  = leakage_check(X_train, y_train, X_val, y_val)
        report["importance"] = feature_importance(model, scaler, X_val, y_val)

        if args.full:
            report["calibration"] = calibration_check(model, scaler, X_val, y_val)
    else:
        print("\n  Skipping model-dependent checks (model not loaded)")
        report["holdout"] = {}
        report["cross_validation"] = {}
        report["leakage"]  = leakage_check(X_train, y_train, X_val, y_val)

    # Verdict
    report["summary"] = print_verdict(
        report.get("holdout", {}),
        report.get("cross_validation", {}),
        report.get("leakage", {}),
        report.get("dataset", {}),
        report.get("features", {}),
    )

    # Save report
    if args.report:
        REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
        with open(REPORT_OUT, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  Report saved: {REPORT_OUT}")

    print(f"\n{'='*60}")
    print("  Validation complete.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
