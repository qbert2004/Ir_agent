"""
Strict Statistical Audit — IR-Agent ML Pipeline
================================================
Addresses all identified risks from critical review:

1. Source x Class leakage check (CRITICAL: synthetic=100% benign, evtx=100% malicious)
2. Leave-One-Source-Out (LOSO) cross-validation — true generalization estimate
3. GroupKFold cross-validation by source
4. Calibration curve (reliability diagram) + Brier score
5. SHAP feature importance (global + local)
6. Feature-by-class separation audit (which features bleed class info)
7. Noise injection test — robustness to 5%/10%/20% feature noise
8. Adversarial evasion test — zero out attack indicator features
9. Concept drift simulation — train on one attack family, test on another
10. Synthetic-only baseline — what accuracy from source alone?

Usage:
  py scripts/strict_audit.py                    # full audit (~5 min)
  py scripts/strict_audit.py --quick            # skip SHAP + LOSO (~1 min)
  py scripts/strict_audit.py --skip-shap        # skip SHAP only
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import List, Tuple, Dict

import numpy as np

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

TRAIN_EVENTS = ROOT / "training" / "data" / "train_events.json"
TRAIN_LABELS = ROOT / "training" / "data" / "train_labels.json"
VAL_EVENTS   = ROOT / "training" / "data" / "val_events.json"
VAL_LABELS   = ROOT / "training" / "data" / "val_labels.json"
MODEL_PATH   = ROOT / "models" / "gradient_boosting_production.pkl"

REPORT_PATH  = ROOT / "reports" / "strict_audit_report.json"


# ============================================================
# Helpers
# ============================================================

def section(title: str) -> None:
    print(f"\n{'='*65}")
    print(f"  {title}")
    print(f"{'='*65}")


def warn(msg: str) -> None:
    print(f"  [!!] {msg}")


def ok(msg: str) -> None:
    print(f"  [OK] {msg}")


def info(msg: str) -> None:
    print(f"  ... {msg}")


def _to_int(label) -> int:
    if isinstance(label, int):
        return label
    if isinstance(label, dict):
        return int(label.get("label", label.get("is_malicious", 0)))
    return 0 if str(label).lower().startswith("benign") else 1


# ============================================================
# Feature extraction (v3 — matches production model)
# ============================================================

_TOP_EVENT_IDS = [
    1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 22,
    4624, 4625, 4648, 4672, 4688,
    4698, 4720, 7045, 4104,
]

_SUSP_KW = [
    'mimikatz', 'sekurlsa', 'lsadump', 'lsass', 'procdump', 'comsvcs',
    'ntds.dit', 'dumpcreds', 'invoke-', 'iex', 'downloadstring',
    'webclient', 'frombase64', 'reflection', 'powersploit', 'empire',
    'bypass', 'hidden', '-enc', 'base64', '-nop', 'amsi', 'etw',
    'cobalt', 'meterpreter', 'payload', 'beacon', 'shellcode',
    'nc.exe', 'netcat', 'psexec', 'winrs', 'wmic process',
    'schtasks /create', 'sc create', 'reg add',
    'certutil -urlcache', 'bitsadmin /transfer',
    'mshta', 'rundll32', 'regsvr32', 'installutil', 'msbuild',
]

_SUSP_PROC = [
    'powershell', 'pwsh', 'wscript', 'cscript', 'mshta',
    'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
    'installutil', 'msbuild', 'wmic', 'psexec',
    'mimikatz', 'procdump',
]

FEATURE_NAMES = (
    [f"eid_{eid}" for eid in _TOP_EVENT_IDS] + [
        "kw_count_norm", "susp_process_exact", "susp_process_partial",
        "base64_encoded", "lsass_credential", "powershell_bypass",
        "network_download", "persistence", "defense_evasion",
        "lateral_movement", "has_dest_ip", "suspicious_port",
        "suspicious_path", "suspicious_parent", "network_logon",
        "external_src_ip", "registry_op", "driver_load",
        "process_injection", "has_hashes", "high_entropy_cmdline",
    ]
)


def extract_v3(event: dict) -> List[float]:
    cmdline = str(event.get("command_line", "") or "").lower()
    process = str(event.get("process_name", "") or "").lower()
    script  = str(event.get("script_block_text", "") or "").lower()
    parent  = str(event.get("parent_image", event.get("parent_process", "")) or "").lower()
    hashes  = str(event.get("hashes", "") or "")
    dest_ip = str(event.get("destination_ip", "") or "")
    src_ip  = str(event.get("source_ip", "") or "")

    try:
        event_id = int(event.get("event_id", 0) or 0)
    except (ValueError, TypeError):
        event_id = 0
    try:
        port = int(event.get("destination_port", 0) or 0)
    except (ValueError, TypeError):
        port = 0

    all_text = f"{cmdline} {script} {process}"
    f: List[float] = []

    for eid in _TOP_EVENT_IDS:
        f.append(float(event_id == eid))

    kw_count = sum(1 for kw in _SUSP_KW if kw in all_text)
    f.append(min(kw_count / 5.0, 1.0))

    proc_name = process.split("/")[-1].split("\\")[-1]
    f.append(float(any(sp == proc_name for sp in _SUSP_PROC)))
    f.append(float(any(sp in proc_name for sp in _SUSP_PROC)))

    f.append(float("-enc" in cmdline or "base64" in cmdline or
                   "frombase64" in all_text or "encodedcommand" in cmdline))
    f.append(float("lsass" in all_text or "sekurlsa" in all_text or
                   "procdump" in all_text or "comsvcs" in all_text))
    f.append(float("powershell" in process and
                   any(x in cmdline for x in ["-enc", "-nop", "bypass", "hidden", "windowstyle"])))
    f.append(float(any(kw in all_text for kw in [
        "webclient", "downloadstring", "invoke-webrequest", "urlcache", "bitsadmin", "wget", "curl"
    ])))
    f.append(float(any(kw in all_text for kw in [
        "schtasks /create", "reg add", "sc create", "runonce", "onlogon",
        "hkcu\\software\\microsoft\\windows\\currentversion\\run"
    ])))
    f.append(float(any(kw in all_text for kw in [
        "bypass", "amsi", "etw", "-nop", "hidden", "mshta", "installutil", "regsvr32", "cmstp"
    ])))
    f.append(float(any(kw in all_text for kw in [
        "psexec", "winrs", "wmic process", "invoke-wmimethod", "dcom"
    ])))

    f.append(float(bool(dest_ip) and dest_ip not in ("0.0.0.0", "127.0.0.1", "")))
    f.append(float(port in {4444, 1337, 8080, 9090, 3333, 31337, 5555, 6666, 7777}))

    is_system = any(p in process for p in ["windows\\system32", "windows\\syswow64", "program files"])
    is_susp   = any(p in process for p in ["appdata", "temp", "downloads", "public", "programdata"])
    f.append(float(not is_system and is_susp))

    f.append(float(any(sp in parent for sp in [
        "outlook", "winword", "excel", "powerpnt", "iexplore", "firefox", "chrome"
    ])))
    f.append(float(str(event.get("logon_type", "")) in ("3", "10")))
    is_internal = src_ip.startswith(("10.", "192.168.", "172.", "127.", "::1", ""))
    f.append(float(bool(src_ip) and not is_internal))

    f.append(float(event_id in {12, 13, 14}))
    f.append(float(event_id in {6, 7}))
    f.append(float(event_id in {8, 10}))
    f.append(float(bool(hashes and len(hashes) > 10)))

    if len(cmdline) > 20:
        unique_ratio = len(set(cmdline)) / len(cmdline)
        f.append(float(unique_ratio > 0.6 and len(cmdline) > 50))
    else:
        f.append(0.0)

    return f


# ============================================================
# Load data
# ============================================================

def load_all() -> Tuple[List[dict], np.ndarray, np.ndarray]:
    """Returns events, labels (int), source_groups (int)."""
    te = json.load(open(TRAIN_EVENTS, encoding="utf-8"))
    tl = json.load(open(TRAIN_LABELS, encoding="utf-8"))
    ve = json.load(open(VAL_EVENTS,   encoding="utf-8"))
    vl = json.load(open(VAL_LABELS,   encoding="utf-8"))

    events  = te + ve
    labels  = np.array([_to_int(l) for l in tl + vl], dtype=np.int32)
    sources = [str(e.get("source_type", "unknown")) for e in events]

    # Map sources to integer groups (for GroupKFold)
    unique_sources = sorted(set(sources))
    src_map = {s: i for i, s in enumerate(unique_sources)}
    groups  = np.array([src_map[s] for s in sources], dtype=np.int32)

    return events, labels, groups, sources


# ============================================================
# Main audit
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick",      action="store_true", help="Skip SHAP + LOSO (fast mode)")
    parser.add_argument("--skip-shap",  action="store_true", help="Skip SHAP analysis")
    args = parser.parse_args()

    from sklearn.metrics import (
        accuracy_score, roc_auc_score, f1_score,
        brier_score_loss, confusion_matrix, classification_report
    )
    from sklearn.preprocessing import StandardScaler
    from sklearn.calibration import calibration_curve
    from sklearn.model_selection import GroupKFold, LeaveOneGroupOut
    from sklearn.inspection import permutation_importance

    print("=" * 65)
    print("  IR-Agent — Strict Statistical Audit")
    print("  Production Model: gradient_boosting_production.pkl")
    print("=" * 65)

    report: Dict = {}

    # -------------------------------------------------------- #
    # Load model
    # -------------------------------------------------------- #
    section("0. Loading production model")
    if not MODEL_PATH.exists():
        warn(f"Model not found: {MODEL_PATH}")
        sys.exit(1)

    with open(MODEL_PATH, "rb") as fh:
        payload = pickle.load(fh)

    model  = payload["model"]
    scaler = payload["scaler"]
    stored_metrics = payload.get("metrics", {})
    info(f"Model: {type(model).__name__}")
    info(f"Stored metrics: acc={stored_metrics.get('accuracy',0):.4f} "
         f"auc={stored_metrics.get('roc_auc',0):.4f}")

    # -------------------------------------------------------- #
    # 1. Source x Class leakage audit (CRITICAL CHECK)
    # -------------------------------------------------------- #
    section("1. SOURCE x CLASS LEAKAGE AUDIT [CRITICAL]")
    events, labels, groups, sources = load_all()
    info(f"Total: {len(events):,} events")

    src_class: Dict[str, Counter] = defaultdict(Counter)
    for s, l in zip(sources, labels):
        src_class[s][l] += 1

    leakage_detected = False
    leakage_details  = {}
    print(f"\n  {'Source':20s}  {'Benign':>8}  {'Malicious':>10}  {'Malicious%':>12}  {'Risk'}")
    print(f"  {'-'*70}")
    for src in sorted(src_class):
        dist  = src_class[src]
        total = sum(dist.values())
        b     = dist[0]
        m     = dist[1]
        mal_pct = m / total * 100 if total > 0 else 0
        risk  = ""
        if mal_pct == 100.0 or mal_pct == 0.0:
            risk = "[!!] PERFECT SEPARATION"
            leakage_detected = True
        elif mal_pct > 95 or mal_pct < 5:
            risk = "[!!] NEAR-PERFECT"
            leakage_detected = True
        else:
            risk = "[OK] Mixed"
        leakage_details[src] = {
            "benign": b, "malicious": m, "malicious_pct": round(mal_pct, 1)
        }
        print(f"  {src:20s}  {b:8d}  {m:10d}  {mal_pct:11.1f}%  {risk}")

    print()
    if leakage_detected:
        warn("SOURCE IS A PERFECT PREDICTOR OF CLASS")
        warn("Any model trained on source-differentiated data learns source identity, not attack behavior")
        warn("True production accuracy (on unseen Windows logs) is UNKNOWN")
        warn("The 98.58% accuracy reflects source recognition, NOT threat detection")
        print()
        print("  Implication: if model were deployed in an enterprise with real")
        print("  mixed logs (both benign AND malicious events from same source),")
        print("  the actual false positive / false negative rates would be different.")
        report["leakage_audit"] = {
            "leakage_detected": True,
            "severity": "CRITICAL",
            "details": leakage_details,
            "explanation": (
                "synthetic source=100% benign, evtx+unknown=100% malicious. "
                "Model implicitly learns source identity. True generalization unknown."
            )
        }
    else:
        ok("No perfect source-class separation detected")
        report["leakage_audit"] = {"leakage_detected": False, "details": leakage_details}

    # -------------------------------------------------------- #
    # 2. Naive source-only baseline
    # -------------------------------------------------------- #
    section("2. NAIVE BASELINE: classify by source alone")
    # If source == synthetic -> predict benign (0), else -> predict malicious (1)
    naive_pred = np.array([0 if s == "synthetic" else 1 for s in sources])
    naive_acc  = accuracy_score(labels, naive_pred)
    naive_f1   = f1_score(labels, naive_pred, zero_division=0)
    naive_cm   = confusion_matrix(labels, naive_pred)

    print(f"\n  Naive 'source == synthetic -> benign' classifier:")
    print(f"  Accuracy: {naive_acc:.4f}  F1: {naive_f1:.4f}")
    tn, fp, fn, tp = naive_cm.ravel() if naive_cm.shape == (2, 2) else (0, 0, 0, 0)
    print(f"  TN={tn}  FP={fp}  FN={fn}  TP={tp}")
    print()

    if naive_acc > 0.95:
        warn(f"Naive source baseline: {naive_acc:.1%} — almost as good as trained model!")
        warn("This confirms the model exploits source structure, not event semantics")
    else:
        ok(f"Naive baseline: {naive_acc:.1%} — model learns beyond source identity")

    report["naive_baseline"] = {
        "accuracy": round(float(naive_acc), 4),
        "f1": round(float(naive_f1), 4),
        "note": "classify by source_type alone (synthetic=benign, else=malicious)"
    }

    # -------------------------------------------------------- #
    # 3. Feature extraction
    # -------------------------------------------------------- #
    section("3. Feature extraction v3 (41 features)")
    info("Extracting features for all events...")
    t0 = time.time()
    X = np.array([extract_v3(e) for e in events], dtype=np.float32)
    info(f"Done in {time.time()-t0:.1f}s. Shape: {X.shape}")

    # -------------------------------------------------------- #
    # 4. Feature-class separation (which features leak class?)
    # -------------------------------------------------------- #
    section("4. FEATURE-CLASS SEPARATION AUDIT")
    print(f"\n  {'Feature':40s}  {'Benign_mean':>12}  {'Mal_mean':>10}  {'Sep':>8}  {'Risk'}")
    print(f"  {'-'*85}")

    HIGH_SEP_THRESHOLD = 0.4
    separation_issues = []

    for i, fname in enumerate(FEATURE_NAMES):
        b_mean = float(np.mean(X[labels == 0, i]))
        m_mean = float(np.mean(X[labels == 1, i]))
        sep    = abs(m_mean - b_mean)
        risk   = ""
        if sep > HIGH_SEP_THRESHOLD:
            # Check if this is a structural leak (event_id one-hot for evtx vs synthetic)
            if fname.startswith("eid_"):
                risk = "[!!] EID STRUCT LEAK"
                separation_issues.append(fname)
            else:
                risk = "[NOTE] High separation"
        print(f"  {fname:40s}  {b_mean:12.4f}  {m_mean:10.4f}  {sep:8.4f}  {risk}")

    if separation_issues:
        print()
        warn(f"Event-ID features with high separation: {separation_issues}")
        warn("These may reflect SOURCE distribution, not attack behavior")
        warn("e.g., eid_4624 high in benign because synthetic always uses 4624")
    else:
        ok("No extreme feature-class separation found in non-event-id features")

    report["feature_separation"] = {
        "high_separation_features": separation_issues,
        "threshold": HIGH_SEP_THRESHOLD
    }

    # -------------------------------------------------------- #
    # 5. GroupKFold cross-validation (groups = sources)
    # -------------------------------------------------------- #
    section("5. GROUPKFOLD CROSS-VALIDATION (by source)")
    info("3-fold GroupKFold. Each fold: different source in val.")

    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.calibration import CalibratedClassifierCV

    gkf = GroupKFold(n_splits=3)
    fold_results = []

    for fold, (train_idx, val_idx) in enumerate(gkf.split(X, labels, groups)):
        X_tr, y_tr = X[train_idx], labels[train_idx]
        X_vl, y_vl = X[val_idx],   labels[val_idx]

        val_sources_in_fold = set(np.array(sources)[val_idx])
        train_sources_in_fold = set(np.array(sources)[train_idx])

        # Scale
        sc = StandardScaler()
        X_tr_sc = sc.fit_transform(X_tr)
        X_vl_sc = sc.transform(X_vl)

        # Train fast model (fewer estimators for speed)
        base = GradientBoostingClassifier(n_estimators=100, max_depth=4,
                                           learning_rate=0.1, random_state=42)
        cal = CalibratedClassifierCV(base, cv=3, method="sigmoid")
        cal.fit(X_tr_sc, y_tr)

        y_pred = cal.predict(X_vl_sc)
        y_prob = cal.predict_proba(X_vl_sc)[:, 1]

        acc = accuracy_score(y_vl, y_pred)
        auc = roc_auc_score(y_vl, y_prob) if len(set(y_vl)) > 1 else float('nan')
        f1  = f1_score(y_vl, y_pred, zero_division=0)
        bri = brier_score_loss(y_vl, y_prob)

        fold_results.append({
            "fold": fold + 1,
            "val_sources": sorted(val_sources_in_fold),
            "train_sources": sorted(train_sources_in_fold),
            "n_train": len(y_tr),
            "n_val": len(y_vl),
            "accuracy": round(float(acc), 4),
            "roc_auc":  round(float(auc), 4) if not np.isnan(auc) else None,
            "f1": round(float(f1), 4),
            "brier": round(float(bri), 4),
        })

        print(f"\n  Fold {fold+1}:")
        print(f"    Train sources: {sorted(train_sources_in_fold)}")
        print(f"    Val sources:   {sorted(val_sources_in_fold)}")
        print(f"    n_train={len(y_tr):,}  n_val={len(y_vl):,}")
        print(f"    class in val: benign={Counter(y_vl)[0]:,}  malicious={Counter(y_vl)[1]:,}")
        print(f"    ACC={acc:.4f}  AUC={auc:.4f}  F1={f1:.4f}  Brier={bri:.4f}")

    print()
    mean_acc = np.mean([r["accuracy"] for r in fold_results])
    std_acc  = np.std([r["accuracy"] for r in fold_results])
    mean_auc = np.nanmean([r["roc_auc"] for r in fold_results if r["roc_auc"] is not None])
    print(f"  GroupKFold summary: ACC={mean_acc:.4f}+-{std_acc:.4f}  AUC={mean_auc:.4f}")
    if std_acc > 0.10:
        warn(f"High variance across folds ({std_acc:.4f}) — model does NOT generalize uniformly")
    else:
        ok(f"Low variance ({std_acc:.4f}) — consistent across source groups")

    report["groupkfold"] = {
        "folds": fold_results,
        "mean_accuracy": round(float(mean_acc), 4),
        "std_accuracy":  round(float(std_acc),  4),
        "mean_roc_auc":  round(float(mean_auc), 4),
    }

    # -------------------------------------------------------- #
    # 6. LOSO validation (Leave-One-Source-Out)
    # -------------------------------------------------------- #
    if not args.quick:
        section("6. LEAVE-ONE-SOURCE-OUT (LOSO) VALIDATION")
        logo = LeaveOneGroupOut()
        loso_results = []

        for train_idx, val_idx in logo.split(X, labels, groups):
            X_tr, y_tr = X[train_idx], labels[train_idx]
            X_vl, y_vl = X[val_idx],   labels[val_idx]
            val_src = sorted(set(np.array(sources)[val_idx]))

            if len(set(y_vl)) < 2:
                print(f"\n  Skipping val_source={val_src} (only one class)")
                continue

            sc = StandardScaler()
            X_tr_sc = sc.fit_transform(X_tr)
            X_vl_sc = sc.transform(X_vl)

            base = GradientBoostingClassifier(n_estimators=100, max_depth=4,
                                               learning_rate=0.1, random_state=42)
            cal = CalibratedClassifierCV(base, cv=3, method="sigmoid")
            cal.fit(X_tr_sc, y_tr)

            y_pred = cal.predict(X_vl_sc)
            y_prob = cal.predict_proba(X_vl_sc)[:, 1]

            acc = accuracy_score(y_vl, y_pred)
            auc = roc_auc_score(y_vl, y_prob)
            f1  = f1_score(y_vl, y_pred, zero_division=0)
            bri = brier_score_loss(y_vl, y_prob)

            loso_results.append({
                "val_source": val_src,
                "n_val": len(y_vl),
                "accuracy": round(float(acc), 4),
                "roc_auc":  round(float(auc), 4),
                "f1": round(float(f1), 4),
                "brier": round(float(bri), 4),
            })
            print(f"\n  Hold-out: {val_src}  (n={len(y_vl):,})")
            print(f"    ACC={acc:.4f}  AUC={auc:.4f}  F1={f1:.4f}  Brier={bri:.4f}")

        if loso_results:
            loso_acc = [r["accuracy"] for r in loso_results]
            loso_auc = [r["roc_auc"]  for r in loso_results]
            print(f"\n  LOSO summary: ACC={np.mean(loso_acc):.4f}+-{np.std(loso_acc):.4f}  "
                  f"AUC={np.mean(loso_auc):.4f}+-{np.std(loso_auc):.4f}")

        report["loso"] = {
            "results": loso_results,
            "mean_accuracy": round(float(np.mean([r["accuracy"] for r in loso_results])), 4) if loso_results else None,
        }
    else:
        section("6. LOSO VALIDATION — skipped (--quick mode)")
        report["loso"] = {"skipped": True}

    # -------------------------------------------------------- #
    # 7. Calibration analysis on full dataset
    # -------------------------------------------------------- #
    section("7. PROBABILITY CALIBRATION (Brier + Reliability Diagram)")

    sc_full = StandardScaler()
    X_all_sc = sc_full.fit_transform(X)
    # Use stored model on held-out val (unknown source = real APT)
    val_mask = np.array([s == "unknown" for s in sources])
    X_val_sc  = scaler.transform(X[val_mask])
    y_val_lbl = labels[val_mask]
    y_val_prob = model.predict_proba(X_val_sc)[:, 1]
    y_val_pred = model.predict(X_val_sc)

    brier = brier_score_loss(y_val_lbl, y_val_prob)
    print(f"\n  Val set (unknown/real APT): n={val_mask.sum():,}")
    print(f"  Brier score: {brier:.4f}  (0=perfect, 0.25=random, lower=better)")

    if brier < 0.05:
        ok(f"Brier={brier:.4f} — excellent calibration")
    elif brier < 0.15:
        ok(f"Brier={brier:.4f} — good calibration")
    else:
        warn(f"Brier={brier:.4f} — poor calibration (model overconfident or underconfident)")

    # Reliability diagram (ASCII)
    print(f"\n  Reliability diagram (fraction_of_positives vs mean_predicted_prob):")
    try:
        prob_true, prob_pred_vals = calibration_curve(y_val_lbl, y_val_prob, n_bins=10)
        print(f"  {'Bin_prob':>10}  {'True_rate':>10}  {'Gap':>8}  {'Calibrated?'}")
        print(f"  {'-'*50}")
        overconf_count = 0
        for pt, pp in zip(prob_pred_vals, prob_true):
            gap = abs(pt - pp)
            status = "[OK]" if gap < 0.10 else "[!!] over/under-confident"
            if gap >= 0.10:
                overconf_count += 1
            print(f"  {pt:10.3f}  {pp:10.3f}  {gap:8.3f}  {status}")

        if overconf_count == 0:
            ok("All calibration bins within 10% of perfect calibration")
        else:
            warn(f"{overconf_count} bins deviate >10% from perfect calibration")
    except Exception as e:
        warn(f"Calibration curve failed: {e}")
        prob_true, prob_pred_vals = [], []

    report["calibration"] = {
        "brier_score": round(float(brier), 4),
        "n_val": int(val_mask.sum()),
        "source": "unknown (real APT recordings)",
    }

    # -------------------------------------------------------- #
    # 8. Noise injection robustness test
    # -------------------------------------------------------- #
    section("8. NOISE INJECTION ROBUSTNESS TEST")
    print("\n  Adding Gaussian noise to feature vectors, measuring accuracy drop...")

    X_val_orig  = X[val_mask]
    y_val_true  = labels[val_mask]
    X_val_sc_orig = scaler.transform(X_val_orig)
    base_acc    = accuracy_score(y_val_true, model.predict(X_val_sc_orig))

    rng = np.random.RandomState(42)
    noise_results = []

    print(f"\n  {'Noise_std':>10}  {'Noise_%':>8}  {'Accuracy':>10}  {'Accuracy_drop':>14}  {'Verdict'}")
    print(f"  {'-'*65}")

    for noise_std in [0.01, 0.05, 0.10, 0.20, 0.50]:
        noisy = X_val_orig.copy().astype(np.float32)
        noisy += rng.normal(0, noise_std, noisy.shape).astype(np.float32)
        noisy = np.clip(noisy, 0, 1)  # features are in [0,1] range (binary/normalized)

        noisy_sc  = scaler.transform(noisy)
        noisy_acc = accuracy_score(y_val_true, model.predict(noisy_sc))
        drop      = base_acc - noisy_acc
        pct_noise = noise_std * 100

        verdict = "[OK]" if drop < 0.02 else ("[!!] FRAGILE" if drop > 0.10 else "[NOTE] Minor drop")
        print(f"  {noise_std:10.2f}  {pct_noise:7.0f}%  {noisy_acc:10.4f}  {drop:+14.4f}  {verdict}")

        noise_results.append({
            "noise_std": noise_std,
            "accuracy": round(float(noisy_acc), 4),
            "accuracy_drop": round(float(drop), 4)
        })

    report["noise_robustness"] = {
        "base_accuracy": round(float(base_acc), 4),
        "results": noise_results
    }

    # -------------------------------------------------------- #
    # 9. Adversarial evasion test (zero-out attack features)
    # -------------------------------------------------------- #
    section("9. ADVERSARIAL EVASION TEST")
    print("\n  Simulate attacker who removes all obvious attack indicators from event.")
    print("  Zero-out keyword, process, encoding, credential, lateral-movement features.")

    # Feature indices for attack indicators (v3 features 20-40 = non-event-id features)
    attack_feature_indices = list(range(20, 41))  # all non-EID features

    X_val_adv = X_val_orig.copy().astype(np.float32)
    X_val_adv[:, attack_feature_indices] = 0.0  # erase all behavioral indicators

    X_val_adv_sc = scaler.transform(X_val_adv)
    adv_pred   = model.predict(X_val_adv_sc)
    adv_prob   = model.predict_proba(X_val_adv_sc)[:, 1]
    adv_acc    = accuracy_score(y_val_true, adv_pred)
    adv_mal_detected = (adv_pred[y_val_true == 1] == 1).mean()

    print(f"\n  Adversarial accuracy (all behavioral features = 0): {adv_acc:.4f}")
    print(f"  Malicious events still detected:                     {adv_mal_detected:.1%}")
    print(f"  Accuracy drop:                                       {base_acc-adv_acc:+.4f}")
    print()

    if adv_mal_detected > 0.90:
        ok(f"Model detects {adv_mal_detected:.1%} of attacks even with zero behavioral features")
        print("    Likely relies on event_id (Sysmon 12/6/7) as primary discriminator")
        warn("    This means attacker can evade by using event_ids common in benign logs")
    elif adv_mal_detected > 0.50:
        print(f"  [NOTE] Partial evasion: {1-adv_mal_detected:.1%} attacks missed without behavioral features")
    else:
        warn(f"  CRITICAL: only {adv_mal_detected:.1%} detected — model relies entirely on behavioral keywords")
        print("    Attackers using fileless / LOLBin-only techniques will evade detection")

    report["adversarial_evasion"] = {
        "accuracy_on_adversarial": round(float(adv_acc), 4),
        "malicious_detection_rate": round(float(adv_mal_detected), 4),
        "zeroed_features": "all non-event-id features (indices 20-40)"
    }

    # -------------------------------------------------------- #
    # 10. Concept drift simulation
    # -------------------------------------------------------- #
    section("10. CONCEPT DRIFT SIMULATION")
    print("\n  Train on one attack 'family', evaluate on another.")
    print("  Simulated via event_id families:")
    print("  Family A (process/logon): EIDs {1, 4624, 4688} -> includes benign synthetic")
    print("  Family B (sysmon/network): EIDs {5,6,7,12,13,22} -> all from evtx/unknown")

    # Since evtx=all malicious and synthetic=all benign, we can't do a true family split
    # Instead: train on evtx-style attacks (sysmon EIDs) vs unknown-style (AD attacks)
    evtx_idx    = np.array([i for i, s in enumerate(sources) if s == "evtx"])
    unknown_idx = np.array([i for i, s in enumerate(sources) if s == "unknown"])
    synthetic_idx = np.array([i for i, s in enumerate(sources) if s == "synthetic"])

    if len(evtx_idx) > 0 and len(unknown_idx) > 0 and len(synthetic_idx) > 0:
        # Scenario A: TRAIN=evtx+synthetic, VAL=unknown (original scenario, but re-measured)
        train_A = np.concatenate([evtx_idx, synthetic_idx])
        val_A   = unknown_idx
        # Scenario B: TRAIN=unknown+synthetic, VAL=evtx
        train_B = np.concatenate([unknown_idx, synthetic_idx])
        val_B   = evtx_idx

        drift_results = []
        for label, t_idx, v_idx in [("A: evtx+syn->unknown", train_A, val_A),
                                     ("B: unknown+syn->evtx",  train_B, val_B)]:
            X_tr, y_tr = X[t_idx], labels[t_idx]
            X_vl, y_vl = X[v_idx], labels[v_idx]

            if len(set(y_vl)) < 2:
                print(f"  [{label}] skip — only one class in val")
                continue

            sc = StandardScaler()
            X_tr_sc = sc.fit_transform(X_tr)
            X_vl_sc = sc.transform(X_vl)

            base_m = GradientBoostingClassifier(n_estimators=100, max_depth=4,
                                                 learning_rate=0.1, random_state=42)
            cal_m  = CalibratedClassifierCV(base_m, cv=3, method="sigmoid")
            cal_m.fit(X_tr_sc, y_tr)

            y_pred = cal_m.predict(X_vl_sc)
            y_prob = cal_m.predict_proba(X_vl_sc)[:, 1]

            acc = accuracy_score(y_vl, y_pred)
            auc = roc_auc_score(y_vl, y_prob) if len(set(y_vl)) > 1 else float('nan')
            f1  = f1_score(y_vl, y_pred, zero_division=0)

            print(f"\n  Scenario {label}:")
            print(f"    n_train={len(y_tr):,}  n_val={len(y_vl):,}")
            print(f"    Val class: benign={Counter(y_vl)[0]:,}  malicious={Counter(y_vl)[1]:,}")
            print(f"    ACC={acc:.4f}  AUC={auc:.4f}  F1={f1:.4f}")

            drift_results.append({
                "scenario": label,
                "accuracy": round(float(acc), 4),
                "roc_auc":  round(float(auc), 4) if not np.isnan(auc) else None,
                "f1": round(float(f1), 4),
            })

        report["drift_simulation"] = {"scenarios": drift_results}
    else:
        warn("Cannot run drift simulation: missing one of evtx/unknown/synthetic sources")
        report["drift_simulation"] = {"skipped": True}

    # -------------------------------------------------------- #
    # 11. SHAP analysis
    # -------------------------------------------------------- #
    if not args.quick and not args.skip_shap:
        section("11. SHAP FEATURE IMPORTANCE")
        try:
            import shap

            info("Computing SHAP values on val set (n=200 background, n=500 explain)...")
            # For CalibratedClassifierCV we need the underlying estimator
            # Extract base estimator from calibrated model
            if hasattr(model, "calibrated_classifiers_"):
                base_est = model.calibrated_classifiers_[0].estimator
            elif hasattr(model, "estimator"):
                base_est = model.estimator
            else:
                base_est = model

            X_val_sc_shap = scaler.transform(X[val_mask][:500])
            X_bg_sc       = scaler.transform(X[:200])

            explainer   = shap.TreeExplainer(base_est, X_bg_sc)
            shap_values = explainer.shap_values(X_val_sc_shap)

            # For binary classification, shap_values is (n, features)
            if isinstance(shap_values, list):
                sv = shap_values[1]  # malicious class
            else:
                sv = shap_values

            mean_abs_shap = np.abs(sv).mean(axis=0)
            ranked        = np.argsort(mean_abs_shap)[::-1]

            print(f"\n  {'Rank':>4}  {'Feature':40s}  {'SHAP_importance':>16}")
            print(f"  {'-'*65}")
            shap_top = []
            for rank, idx in enumerate(ranked[:15], 1):
                name = FEATURE_NAMES[idx] if idx < len(FEATURE_NAMES) else f"f{idx}"
                imp  = float(mean_abs_shap[idx])
                bar  = "#" * max(0, int(imp * 60))
                print(f"  {rank:4d}  {name:40s}  {imp:16.4f}  {bar}")
                shap_top.append({"rank": rank, "feature": name, "shap_importance": round(imp, 4)})

            # Check if event_id features dominate SHAP
            eid_features_in_top5 = sum(1 for r in shap_top[:5] if r["feature"].startswith("eid_"))
            if eid_features_in_top5 >= 3:
                warn(f"{eid_features_in_top5}/5 top SHAP features are event_id one-hots")
                warn("Model relies primarily on event_id = source type discriminant")
            else:
                ok(f"Top SHAP features include behavioral signals (not just event_ids)")

            report["shap"] = {"top_features": shap_top}
        except ImportError:
            warn("SHAP not installed: pip install shap")
            report["shap"] = {"error": "shap not installed"}
        except Exception as e:
            warn(f"SHAP failed: {e}")
            report["shap"] = {"error": str(e)}
    else:
        section("11. SHAP ANALYSIS — skipped")
        report["shap"] = {"skipped": True}

    # -------------------------------------------------------- #
    # 12. Final verdict
    # -------------------------------------------------------- #
    section("AUDIT VERDICT")

    issues = []
    if report["leakage_audit"]["leakage_detected"]:
        issues.append("CRITICAL: Source is perfect predictor (synthetic=benign, evtx=malicious)")
    if float(report["naive_baseline"]["accuracy"]) > 0.95:
        issues.append(f"CRITICAL: Naive source-only baseline = {report['naive_baseline']['accuracy']:.1%}")

    gkf_std = report["groupkfold"]["std_accuracy"]
    if gkf_std > 0.10:
        issues.append(f"HIGH: GroupKFold std={gkf_std:.4f} — inconsistent generalization")

    adv_rate = report["adversarial_evasion"]["malicious_detection_rate"]
    if adv_rate > 0.90:
        issues.append(f"MEDIUM: Adversarial evasion easy — model relies on event_id not behavior ({adv_rate:.1%} detected with 0 behavioral features)")

    brier_val = report["calibration"]["brier_score"]
    if brier_val > 0.15:
        issues.append(f"MEDIUM: Poor calibration (Brier={brier_val:.4f})")

    print()
    if issues:
        print(f"  Issues found: {len(issues)}")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
    else:
        ok("No critical issues found")

    print()
    print("  HONEST ASSESSMENT:")
    print("  ------------------")
    print("  The 98.58% accuracy is REAL but reflects cross-source generalization,")
    print("  not cross-semantic generalization. The model correctly identifies events")
    print("  from 'unknown' (APT) source vs 'synthetic' (benign) source.")
    print()
    print("  What this means for production:")
    print("  - WILL work well when processing logs from known attack campaigns (PurpleSharp, PetiPotam)")
    print("  - MAY struggle with novel attacks using benign event_ids (e.g., LOLBAS via 4688)")
    print("  - FALSE POSITIVE RATE is unknown for real benign enterprise logs with Sysmon EIDs")
    print()
    print("  Recommended fix: collect real benign Sysmon logs (EIDs 1,3,7,12,13 from benign endpoints)")
    print("  and retrain with source_type='real_benign'. This will force model to learn")
    print("  behavioral features (keywords, process chains) not just event_id distribution.")

    report["verdict"] = {
        "issues": issues,
        "n_issues": len(issues),
        "honest_accuracy_estimate": "98.58% on known APT source; unknown for truly novel enterprise logs",
        "production_recommendation": (
            "CONDITIONALLY USABLE: strong for known attack campaign detection. "
            "Supplement with ThreatAssessment Engine (IoC+MITRE) for unknown attacks. "
            "Collect real benign Sysmon logs to eliminate source-class coupling."
        )
    }

    # Save report
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
    print(f"\n  Full report saved: {REPORT_PATH}")

    print()
    print("=" * 65)
    print("  Audit complete.")
    print("=" * 65)


if __name__ == "__main__":
    main()
