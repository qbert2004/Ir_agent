"""
Baseline comparison: Rule-based vs ML vs ML+ThreatAssessment

Compares 3 approaches on the same validation set:
  1. Rule-based   - keyword/event_id matching (like simple SIEM rules)
  2. ML-only      - GradientBoosting classifier (threshold=0.60)
  3. ML+MITRE     - ML score + MITRE ATT&CK pattern matching (fusion)

Output: comparison table in Markdown format (for EVALUATION.md).

Usage:
  python scripts/compare_baselines.py
  python scripts/compare_baselines.py --output reports/baseline_comparison.json
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
from collections import Counter
from pathlib import Path
from typing import List, Tuple

import numpy as np

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

VAL_EVENTS = ROOT / "training" / "data" / "val_events.json"
VAL_LABELS = ROOT / "training" / "data" / "val_labels.json"
MODEL_PATH = ROOT / "models" / "gradient_boosting_production.pkl"


# --------------------------------------------------------------------------- #
# Baseline 1: Rule-based (keyword/event_id matching)
# --------------------------------------------------------------------------- #

CRITICAL_KEYWORDS = [
    'mimikatz', 'sekurlsa', 'lsadump', 'procdump', 'comsvcs',
    'vssadmin delete', 'bcdedit', 'wmic shadowcopy',
]
HIGH_KEYWORDS = [
    '-enc', 'frombase64', 'downloadstring', 'iex(', 'iex ',
    'certutil -urlcache', 'bitsadmin /transfer', 'psexec',
    'cobalt', 'meterpreter', 'shellcode', 'invoke-expression',
]
SUSPICIOUS_EVENT_IDS = {8, 10, 4104, 7045, 4698}  # injection, PS, service


def rule_based_predict(event: dict) -> Tuple[int, float]:
    """
    Returns (prediction, confidence).
    Rule-based: keywords in command_line/process_name, suspicious event_ids.
    """
    cmdline = str(event.get('command_line', '') or '').lower()
    process = str(event.get('process_name', '') or '').lower()
    eid = int(event.get('event_id', 0) or 0)
    text = f"{cmdline} {process}"

    for kw in CRITICAL_KEYWORDS:
        if kw in text:
            return 1, 0.95

    for kw in HIGH_KEYWORDS:
        if kw in text:
            return 1, 0.80

    if eid in SUSPICIOUS_EVENT_IDS:
        return 1, 0.65

    return 0, 0.90


# --------------------------------------------------------------------------- #
# Baseline 2: ML-only
# --------------------------------------------------------------------------- #

def ml_predict(events: list, model, scaler, threshold: float):
    """Returns (predictions, probabilities) arrays."""
    from scripts.retrain_source_split import extract_features_v3
    X = np.array([extract_features_v3(e) for e in events], dtype=np.float32)
    X_s = scaler.transform(X)
    probs = model.predict_proba(X_s)[:, 1]
    preds = (probs >= threshold).astype(int)
    return preds, probs


# --------------------------------------------------------------------------- #
# Baseline 3: ML + MITRE pattern (simple fusion)
# --------------------------------------------------------------------------- #

MITRE_PATTERNS = [
    # T1003: Credential Dumping
    ('lsass', 0.3), ('procdump', 0.3), ('mimikatz', 0.4), ('comsvcs', 0.3),
    # T1059: Command & Scripting
    ('-enc', 0.2), ('frombase64', 0.25), ('iex(', 0.25),
    # T1105: Ingress Tool Transfer
    ('certutil -urlcache', 0.2), ('bitsadmin', 0.2),
    # T1021: Remote Services
    ('psexec', 0.25), ('winrs', 0.15), ('wmic process', 0.2),
    # T1543: Create/Modify Service
    ('sc create', 0.2), ('sc config', 0.15),
]


def ml_mitre_predict(events: list, model, scaler, threshold: float):
    """ML score boosted by MITRE pattern matching."""
    from scripts.retrain_source_split import extract_features_v3
    X = np.array([extract_features_v3(e) for e in events], dtype=np.float32)
    X_s = scaler.transform(X)
    ml_probs = model.predict_proba(X_s)[:, 1]

    fused_probs = []
    for event, ml_prob in zip(events, ml_probs):
        text = (str(event.get('command_line', '') or '') + ' ' +
                str(event.get('process_name', '') or '')).lower()

        mitre_boost = 0.0
        for pattern, weight in MITRE_PATTERNS:
            if pattern in text:
                mitre_boost = max(mitre_boost, weight)

        # Fusion: weighted sum, capped at 1.0
        fused = min(1.0, ml_prob * 0.70 + mitre_boost * 0.30)
        fused_probs.append(fused)

    fused_probs = np.array(fused_probs)
    preds = (fused_probs >= threshold).astype(int)
    return preds, fused_probs


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> dict:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix
    )
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn + 1e-9)
    fnr = fn / (fn + tp + 1e-9)

    try:
        auc = float(roc_auc_score(y_true, y_prob))
    except Exception:
        auc = 0.0

    return {
        "accuracy":  round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc":   round(auc, 4),
        "fpr":       round(float(fpr), 4),
        "fnr":       round(float(fnr), 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def section(title: str):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="reports/baseline_comparison.json")
    args = parser.parse_args()

    section("Loading validation data")
    with open(VAL_EVENTS, encoding="utf-8") as f:
        val_events = json.load(f)
    with open(VAL_LABELS, encoding="utf-8") as f:
        val_labels = json.load(f)

    y_true = np.array(val_labels, dtype=np.int32)
    print(f"  Val set: {len(val_events):,} events")
    print(f"  Class distribution: {Counter(val_labels.count(0) if isinstance(val_labels[0], int) else (1 if v else 0) for v in val_labels)}")
    print(f"  Benign: {int(np.sum(y_true == 0)):,}  |  Malicious: {int(np.sum(y_true == 1)):,}")

    # Load ML model
    section("Loading ML model")
    if not MODEL_PATH.exists():
        print(f"  ERROR: {MODEL_PATH} not found!")
        print("  Run: python scripts/retrain_source_split.py")
        sys.exit(1)

    with open(MODEL_PATH, "rb") as f:
        payload = pickle.load(f)

    model = payload["model"]
    scaler = payload["scaler"]
    threshold = payload.get("threshold", 0.60)
    print(f"  Loaded: {MODEL_PATH.name}")
    print(f"  Threshold: {threshold}")

    results = {}

    # ------------------------------------------------------------------ #
    # 1. Rule-based baseline
    # ------------------------------------------------------------------ #
    section("1. Rule-based baseline")
    print("  Running keyword/event_id matching...")
    rb_preds = []
    rb_probs = []
    for event in val_events:
        pred, conf = rule_based_predict(event)
        rb_preds.append(pred)
        rb_probs.append(conf if pred == 1 else 1 - conf)

    rb_preds = np.array(rb_preds)
    rb_probs = np.array(rb_probs)
    m_rb = compute_metrics(y_true, rb_preds, rb_probs)
    results["rule_based"] = m_rb
    print(f"  Accuracy:  {m_rb['accuracy']:.4f}")
    print(f"  Precision: {m_rb['precision']:.4f}")
    print(f"  Recall:    {m_rb['recall']:.4f}")
    print(f"  F1:        {m_rb['f1']:.4f}")
    print(f"  FPR:       {m_rb['fpr']*100:.2f}%")

    # ------------------------------------------------------------------ #
    # 2. ML-only
    # ------------------------------------------------------------------ #
    section("2. ML-only (GradientBoosting)")
    print(f"  Running ML classifier (threshold={threshold})...")
    ml_preds, ml_probs = ml_predict(val_events, model, scaler, threshold)
    m_ml = compute_metrics(y_true, ml_preds, ml_probs)
    results["ml_only"] = m_ml
    print(f"  Accuracy:  {m_ml['accuracy']:.4f}")
    print(f"  Precision: {m_ml['precision']:.4f}")
    print(f"  Recall:    {m_ml['recall']:.4f}")
    print(f"  F1:        {m_ml['f1']:.4f}")
    print(f"  ROC-AUC:   {m_ml['roc_auc']:.4f}")
    print(f"  FPR:       {m_ml['fpr']*100:.2f}%")

    # ------------------------------------------------------------------ #
    # 3. ML + MITRE fusion
    # ------------------------------------------------------------------ #
    section("3. ML + MITRE ATT&CK pattern fusion")
    print(f"  Running ML + MITRE fusion (threshold={threshold})...")
    fusion_preds, fusion_probs = ml_mitre_predict(val_events, model, scaler, threshold)
    m_fusion = compute_metrics(y_true, fusion_preds, fusion_probs)
    results["ml_mitre_fusion"] = m_fusion
    print(f"  Accuracy:  {m_fusion['accuracy']:.4f}")
    print(f"  Precision: {m_fusion['precision']:.4f}")
    print(f"  Recall:    {m_fusion['recall']:.4f}")
    print(f"  F1:        {m_fusion['f1']:.4f}")
    print(f"  ROC-AUC:   {m_fusion['roc_auc']:.4f}")
    print(f"  FPR:       {m_fusion['fpr']*100:.2f}%")

    # ------------------------------------------------------------------ #
    # Summary table
    # ------------------------------------------------------------------ #
    section("COMPARISON TABLE")

    print(f"""
  {'Approach':<30} {'Accuracy':>9} {'Precision':>10} {'Recall':>7} {'F1':>7} {'ROC-AUC':>8} {'FPR':>7}
  {'-'*82}
  {'Rule-based (keywords)':<30} {m_rb['accuracy']:>9.4f} {m_rb['precision']:>10.4f} {m_rb['recall']:>7.4f} {m_rb['f1']:>7.4f} {'N/A':>8} {m_rb['fpr']*100:>6.1f}%
  {'ML-only (GradientBoosting)':<30} {m_ml['accuracy']:>9.4f} {m_ml['precision']:>10.4f} {m_ml['recall']:>7.4f} {m_ml['f1']:>7.4f} {m_ml['roc_auc']:>8.4f} {m_ml['fpr']*100:>6.1f}%
  {'ML + MITRE fusion (ours)':<30} {m_fusion['accuracy']:>9.4f} {m_fusion['precision']:>10.4f} {m_fusion['recall']:>7.4f} {m_fusion['f1']:>7.4f} {m_fusion['roc_auc']:>8.4f} {m_fusion['fpr']*100:>6.1f}%
""")

    # Improvement over baselines
    f1_gain_over_rules = (m_fusion['f1'] - m_rb['f1']) / max(m_rb['f1'], 0.001) * 100
    f1_gain_over_ml = (m_fusion['f1'] - m_ml['f1']) / max(m_ml['f1'], 0.001) * 100
    print(f"  F1 improvement over rule-based: {f1_gain_over_rules:+.1f}%")
    print(f"  F1 improvement over ML-only:    {f1_gain_over_ml:+.1f}%")

    # ------------------------------------------------------------------ #
    # Markdown for EVALUATION.md
    # ------------------------------------------------------------------ #
    md_table = f"""## 9. Baseline Comparison

Evaluation on the same validation set ({len(val_events):,} events: {int(np.sum(y_true==0)):,} benign, {int(np.sum(y_true==1)):,} malicious).

| Approach | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|---|
| Rule-based (keywords/event_id) | {m_rb['accuracy']:.4f} | {m_rb['precision']:.4f} | {m_rb['recall']:.4f} | {m_rb['f1']:.4f} | N/A | {m_rb['fpr']*100:.1f}% |
| ML-only (GradientBoosting) | {m_ml['accuracy']:.4f} | {m_ml['precision']:.4f} | {m_ml['recall']:.4f} | {m_ml['f1']:.4f} | {m_ml['roc_auc']:.4f} | {m_ml['fpr']*100:.1f}% |
| **ML + MITRE fusion (this work)** | **{m_fusion['accuracy']:.4f}** | **{m_fusion['precision']:.4f}** | **{m_fusion['recall']:.4f}** | **{m_fusion['f1']:.4f}** | **{m_fusion['roc_auc']:.4f}** | **{m_fusion['fpr']*100:.1f}%** |

Dataset: real_benign (Sysmon operational logs) vs evtx+unknown (EVTX-ATTACK-SAMPLES + PurpleSharp/PetiPotam).
No synthetic data. Threshold optimized via Youden J = {threshold}.
"""
    print("\n  Markdown table for EVALUATION.md:")
    print("  " + "-"*58)
    for line in md_table.strip().split('\n'):
        print("  " + line)

    # ------------------------------------------------------------------ #
    # Save results
    # ------------------------------------------------------------------ #
    output_path = ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "val_size": len(val_events),
        "val_benign": int(np.sum(y_true == 0)),
        "val_malicious": int(np.sum(y_true == 1)),
        "threshold": float(threshold),
        "results": results,
        "markdown_table": md_table,
        "f1_gain_over_rules_pct": round(f1_gain_over_rules, 2),
        "f1_gain_over_ml_pct": round(f1_gain_over_ml, 2),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\n  Saved to: {output_path}")
    section("DONE")


if __name__ == "__main__":
    main()
