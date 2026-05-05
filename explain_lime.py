"""
LIME Local Explanations — IR-Agent Event Classifier
=====================================================
Uses LIME (Local Interpretable Model-agnostic Explanations) to show WHY
the GradientBoosting model flagged a specific security event.

Unlike SHAP (which decomposes global averages), LIME fits a tiny linear model
*around one prediction*, so it directly answers:
  "For THIS event, which features moved the score toward malicious?"

Produces:
  models/lime_report.html     — interactive HTML with all examples
  models/lime_<N>.png         — bar chart for each example event

Usage:
    python explain_lime.py
    python explain_lime.py --events training/data/sample_events.json
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

MODELS_DIR = ROOT / "models"

try:
    from lime.lime_tabular import LimeTabularExplainer
except ImportError:
    raise ImportError("pip install lime")

# ── Feature definitions (must match CyberMLEngine._get_feature_names) ─────────
FEATURE_NAMES = [
    "event_id",
    "is_high_risk_event",
    "channel_hash",
    "is_suspicious_process",
    "cmdline_length",
    "suspicious_keyword_count",
    "has_base64_encoding",
    "has_download_command",
    "has_hidden_window",
    "parent_is_suspicious",
    "logon_type",
    "is_network_or_rdp_logon",
    "is_system_user",
    "is_admin_user",
    "destination_port",
    "is_c2_port",
]

CATEGORICAL_FEATURES = [1, 3, 6, 7, 8, 9, 11, 12, 13, 15]  # binary flags

# Feature labels for readability
FEATURE_LABELS = {
    "event_id":                "Windows Event ID",
    "is_high_risk_event":      "High-Risk Event ID?",
    "channel_hash":            "Log Channel",
    "is_suspicious_process":   "LOLBin Process?",
    "cmdline_length":          "Command Line Length",
    "suspicious_keyword_count":"Malicious Keywords (#)",
    "has_base64_encoding":     "Base64 Encoded Cmd?",
    "has_download_command":    "Download Command?",
    "has_hidden_window":       "Hidden Window Flag?",
    "parent_is_suspicious":    "Suspicious Parent Process?",
    "logon_type":              "Logon Type",
    "is_network_or_rdp_logon": "Network/RDP Logon?",
    "is_system_user":          "SYSTEM Account?",
    "is_admin_user":           "Admin Account?",
    "destination_port":        "Destination Port",
    "is_c2_port":              "Known C2 Port?",
}

# ── Synthetic example events (covers benign + various attack patterns) ─────────
EXAMPLE_EVENTS = [
    {
        "name": "Normal user login",
        "features": [4624, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0],
        "expected": "benign",
    },
    {
        "name": "PowerShell Base64 download cradle",
        "features": [4688, 1, 3, 1, 280, 4, 1, 1, 1, 0, 0, 0, 0, 0, 443, 1],
        "expected": "malicious",
    },
    {
        "name": "Lateral movement via PsExec (SMB logon)",
        "features": [4624, 1, 3, 1, 120, 2, 0, 0, 0, 1, 3, 1, 0, 1, 445, 0],
        "expected": "malicious",
    },
    {
        "name": "Scheduled task creation",
        "features": [4698, 1, 3, 0, 95, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        "expected": "suspicious",
    },
    {
        "name": "Ransomware: VSS deletion",
        "features": [4688, 1, 3, 0, 210, 5, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        "expected": "malicious",
    },
    {
        "name": "Standard service start",
        "features": [7036, 0, 5, 0, 30, 0, 0, 0, 0, 0, 5, 0, 1, 0, 0, 0],
        "expected": "benign",
    },
    {
        "name": "C2 beacon on port 4444",
        "features": [3, 1, 3, 1, 60, 1, 0, 0, 0, 0, 0, 1, 0, 0, 4444, 1],
        "expected": "malicious",
    },
    {
        "name": "Admin password change",
        "features": [4723, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        "expected": "suspicious",
    },
]


def _load_model():
    """Load the GradientBoosting model whose scaler matches our 16-feature vector."""
    # prefer model whose scaler matches our feature count (16); fallback to others
    candidates = [
        "gradient_boosting_model.pkl",        # 18-feature scaler — closest
        "gradient_boosting_honest.pkl",
        "gradient_boosting_production.pkl",
    ]
    for name in candidates:
        p = MODELS_DIR / name
        if p.exists():
            with open(p, "rb") as f:
                data = pickle.load(f)
            model  = data.get("model") or data.get("classifier")
            scaler = data.get("scaler")
            print(f"[lime] Loaded: {p.name}")
            return model, scaler
    raise FileNotFoundError(f"No model found in {MODELS_DIR}")


def _make_predict_fn(model, scaler):
    """Return a prediction function compatible with LIME.
    Pads feature vectors to match the scaler's expected width if needed.
    """
    n_our   = len(FEATURE_NAMES)   # 16
    n_scaler = scaler.n_features_in_ if scaler is not None else n_our

    def predict_proba(X: np.ndarray) -> np.ndarray:
        if scaler is not None:
            # pad with zeros if scaler expects more features
            if X.shape[1] < n_scaler:
                pad = np.zeros((X.shape[0], n_scaler - X.shape[1]))
                X = np.hstack([X, pad])
            elif X.shape[1] > n_scaler:
                X = X[:, :n_scaler]
            X = scaler.transform(X)
        return model.predict_proba(X)
    return predict_proba


def _build_training_matrix() -> np.ndarray:
    """Build a background matrix from example events + random perturbations."""
    rng = np.random.default_rng(42)
    base = np.array([e["features"] for e in EXAMPLE_EVENTS], dtype=float)
    # add random perturbations to give LIME a reasonable neighbourhood
    noise = rng.normal(0, 0.5, size=(200, len(FEATURE_NAMES)))
    noise[:, CATEGORICAL_FEATURES] = rng.integers(0, 2,
                                                   size=(200, len(CATEGORICAL_FEATURES)),
                                                   dtype=int).astype(float)
    repeated = np.tile(base, (25, 1))[:200]
    training = np.clip(repeated + noise, 0, None)
    return training


def explain_event(
    explainer: LimeTabularExplainer,
    predict_fn,
    event: dict,
    out_path: Path,
):
    """Generate a LIME explanation for one event and save a bar chart."""
    x = np.array(event["features"], dtype=float)
    label_idx = 1  # index for "malicious" in predict_proba

    exp = explainer.explain_instance(
        x,
        predict_fn,
        num_features=len(FEATURE_NAMES),
        labels=[label_idx],
        num_samples=1000,
    )

    proba = predict_fn(x.reshape(1, -1))[0]
    mal_prob = proba[1]

    # extract and sort by absolute weight
    feat_weights = exp.as_list(label=label_idx)
    feat_weights.sort(key=lambda t: abs(t[1]), reverse=True)
    labels, values = zip(*feat_weights) if feat_weights else ([], [])

    # human-readable label: strip LIME's condition text → just the feature name
    def _clean(label: str) -> str:
        for fn in FEATURE_NAMES:
            if fn in label:
                return FEATURE_LABELS.get(fn, fn)
        return label[:35]

    clean_labels = [_clean(l) for l in labels]
    colors = ["#e74c3c" if v > 0 else "#2ecc71" for v in values]

    fig, ax = plt.subplots(figsize=(9, max(4, len(labels) * 0.4 + 1.5)))
    bars = ax.barh(range(len(values)), values, color=colors, edgecolor="white", height=0.65)
    ax.set_yticks(range(len(values)))
    ax.set_yticklabels(clean_labels, fontsize=9)
    ax.axvline(0, color="black", linewidth=0.8)
    ax.set_xlabel("LIME Weight  (red = pushes toward MALICIOUS, green = toward BENIGN)")
    verdict_color = "#e74c3c" if mal_prob > 0.5 else "#2ecc71"
    verdict = "MALICIOUS" if mal_prob > 0.5 else "BENIGN"
    ax.set_title(
        f'LIME Explanation — "{event["name"]}"\n'
        f'Model verdict: {verdict}  (P_malicious = {mal_prob:.3f})',
        fontsize=10, color=verdict_color, fontweight="bold",
    )
    ax.invert_yaxis()
    fig.tight_layout()
    fig.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)
    print(f"  [saved] {out_path.name}  verdict={verdict}  p_mal={mal_prob:.3f}")
    return feat_weights, mal_prob


def build_html_report(results: list[dict]) -> str:
    """Build a self-contained HTML report showing all LIME explanations."""

    def _row_color(p):
        if p >= 0.75:
            return "#fde8e8"
        if p >= 0.5:
            return "#fff3e0"
        return "#e8fde8"

    rows = ""
    for r in results:
        color = _row_color(r["p_mal"])
        verdict = "MALICIOUS" if r["p_mal"] > 0.5 else "BENIGN"
        v_color = "#c0392b" if r["p_mal"] > 0.5 else "#27ae60"

        fw_html = ""
        for feat_label, weight in r["weights"][:8]:
            w_color = "#e74c3c" if weight > 0 else "#2ecc71"
            pct = min(abs(weight) * 500, 100)
            fw_html += (
                f'<div style="display:flex;align-items:center;margin:3px 0">'
                f'<span style="width:230px;font-size:12px;color:#333">{feat_label[:40]}</span>'
                f'<div style="width:{pct:.0f}px;height:14px;background:{w_color};'
                f'border-radius:3px;margin-left:4px"></div>'
                f'<span style="margin-left:6px;font-size:11px;color:{w_color}">'
                f'{weight:+.4f}</span>'
                f'</div>'
            )

        rows += f"""
        <tr style="background:{color}">
          <td style="padding:12px;font-weight:600;font-size:13px">{r['name']}</td>
          <td style="padding:12px;color:{v_color};font-weight:700;font-size:14px">{verdict}</td>
          <td style="padding:12px;font-size:13px">{r['p_mal']:.3f}</td>
          <td style="padding:12px">{fw_html}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LIME Explanations — IR-Agent</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #f4f6f9; margin: 0; padding: 24px; }}
  h1   {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
  .subtitle {{ color: #7f8c8d; margin-top:-10px; margin-bottom:24px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           box-shadow:0 2px 12px rgba(0,0,0,.08); border-radius:8px;
           overflow:hidden; }}
  th    {{ background:#2c3e50; color:#fff; padding:12px; text-align:left; font-size:13px; }}
  tr:hover td {{ background:rgba(52,152,219,.05)!important; }}
  .legend {{ margin-top:20px; font-size:13px; color:#555; }}
  .dot {{ display:inline-block; width:12px; height:12px; border-radius:50%;
          margin-right:5px; vertical-align:middle; }}
</style>
</head>
<body>
<h1>LIME Local Explanations — IR-Agent Event Classifier</h1>
<p class="subtitle">
  Each row shows <strong>why</strong> the GradientBoosting model made its decision
  for a specific security event. LIME fits a local linear surrogate model around
  the prediction point, so the weights show <em>this event's</em> contributing factors,
  not global averages.
</p>
<table>
  <thead>
    <tr>
      <th>Event Description</th>
      <th>Verdict</th>
      <th>P(malicious)</th>
      <th>Feature Contributions (LIME weights)</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<div class="legend">
  <span class="dot" style="background:#e74c3c"></span> Red bar = pushes toward MALICIOUS &nbsp;&nbsp;
  <span class="dot" style="background:#2ecc71"></span> Green bar = pushes toward BENIGN &nbsp;&nbsp;
  Bar length ∝ magnitude of contribution.
</div>
</body>
</html>
"""


def run(events: list[dict] | None = None):
    model, scaler = _load_model()
    predict_fn = _make_predict_fn(model, scaler)
    training   = _build_training_matrix()

    explainer = LimeTabularExplainer(
        training,
        feature_names=[FEATURE_LABELS[n] for n in FEATURE_NAMES],
        class_names=["benign", "malicious"],
        categorical_features=CATEGORICAL_FEATURES,
        discretize_continuous=True,
        random_state=42,
    )

    if events is None:
        events = EXAMPLE_EVENTS

    print(f"[lime] Explaining {len(events)} events …\n")
    results = []
    for k, event in enumerate(events):
        out_png = MODELS_DIR / f"lime_{k+1:02d}.png"
        weights, p_mal = explain_event(explainer, predict_fn, event, out_png)

        # clean labels for the HTML report
        clean_weights = []
        for feat_label, w in weights[:8]:
            for fn in FEATURE_NAMES:
                if fn in feat_label:
                    clean_weights.append((FEATURE_LABELS.get(fn, fn), w))
                    break
            else:
                clean_weights.append((feat_label[:40], w))

        results.append({
            "name":    event["name"],
            "p_mal":   p_mal,
            "weights": clean_weights,
        })

    html = build_html_report(results)
    out_html = MODELS_DIR / "lime_report.html"
    out_html.write_text(html, encoding="utf-8")
    print(f"\n[saved] {out_html}")
    print(f"[done]  {len(events)} LIME explanations generated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", default=None,
                        help="JSON file with list of event dicts (optional)")
    args = parser.parse_args()

    custom = None
    if args.events:
        with open(args.events, encoding="utf-8") as f:
            custom = json.load(f)

    run(custom)
