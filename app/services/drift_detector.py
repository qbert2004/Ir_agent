"""
Concept Drift Detector for IR-Agent ML Pipeline
================================================
Detects when incoming event distribution shifts from training distribution.

Approach:
  - Maintains a rolling window of recent feature vectors
  - Uses Population Stability Index (PSI) per feature
  - Page-Hinkley test for sequential drift detection
  - Score distribution drift (probability output shift)
  - Alerts when drift detected

PSI interpretation:
  PSI < 0.10  -> no significant drift
  PSI 0.10-0.25 -> moderate drift, monitor
  PSI > 0.25  -> significant drift, retrain recommended

Usage:
  # In EventProcessor or inference pipeline:
  from app.services.drift_detector import get_drift_detector
  detector = get_drift_detector()
  detector.update(feature_vector, ml_score)
  drift_status = detector.check()

  # Or as standalone analysis script:
  py -m app.services.drift_detector --analyze
"""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("ir-agent.drift")

ROOT = Path(__file__).parent.parent.parent
DRIFT_BASELINE_PATH = ROOT / "models" / "drift_baseline.json"
DRIFT_REPORT_PATH   = ROOT / "reports"  / "drift_report.json"

# PSI thresholds
PSI_WARNING  = 0.10
PSI_CRITICAL = 0.25

# Page-Hinkley sensitivity
PH_DELTA     = 0.005   # minimum acceptable mean change
PH_LAMBDA    = 50.0    # threshold for alarm


class PageHinkleyTest:
    """
    Sequential drift detection using Page-Hinkley test.
    Detects upward shifts in a stream of values.
    """

    def __init__(self, delta: float = PH_DELTA, lam: float = PH_LAMBDA):
        self.delta = delta
        self.lam   = lam
        self._reset()

    def _reset(self) -> None:
        self.n      = 0
        self.sum_   = 0.0
        self.min_   = float("inf")
        self.x_mean = 0.0

    def update(self, value: float) -> bool:
        """
        Update with new observation. Returns True if drift detected.
        """
        self.n     += 1
        self.x_mean = self.x_mean + (value - self.x_mean) / self.n
        self.sum_  += value - self.x_mean - self.delta
        self.min_   = min(self.min_, self.sum_)

        ph_statistic = self.sum_ - self.min_
        return ph_statistic > self.lam

    def reset(self) -> None:
        self._reset()


def _compute_psi(expected: np.ndarray, actual: np.ndarray, bins: int = 10) -> float:
    """
    Compute Population Stability Index between two distributions.
    Expected = training baseline, Actual = recent window.
    """
    eps = 1e-10

    # Use quantile-based bins from expected distribution
    quantiles = np.linspace(0, 100, bins + 1)
    bin_edges = np.percentile(expected, quantiles)
    # Ensure unique edges
    bin_edges = np.unique(bin_edges)

    if len(bin_edges) < 2:
        return 0.0  # all values same, no drift possible

    exp_counts, _ = np.histogram(expected, bins=bin_edges)
    act_counts, _ = np.histogram(actual,   bins=bin_edges)

    exp_pct = exp_counts / (len(expected) + eps)
    act_pct = act_counts / (len(actual)   + eps)

    # Clip to avoid log(0)
    exp_pct = np.clip(exp_pct, eps, None)
    act_pct = np.clip(act_pct, eps, None)

    psi = np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct))
    return float(psi)


class DriftDetector:
    """
    Multi-signal drift detector for ML pipeline monitoring.

    Tracks:
    1. Feature distribution drift (PSI per feature)
    2. Score distribution drift (PSI on ML probability outputs)
    3. Sequential drift (Page-Hinkley on score stream)
    4. Event rate anomaly (sudden spike/drop in event volume)
    """

    FEATURE_NAMES = [
        f"eid_{eid}" for eid in [
            1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 22,
            4624, 4625, 4648, 4672, 4688, 4698, 4720, 7045, 4104,
        ]
    ] + [
        "kw_count_norm", "susp_process_exact", "susp_process_partial",
        "base64_encoded", "lsass_credential", "powershell_bypass",
        "network_download", "persistence", "defense_evasion",
        "lateral_movement", "has_dest_ip", "suspicious_port",
        "suspicious_path", "suspicious_parent", "network_logon",
        "external_src_ip", "registry_op", "driver_load",
        "process_injection", "has_hashes", "high_entropy_cmdline",
    ]

    def __init__(
        self,
        window_size: int = 500,
        check_every: int = 100,
    ):
        self.window_size = window_size
        self.check_every = check_every

        self._feature_window: deque = deque(maxlen=window_size)
        self._score_window:   deque = deque(maxlen=window_size)
        self._n_updates = 0

        # Baseline (loaded from training distribution)
        self._baseline_features: Optional[np.ndarray] = None
        self._baseline_scores:   Optional[np.ndarray] = None

        # Page-Hinkley for score stream
        self._ph_test = PageHinkleyTest()

        # Drift state
        self.drift_detected  = False
        self.last_drift_time: Optional[float] = None
        self.last_check_time: Optional[float] = None
        self.last_psi_report: Dict = {}

        self._load_baseline()

    # ------------------------------------------------------------------ #
    # Baseline management
    # ------------------------------------------------------------------ #

    def _load_baseline(self) -> None:
        """Load training distribution baseline."""
        if DRIFT_BASELINE_PATH.exists():
            try:
                data = json.load(open(DRIFT_BASELINE_PATH, encoding="utf-8"))
                self._baseline_features = np.array(data["feature_means"], dtype=np.float32)
                self._baseline_scores   = np.array(data["score_distribution"], dtype=np.float32)
                logger.info(f"Drift baseline loaded from {DRIFT_BASELINE_PATH}")
            except Exception as e:
                logger.warning(f"Failed to load drift baseline: {e}")

    def save_baseline(
        self,
        feature_matrix: np.ndarray,
        score_distribution: np.ndarray,
    ) -> None:
        """
        Save training distribution as baseline for drift detection.
        Call after training with training feature matrix and predicted scores.
        """
        baseline = {
            "n_samples": int(len(feature_matrix)),
            "feature_means": feature_matrix.mean(axis=0).tolist(),
            "feature_stds":  feature_matrix.std(axis=0).tolist(),
            "score_distribution": score_distribution.tolist(),
            "feature_names": self.FEATURE_NAMES,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

        # Store per-feature raw samples for PSI (sample up to 2000)
        sample_idx = np.random.choice(
            len(feature_matrix),
            min(2000, len(feature_matrix)),
            replace=False,
        )
        baseline["feature_samples"] = feature_matrix[sample_idx].tolist()
        baseline["score_samples"]   = score_distribution[
            np.random.choice(len(score_distribution),
                             min(2000, len(score_distribution)), replace=False)
        ].tolist()

        DRIFT_BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(DRIFT_BASELINE_PATH, "w", encoding="utf-8") as fh:
            json.dump(baseline, fh, indent=2)

        self._baseline_features = feature_matrix.mean(axis=0)
        self._baseline_scores   = score_distribution
        logger.info(f"Drift baseline saved to {DRIFT_BASELINE_PATH}")

    # ------------------------------------------------------------------ #
    # Online updates
    # ------------------------------------------------------------------ #

    def update(self, feature_vector: List[float], ml_score: float) -> None:
        """
        Update detector with a new observation.
        Call this for every event processed by the ML pipeline.
        """
        self._feature_window.append(feature_vector)
        self._score_window.append(ml_score)
        self._n_updates += 1

        # Page-Hinkley update
        ph_drift = self._ph_test.update(ml_score)
        if ph_drift and not self.drift_detected:
            logger.warning(
                "Drift detector: Page-Hinkley alarm triggered! "
                f"Score stream shifted (n={self._n_updates})"
            )
            self.drift_detected = True
            self.last_drift_time = time.time()

        # Periodic full PSI check
        if self._n_updates % self.check_every == 0:
            _ = self.check()

    def check(self) -> Dict:
        """
        Run full drift check. Returns drift status dict.
        Can be called on-demand or periodically.
        """
        self.last_check_time = time.time()
        result: Dict = {
            "n_processed": self._n_updates,
            "window_size": len(self._feature_window),
            "ph_drift":    self.drift_detected,
            "psi_features": {},
            "psi_scores":   None,
            "drift_level":  "none",
            "alarms":       [],
        }

        if len(self._feature_window) < 50:
            result["note"] = "Insufficient data (< 50 events)"
            return result

        current_features = np.array(list(self._feature_window), dtype=np.float32)
        current_scores   = np.array(list(self._score_window),   dtype=np.float32)

        # ---- Feature PSI ----
        if self._baseline_features is not None:
            # We need per-feature samples from baseline
            baseline_data = json.load(open(DRIFT_BASELINE_PATH)) if DRIFT_BASELINE_PATH.exists() else {}
            baseline_feat_samples = np.array(
                baseline_data.get("feature_samples", []), dtype=np.float32
            )

            if len(baseline_feat_samples) > 0:
                max_psi = 0.0
                critical_features = []

                for i, fname in enumerate(self.FEATURE_NAMES):
                    if i >= current_features.shape[1]:
                        break
                    expected = baseline_feat_samples[:, i]
                    actual   = current_features[:, i]
                    psi = _compute_psi(expected, actual)
                    result["psi_features"][fname] = round(psi, 4)

                    if psi > PSI_CRITICAL:
                        critical_features.append(f"{fname}(PSI={psi:.3f})")
                        max_psi = max(max_psi, psi)
                    elif psi > PSI_WARNING:
                        max_psi = max(max_psi, psi)

                if max_psi > PSI_CRITICAL:
                    result["drift_level"] = "CRITICAL"
                    result["alarms"].append(
                        f"CRITICAL feature drift: {', '.join(critical_features[:5])}"
                    )
                    self.drift_detected = True
                elif max_psi > PSI_WARNING:
                    result["drift_level"] = "WARNING"
                    result["alarms"].append(
                        f"Moderate feature drift detected (max PSI={max_psi:.3f})"
                    )

        # ---- Score PSI ----
        if self._baseline_scores is not None and len(self._baseline_scores) > 0:
            baseline_data = json.load(open(DRIFT_BASELINE_PATH)) if DRIFT_BASELINE_PATH.exists() else {}
            baseline_score_samples = np.array(
                baseline_data.get("score_samples", []), dtype=np.float32
            )
            if len(baseline_score_samples) > 0:
                score_psi = _compute_psi(baseline_score_samples, current_scores)
                result["psi_scores"] = round(score_psi, 4)

                if score_psi > PSI_CRITICAL:
                    result["drift_level"] = "CRITICAL"
                    result["alarms"].append(
                        f"CRITICAL score distribution shift (PSI={score_psi:.3f})"
                    )
                    self.drift_detected = True
                elif score_psi > PSI_WARNING:
                    if result["drift_level"] == "none":
                        result["drift_level"] = "WARNING"
                    result["alarms"].append(
                        f"Score distribution drifting (PSI={score_psi:.3f})"
                    )

        # ---- Page-Hinkley ----
        if self.drift_detected and self.last_drift_time:
            result["alarms"].append(
                f"Page-Hinkley alarm at n={self._n_updates} "
                f"(score stream mean shifted)"
            )
            if result["drift_level"] == "none":
                result["drift_level"] = "WARNING"

        self.last_psi_report = result

        if result["alarms"]:
            logger.warning(
                "Drift detected: level=%s alarms=%s",
                result["drift_level"], result["alarms"]
            )
        else:
            logger.debug("Drift check: no drift (n=%d)", self._n_updates)

        return result

    def reset_drift_alarm(self) -> None:
        """Reset drift alarm after model retrain or manual acknowledgment."""
        self.drift_detected = False
        self.last_drift_time = None
        self._ph_test.reset()
        logger.info("Drift alarm reset")

    def get_status(self) -> Dict:
        """Return current drift status for health endpoint."""
        window_len = len(self._feature_window)
        score_arr  = np.array(list(self._score_window)) if self._score_window else np.array([])
        return {
            "drift_detected":  self.drift_detected,
            "n_processed":     self._n_updates,
            "window_filled":   f"{window_len}/{self.window_size}",
            "last_check_time": self.last_check_time,
            "last_drift_time": self.last_drift_time,
            "recent_mean_score": float(score_arr.mean()) if len(score_arr) > 0 else None,
            "recent_score_std":  float(score_arr.std())  if len(score_arr) > 0 else None,
            "last_drift_level":  self.last_psi_report.get("drift_level", "unknown"),
            "last_alarms":       self.last_psi_report.get("alarms", []),
        }


# ------------------------------------------------------------------ #
# Singleton
# ------------------------------------------------------------------ #

_detector_instance: Optional[DriftDetector] = None


def get_drift_detector(window_size: int = 500, check_every: int = 100) -> DriftDetector:
    """Get global drift detector singleton."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = DriftDetector(
            window_size=window_size,
            check_every=check_every,
        )
    return _detector_instance


# ------------------------------------------------------------------ #
# Standalone analysis mode
# ------------------------------------------------------------------ #

def _build_baseline_from_training() -> None:
    """Build and save drift baseline from training data."""
    import pickle, sys

    model_path = ROOT / "models" / "gradient_boosting_production.pkl"
    if not model_path.exists():
        print(f"ERROR: model not found at {model_path}")
        sys.exit(1)

    train_events_path = ROOT / "training" / "data" / "train_events.json"
    val_events_path   = ROOT / "training" / "data" / "val_events.json"

    if not train_events_path.exists():
        print(f"ERROR: training data not found")
        sys.exit(1)

    # Import feature extractor
    sys.path.insert(0, str(ROOT))
    from scripts.strict_audit import extract_v3

    print("Loading training data...")
    te = json.load(open(train_events_path, encoding="utf-8"))
    ve = json.load(open(val_events_path,   encoding="utf-8"))
    all_events = te + ve

    print(f"Extracting features for {len(all_events):,} events...")
    X = np.array([extract_v3(e) for e in all_events], dtype=np.float32)

    print("Computing ML scores...")
    with open(model_path, "rb") as fh:
        payload = pickle.load(fh)
    model  = payload["model"]
    scaler = payload["scaler"]

    # Sample for efficiency
    idx = np.random.RandomState(42).choice(len(X), min(5000, len(X)), replace=False)
    X_sample = scaler.transform(X[idx])
    scores   = model.predict_proba(X_sample)[:, 1].astype(np.float32)

    detector = get_drift_detector()
    detector.save_baseline(X[idx], scores)
    print(f"Baseline saved: {DRIFT_BASELINE_PATH}")
    print(f"  n_samples={len(idx)}")
    print(f"  mean_score={scores.mean():.4f}  std={scores.std():.4f}")
    print(f"  score distribution: [{scores.min():.3f}, {scores.max():.3f}]")


def _run_analysis() -> None:
    """Demonstrate drift detector with simulated drift."""
    import pickle

    print("=" * 60)
    print("  IR-Agent Drift Detector — Analysis Mode")
    print("=" * 60)

    if not DRIFT_BASELINE_PATH.exists():
        print("\nNo baseline found. Building from training data...")
        _build_baseline_from_training()
    else:
        data = json.load(open(DRIFT_BASELINE_PATH))
        print(f"\nBaseline loaded: {data.get('created_at', '?')}")
        print(f"  n_samples: {data.get('n_samples', '?')}")

    detector = get_drift_detector()

    print("\n--- Simulating no-drift (normal operation) ---")
    rng = np.random.RandomState(42)
    for _ in range(200):
        feat = rng.uniform(0, 0.1, 41).tolist()  # typical production event
        score = float(rng.uniform(0.05, 0.25))   # low score = benign-leaning
        detector.update(feat, score)

    status = detector.check()
    print(f"  Drift level: {status['drift_level']}")
    print(f"  Alarms: {status['alarms'] or 'none'}")

    print("\n--- Simulating drift (sudden attack spike) ---")
    for _ in range(200):
        feat = rng.uniform(0.5, 1.0, 41).tolist()  # high feature values
        score = float(rng.uniform(0.80, 0.99))      # high score = mostly malicious
        detector.update(feat, score)

    status = detector.check()
    print(f"  Drift level: {status['drift_level']}")
    print(f"  Alarms: {status['alarms'] or 'none'}")
    if status.get("psi_scores"):
        print(f"  Score PSI: {status['psi_scores']:.4f}")

    # Save report
    DRIFT_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "analysis_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "n_events_processed": detector._n_updates,
        "final_status": detector.get_status(),
        "last_psi_report": detector.last_psi_report,
    }
    with open(DRIFT_REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"\nReport saved: {DRIFT_REPORT_PATH}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--analyze",        action="store_true", help="Run drift analysis demo")
    parser.add_argument("--build-baseline", action="store_true", help="Build baseline from training data")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.build_baseline:
        _build_baseline_from_training()
    elif args.analyze:
        _run_analysis()
    else:
        print("Usage:")
        print("  py -m app.services.drift_detector --build-baseline")
        print("  py -m app.services.drift_detector --analyze")
        print()
        print("Integration:")
        print("  from app.services.drift_detector import get_drift_detector")
        print("  detector = get_drift_detector()")
        print("  detector.update(feature_vector, ml_score)")
        print("  status = detector.check()")
