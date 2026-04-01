"""
Пересборка датасета с использованием реальных benign событий.

ПРОБЛЕМА (которую исправляем):
  - synthetic source = 100% benign
  - evtx source = 100% malicious
  Модель выучивает источник данных, а не атаку (GroupKFold accuracy = 64.8%)

РЕШЕНИЕ:
  - Убираем synthetic полностью
  - Добавляем real_benign (80k реальных Sysmon логов) как benign класс
  - evtx + unknown остаются как malicious класс
  - Оба класса теперь - реальные логи с реальных машин

Новый датасет:
  TRAIN: real_benign (60k) + evtx (37k) + unknown_train (30k) = 127k событий
  VAL:   real_benign (20k) + unknown_val (18k)                 = 38k событий
         ↑ val содержит ОБА класса из реальных данных

Использование:
  python scripts/rebuild_dataset.py
  python scripts/rebuild_dataset.py --dry-run   # только статистика
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent.parent
REAL_BENIGN = ROOT / "datasets" / "real_benign_sysmon.json"
TRAIN_EVENTS = ROOT / "training" / "data" / "train_events.json"
TRAIN_LABELS = ROOT / "training" / "data" / "train_labels.json"
VAL_EVENTS = ROOT / "training" / "data" / "val_events.json"
VAL_LABELS = ROOT / "training" / "data" / "val_labels.json"
DATA_STATS = ROOT / "training" / "data" / "data_stats.json"

RANDOM_SEED = 42

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _to_binary(label) -> int:
    """Унифицирует метки: 0 = benign, 1 = malicious."""
    if isinstance(label, int):
        return label
    if isinstance(label, dict):
        val = label.get("label", label.get("is_malicious", 0))
        return int(val)
    s = str(label).lower()
    if s.startswith("benign"):
        return 0
    return 1


def load_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))


def section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="Rebuild training dataset with real benign data")
    parser.add_argument("--dry-run", action="store_true", help="Only show statistics, don't write files")
    parser.add_argument("--benign-train", type=int, default=60_000, help="Real benign events for train")
    parser.add_argument("--benign-val", type=int, default=20_000, help="Real benign events for val")
    parser.add_argument("--unknown-val-frac", type=float, default=0.27, help="Fraction of unknown events for val")
    args = parser.parse_args()

    rng = random.Random(RANDOM_SEED)

    print("=" * 60)
    print("  IR-Agent Dataset Rebuild")
    print("  Strategy: Real Benign + Real Attacks (no synthetic)")
    print("=" * 60)

    # ------------------------------------------------------------------ #
    # 1. Load real benign data
    # ------------------------------------------------------------------ #
    section("1. Loading real benign events")

    if not REAL_BENIGN.exists():
        print(f"  ERROR: {REAL_BENIGN} not found!")
        sys.exit(1)

    real_benign_all = load_json(REAL_BENIGN)
    print(f"  Real benign events available: {len(real_benign_all):,}")

    # Shuffle and split
    rng.shuffle(real_benign_all)
    n_train = min(args.benign_train, len(real_benign_all))
    n_val = min(args.benign_val, len(real_benign_all) - n_train)

    benign_train = real_benign_all[:n_train]
    benign_val = real_benign_all[n_train:n_train + n_val]
    print(f"  train benign: {len(benign_train):,}")
    print(f"  val benign:   {len(benign_val):,}")

    # ------------------------------------------------------------------ #
    # 2. Load existing attack events (evtx + unknown)
    # ------------------------------------------------------------------ #
    section("2. Loading attack events from existing training data")

    old_train = load_json(TRAIN_EVENTS)
    old_train_labels = load_json(TRAIN_LABELS)
    old_val = load_json(VAL_EVENTS)
    old_val_labels = load_json(VAL_LABELS)

    # Collect all events with their labels, filter out synthetic benign
    all_attack_events = []
    all_attack_labels = []

    for e, l in zip(old_train + old_val, old_train_labels + old_val_labels):
        src = e.get("source_type", "unknown")
        binary = _to_binary(l)
        if src == "synthetic":
            # УБИРАЕМ синтетику
            continue
        if binary == 0 and src != "real_benign":
            # Пропускаем prочие benign события не из real_benign
            continue
        if binary == 1:
            # Атаки берём все
            all_attack_events.append(e)
            all_attack_labels.append(1)

    # Count by source
    attack_sources = Counter(e.get("source_type", "unknown") for e in all_attack_events)
    print(f"  Attack events by source:")
    for src, cnt in sorted(attack_sources.items(), key=lambda x: -x[1]):
        print(f"    {src:20s}: {cnt:,}")
    print(f"  Total attacks: {len(all_attack_events):,}")

    # ------------------------------------------------------------------ #
    # 3. Split attacks into train/val
    # ------------------------------------------------------------------ #
    section("3. Splitting attacks into train/val")

    # unknown source goes mostly to val (was used for val in source-split)
    # evtx source goes all to train
    evtx_events = [(e, l) for e, l in zip(all_attack_events, all_attack_labels)
                   if e.get("source_type") == "evtx"]
    unknown_events = [(e, l) for e, l in zip(all_attack_events, all_attack_labels)
                      if e.get("source_type") not in ("evtx", "synthetic")]

    # Shuffle
    rng.shuffle(evtx_events)
    rng.shuffle(unknown_events)

    # Put all evtx in train, split unknown
    n_unknown_val = int(len(unknown_events) * args.unknown_val_frac)
    unknown_train = unknown_events[n_unknown_val:]
    unknown_val = unknown_events[:n_unknown_val]

    attack_train_pairs = evtx_events + unknown_train
    attack_val_pairs = unknown_val

    print(f"  EVTX (all -> train):  {len(evtx_events):,}")
    print(f"  Unknown -> train:     {len(unknown_train):,}")
    print(f"  Unknown -> val:       {len(unknown_val):,}")

    # ------------------------------------------------------------------ #
    # 4. Assemble final train/val sets
    # ------------------------------------------------------------------ #
    section("4. Assembling final datasets")

    # TRAIN: benign + attacks
    train_events_list = benign_train + [e for e, _ in attack_train_pairs]
    train_labels_list = [0] * len(benign_train) + [l for _, l in attack_train_pairs]

    # VAL: benign + attacks (BOTH classes in val — правильная оценка)
    val_events_list = benign_val + [e for e, _ in attack_val_pairs]
    val_labels_list = [0] * len(benign_val) + [l for _, l in attack_val_pairs]

    # Shuffle within each set
    train_combined = list(zip(train_events_list, train_labels_list))
    val_combined = list(zip(val_events_list, val_labels_list))
    rng.shuffle(train_combined)
    rng.shuffle(val_combined)

    train_events_final = [e for e, _ in train_combined]
    train_labels_final = [l for _, l in train_combined]
    val_events_final = [e for e, _ in val_combined]
    val_labels_final = [l for _, l in val_combined]

    train_dist = Counter(train_labels_final)
    val_dist = Counter(val_labels_final)

    print(f"\n  TRAIN: {len(train_events_final):,} events")
    print(f"    benign:    {train_dist[0]:,} ({train_dist[0]/len(train_events_final)*100:.1f}%)")
    print(f"    malicious: {train_dist[1]:,} ({train_dist[1]/len(train_events_final)*100:.1f}%)")

    print(f"\n  VAL:   {len(val_events_final):,} events")
    print(f"    benign:    {val_dist[0]:,} ({val_dist[0]/len(val_events_final)*100:.1f}%)")
    print(f"    malicious: {val_dist[1]:,} ({val_dist[1]/len(val_events_final)*100:.1f}%)")

    # Source distribution in train and val
    train_src = Counter(e.get("source_type", "unknown") for e in train_events_final)
    val_src = Counter(e.get("source_type", "unknown") for e in val_events_final)
    print(f"\n  TRAIN sources: {dict(train_src)}")
    print(f"  VAL sources:   {dict(val_src)}")

    # ------------------------------------------------------------------ #
    # 5. Validate (check leakage risk)
    # ------------------------------------------------------------------ #
    section("5. Leakage check")

    # Check: does source predict label?
    for name, events, labels in [("TRAIN", train_events_final, train_labels_final),
                                  ("VAL", val_events_final, val_labels_final)]:
        src_label = {}
        for e, l in zip(events, labels):
            src = e.get("source_type", "unknown")
            if src not in src_label:
                src_label[src] = []
            src_label[src].append(l)

        print(f"\n  {name} source-label distribution:")
        for src, lbls in sorted(src_label.items()):
            c = Counter(lbls)
            total = len(lbls)
            benign_pct = c[0] / total * 100
            mal_pct = c[1] / total * 100
            coupling = "WARNING: 100% coupling!" if (benign_pct == 100 or mal_pct == 100) else "OK (mixed)"
            print(f"    {src:20s}: benign={benign_pct:.0f}% malicious={mal_pct:.0f}%  [{coupling}]")

    # ------------------------------------------------------------------ #
    # 6. Save
    # ------------------------------------------------------------------ #
    if args.dry_run:
        print("\n  [DRY RUN] Файлы не сохранены.")
        return

    section("6. Saving")

    save_json(TRAIN_EVENTS, train_events_final)
    save_json(TRAIN_LABELS, train_labels_final)
    save_json(VAL_EVENTS, val_events_final)
    save_json(VAL_LABELS, val_labels_final)

    from datetime import datetime
    stats = {
        "created_at": datetime.now().isoformat(),
        "strategy": "real_benign_vs_real_attacks_no_synthetic",
        "total_events": len(train_events_final) + len(val_events_final),
        "train_size": len(train_events_final),
        "val_size": len(val_events_final),
        "class_distribution": {
            "train_benign": int(train_dist[0]),
            "train_malicious": int(train_dist[1]),
            "val_benign": int(val_dist[0]),
            "val_malicious": int(val_dist[1]),
        },
        "sources": {
            "train": {k: int(v) for k, v in train_src.items()},
            "val": {k: int(v) for k, v in val_src.items()},
        },
        "notes": (
            "Synthetic benign REMOVED. Real benign (Sysmon operational logs) "
            "used instead. Both train and val contain real events from both classes."
        ),
    }
    save_json(DATA_STATS, stats)

    print(f"  [OK] {TRAIN_EVENTS}")
    print(f"  [OK] {TRAIN_LABELS}")
    print(f"  [OK] {VAL_EVENTS}")
    print(f"  [OK] {VAL_LABELS}")
    print(f"  [OK] {DATA_STATS}")

    section("DONE")
    print(f"""
  New dataset summary:
  --------------------------------------------------
  TRAIN: {len(train_events_final):,} events  (benign={train_dist[0]:,} | malicious={train_dist[1]:,})
  VAL:   {len(val_events_final):,} events  (benign={val_dist[0]:,} | malicious={val_dist[1]:,})

  Key improvement:
  - No more synthetic data
  - Both classes are real Sysmon/EVTX logs
  - Val set contains BOTH classes (real evaluation)

  Next step:
    python scripts/retrain_source_split.py
    """)


if __name__ == "__main__":
    main()
