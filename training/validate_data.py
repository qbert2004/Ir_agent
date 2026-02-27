"""
Валидация подготовленных данных перед обучением.

Проверяет:
1. Наличие всех необходимых файлов
2. Корректность формата данных
3. Баланс классов
4. Качество данных

Использование:
    python training/validate_data.py
"""

import os
import sys
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple

ROOT = Path(__file__).parent.parent
DATA_DIR = ROOT / "training" / "data"

# Классы
EVENT_CLASSES = [
    "benign",
    "suspicious_low",
    "suspicious_medium",
    "malicious_high",
    "malicious_critical",
]


def check_files_exist() -> Tuple[bool, List[str]]:
    """Проверяет наличие необходимых файлов."""
    required_files = [
        "train_events.json",
        "train_labels.json",
        "val_events.json",
        "val_labels.json",
    ]

    missing = []
    for f in required_files:
        if not (DATA_DIR / f).exists():
            missing.append(f)

    return len(missing) == 0, missing


def load_data() -> Tuple[List[Dict], List[str], List[Dict], List[str]]:
    """Загружает данные."""
    with open(DATA_DIR / "train_events.json", "r", encoding="utf-8") as f:
        train_events = json.load(f)

    with open(DATA_DIR / "train_labels.json", "r", encoding="utf-8") as f:
        train_labels = json.load(f)

    with open(DATA_DIR / "val_events.json", "r", encoding="utf-8") as f:
        val_events = json.load(f)

    with open(DATA_DIR / "val_labels.json", "r", encoding="utf-8") as f:
        val_labels = json.load(f)

    return train_events, train_labels, val_events, val_labels


def check_label_consistency(events: List[Dict], labels: List[str], name: str) -> List[str]:
    """Проверяет соответствие событий и меток."""
    issues = []

    if len(events) != len(labels):
        issues.append(f"{name}: Количество событий ({len(events)}) != количество меток ({len(labels)})")

    invalid_labels = [l for l in labels if l not in EVENT_CLASSES]
    if invalid_labels:
        unique_invalid = set(invalid_labels)
        issues.append(f"{name}: Невалидные метки: {unique_invalid}")

    return issues


def analyze_class_balance(labels: List[str], name: str) -> Dict:
    """Анализирует баланс классов."""
    stats = defaultdict(int)
    for label in labels:
        stats[label] += 1

    total = len(labels)
    balance = {}
    for cls in EVENT_CLASSES:
        count = stats[cls]
        pct = count / total * 100 if total > 0 else 0
        balance[cls] = {"count": count, "percent": round(pct, 2)}

    return balance


def check_event_quality(events: List[Dict], name: str) -> Dict:
    """Проверяет качество событий."""
    stats = {
        "total": len(events),
        "with_command_line": 0,
        "with_process_name": 0,
        "with_user": 0,
        "with_hostname": 0,
        "with_timestamp": 0,
        "with_event_id": 0,
        "empty_events": 0,
        "source_types": defaultdict(int),
    }

    for event in events:
        if event.get("command_line"):
            stats["with_command_line"] += 1
        if event.get("process_name"):
            stats["with_process_name"] += 1
        if event.get("user"):
            stats["with_user"] += 1
        if event.get("hostname"):
            stats["with_hostname"] += 1
        if event.get("timestamp"):
            stats["with_timestamp"] += 1
        if event.get("event_id"):
            stats["with_event_id"] += 1

        # Проверяем пустоту
        useful_fields = ["command_line", "process_name", "destination_ip", "source_ip"]
        if not any(event.get(f) for f in useful_fields):
            stats["empty_events"] += 1

        # Источник
        source = event.get("source_type", "unknown")
        stats["source_types"][source] += 1

    stats["source_types"] = dict(stats["source_types"])
    return stats


def check_data_leakage(train_events: List[Dict], val_events: List[Dict]) -> int:
    """Проверяет утечку данных между train и val."""
    # Создаём хэши событий
    def event_hash(event: Dict) -> str:
        cmd = event.get("command_line", "")
        proc = event.get("process_name", "")
        return f"{cmd}|{proc}"

    train_hashes = set(event_hash(e) for e in train_events)
    val_hashes = set(event_hash(e) for e in val_events)

    overlap = train_hashes & val_hashes
    # Исключаем пустые хэши
    overlap = {h for h in overlap if h != "|"}

    return len(overlap)


def print_report(
    train_events: List[Dict],
    train_labels: List[str],
    val_events: List[Dict],
    val_labels: List[str],
):
    """Выводит отчёт о валидации."""
    print("=" * 70)
    print("ОТЧЁТ ВАЛИДАЦИИ ДАННЫХ")
    print("=" * 70)

    # 1. Размер данных
    print("\n[1] РАЗМЕР ДАННЫХ")
    print(f"  Train: {len(train_events)} событий")
    print(f"  Validation: {len(val_events)} событий")
    print(f"  Всего: {len(train_events) + len(val_events)} событий")

    split_ratio = len(val_events) / (len(train_events) + len(val_events)) * 100
    print(f"  Val split: {split_ratio:.1f}%")

    # 2. Баланс классов
    print("\n[2] БАЛАНС КЛАССОВ (Train)")
    train_balance = analyze_class_balance(train_labels, "train")
    for cls, info in train_balance.items():
        bar = "█" * int(info["percent"] / 5)
        print(f"  {cls:20s}: {info['count']:6d} ({info['percent']:5.1f}%) {bar}")

    print("\n[3] БАЛАНС КЛАССОВ (Validation)")
    val_balance = analyze_class_balance(val_labels, "val")
    for cls, info in val_balance.items():
        bar = "█" * int(info["percent"] / 5)
        print(f"  {cls:20s}: {info['count']:6d} ({info['percent']:5.1f}%) {bar}")

    # 3. Качество данных
    print("\n[4] КАЧЕСТВО ДАННЫХ (Train)")
    train_quality = check_event_quality(train_events, "train")
    total = train_quality["total"]
    print(f"  С command_line: {train_quality['with_command_line']} ({train_quality['with_command_line']/total*100:.1f}%)")
    print(f"  С process_name: {train_quality['with_process_name']} ({train_quality['with_process_name']/total*100:.1f}%)")
    print(f"  С user: {train_quality['with_user']} ({train_quality['with_user']/total*100:.1f}%)")
    print(f"  С hostname: {train_quality['with_hostname']} ({train_quality['with_hostname']/total*100:.1f}%)")
    print(f"  Пустых событий: {train_quality['empty_events']} ({train_quality['empty_events']/total*100:.1f}%)")

    print("\n[5] ИСТОЧНИКИ ДАННЫХ")
    for source, count in train_quality["source_types"].items():
        pct = count / total * 100
        print(f"  {source}: {count} ({pct:.1f}%)")

    # 4. Утечка данных
    print("\n[6] ПРОВЕРКА УТЕЧКИ ДАННЫХ")
    leakage = check_data_leakage(train_events, val_events)
    if leakage > 0:
        leakage_pct = leakage / len(val_events) * 100
        print(f"  [WARNING] Найдено {leakage} дублирующихся событий ({leakage_pct:.1f}%)")
    else:
        print("  [OK] Утечка данных не обнаружена")

    # 5. Рекомендации
    print("\n[7] РЕКОМЕНДАЦИИ")
    issues = []

    # Проверяем баланс
    max_ratio = max(info["percent"] for info in train_balance.values())
    min_ratio = min(info["percent"] for info in train_balance.values() if info["count"] > 0)
    if max_ratio / min_ratio > 10:
        issues.append("- Сильный дисбаланс классов. Рекомендуется аугментация или weighted loss.")

    # Проверяем размер
    if len(train_events) < 1000:
        issues.append("- Мало данных для обучения. Рекомендуется добавить больше датасетов.")

    # Проверяем качество
    if train_quality["with_command_line"] / total < 0.5:
        issues.append("- Мало событий с command_line. Это снизит качество классификации.")

    if train_quality["empty_events"] / total > 0.1:
        issues.append("- Много пустых событий. Рекомендуется улучшить парсинг.")

    if leakage > len(val_events) * 0.05:
        issues.append("- Значительная утечка данных. Нужно пересоздать split.")

    if issues:
        for issue in issues:
            print(f"  {issue}")
    else:
        print("  [OK] Данные готовы к обучению!")

    # Готовность
    print("\n" + "=" * 70)
    ready = len(issues) == 0 or all("Рекомендуется" in i for i in issues)
    if ready:
        print("СТАТУС: ✓ ДАННЫЕ ГОТОВЫ К ОБУЧЕНИЮ")
    else:
        print("СТАТУС: ✗ ТРЕБУЕТСЯ ДОРАБОТКА")
    print("=" * 70)

    return ready


def main():
    print("=" * 70)
    print("ВАЛИДАЦИЯ ДАННЫХ ДЛЯ ОБУЧЕНИЯ")
    print("=" * 70)
    print(f"Директория: {DATA_DIR}")

    # Проверяем файлы
    print("\n[0] ПРОВЕРКА ФАЙЛОВ")
    files_ok, missing = check_files_exist()
    if not files_ok:
        print(f"  [ERROR] Отсутствуют файлы: {missing}")
        print("\n  Сначала запустите: python training/prepare_data_full.py")
        sys.exit(1)
    print("  [OK] Все файлы найдены")

    # Загружаем данные
    print("\n[LOAD] Загрузка данных...")
    try:
        train_events, train_labels, val_events, val_labels = load_data()
    except Exception as e:
        print(f"  [ERROR] Ошибка загрузки: {e}")
        sys.exit(1)

    # Проверяем консистентность
    issues = []
    issues.extend(check_label_consistency(train_events, train_labels, "Train"))
    issues.extend(check_label_consistency(val_events, val_labels, "Validation"))

    if issues:
        print("\n[ERROR] Обнаружены проблемы:")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)

    # Выводим отчёт
    ready = print_report(train_events, train_labels, val_events, val_labels)

    if ready:
        print("\nСледующий шаг: python training/train.py")
    else:
        print("\nИсправьте проблемы и запустите валидацию снова.")


if __name__ == "__main__":
    main()
