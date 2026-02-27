"""
ПОЛНЫЙ скрипт подготовки данных из ВСЕХ датасетов.

Использует:
- EVTX-ATTACK-SAMPLES (Windows Event Logs)
- Mordor Security Datasets
- Sigma Rules (для разметки и синтетических данных)
- Синтетические benign события

Использование:
    python training/prepare_data_full.py

    Опции:
    python training/prepare_data_full.py --no-mordor      # Без Mordor
    python training/prepare_data_full.py --no-sigma       # Без Sigma
    python training/prepare_data_full.py --no-synthetic   # Без синтетики
"""

import os
import sys
import json
import re
import random
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict
from datetime import datetime

# Добавляем корень проекта
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Пути
DATASETS_DIR = ROOT / "datasets"
OUTPUT_DIR = ROOT / "training" / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Классы
EVENT_CLASSES = [
    "benign",
    "suspicious_low",
    "suspicious_medium",
    "malicious_high",
    "malicious_critical",
]

# Импорты парсеров (с проверкой)
EVTX_AVAILABLE = False
MORDOR_AVAILABLE = False
SIGMA_AVAILABLE = False

try:
    import Evtx.Evtx as evtx
    from xml.etree import ElementTree as ET
    EVTX_AVAILABLE = True
except ImportError:
    print("[WARNING] python-evtx не установлен")

try:
    from training.parsers.mordor_parser import parse_mordor
    MORDOR_AVAILABLE = True
except ImportError:
    print("[WARNING] Mordor parser недоступен")

try:
    from training.parsers.sigma_parser import SigmaRulesParser
    SIGMA_AVAILABLE = True
except ImportError:
    print("[WARNING] Sigma parser недоступен")


# ============================================================================
# ПАТТЕРНЫ ДЛЯ РАЗМЕТКИ
# ============================================================================

CRITICAL_PATTERNS = [
    r"mimikatz", r"sekurlsa", r"lsass.*dump", r"procdump.*lsass",
    r"vssadmin.*delete.*shadow", r"bcdedit.*recoveryenabled.*no",
    r"wmic.*shadowcopy.*delete", r"ntdsutil", r"dcsync",
]

HIGH_PATTERNS = [
    r"powershell.*-enc", r"powershell.*downloadstring", r"powershell.*iex",
    r"certutil.*-urlcache", r"bitsadmin.*transfer", r"mshta.*http",
    r"regsvr32.*/s.*/u", r"rundll32.*javascript", r"wmic.*process.*call.*create",
    r"psexec", r"cobalt", r"meterpreter", r"empire", r"beacon",
]

MEDIUM_PATTERNS = [
    r"powershell.*-w.*hidden", r"powershell.*bypass", r"schtasks.*/create",
    r"sc.*create", r"reg.*add.*run", r"netsh.*firewall",
    r"net.*user.*add", r"net.*localgroup.*admin",
]

LOW_PATTERNS = [
    r"powershell", r"cmd\.exe", r"wscript", r"cscript",
    r"net.*user", r"ipconfig", r"systeminfo", r"tasklist",
]


# ============================================================================
# EVTX ПАРСЕР
# ============================================================================

def parse_evtx_files(evtx_dir: Path) -> List[Dict]:
    """Парсит EVTX файлы."""
    if not EVTX_AVAILABLE:
        print("  [SKIP] EVTX parser недоступен")
        return []

    events = []
    evtx_files = list(evtx_dir.glob("**/*.evtx"))
    print(f"  Найдено {len(evtx_files)} EVTX файлов")

    for i, evtx_file in enumerate(evtx_files):
        try:
            with evtx.Evtx(str(evtx_file)) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        event = extract_evtx_event(root, evtx_file.name)
                        if event:
                            events.append(event)
                    except:
                        continue
        except:
            continue

        if (i + 1) % 20 == 0:
            print(f"  Обработано {i+1}/{len(evtx_files)} файлов...")

    print(f"  Извлечено {len(events)} событий из EVTX")
    return events


def extract_evtx_event(root, source_file: str) -> Dict:
    """Извлекает данные из XML события."""
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    event = {"source_file": source_file, "source_type": "evtx"}

    system = root.find('e:System', ns)
    if system is not None:
        event_id_elem = system.find('e:EventID', ns)
        if event_id_elem is not None:
            event['event_id'] = int(event_id_elem.text or 0)

        computer = system.find('e:Computer', ns)
        if computer is not None:
            event['hostname'] = computer.text

        time_created = system.find('e:TimeCreated', ns)
        if time_created is not None:
            event['timestamp'] = time_created.get('SystemTime', '')

        channel = system.find('e:Channel', ns)
        if channel is not None:
            event['channel'] = channel.text

    event_data = root.find('e:EventData', ns)
    if event_data is not None:
        for data in event_data.findall('e:Data', ns):
            name = data.get('Name', '')
            value = data.text or ''

            if name == 'CommandLine':
                event['command_line'] = value
            elif name in ('NewProcessName', 'Image'):
                event['process_name'] = value
            elif name == 'ParentImage':
                event['parent_image'] = value
            elif name in ('User', 'SubjectUserName', 'TargetUserName'):
                if 'user' not in event:
                    event['user'] = value
            elif name == 'LogonType':
                event['logon_type'] = int(value) if value.isdigit() else 0
            elif name == 'DestinationIp':
                event['destination_ip'] = value
            elif name == 'DestinationPort':
                event['destination_port'] = int(value) if value.isdigit() else 0

    return event if len(event) > 2 else None


# ============================================================================
# РАЗМЕТКА
# ============================================================================

def auto_label_event(event: Dict, sigma_parser=None) -> str:
    """Автоматически присваивает метку событию."""
    cmdline = str(event.get('command_line', '')).lower()
    process = str(event.get('process_name', '')).lower()
    parent = str(event.get('parent_image', '')).lower()
    combined = f"{cmdline} {process} {parent}"

    # Сначала пробуем Sigma (если доступен)
    if sigma_parser:
        sigma_label = sigma_parser.match_event(event)
        if sigma_label:
            return sigma_label

    # Паттерны
    for pattern in CRITICAL_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return "malicious_critical"

    for pattern in HIGH_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return "malicious_high"

    for pattern in MEDIUM_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return "suspicious_medium"

    for pattern in LOW_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return "suspicious_low"

    # Если из attack samples
    source = event.get('source_type', '')
    if source in ('evtx', 'mordor'):
        return "suspicious_low"

    return "benign"


# ============================================================================
# СИНТЕТИЧЕСКИЕ ДАННЫЕ
# ============================================================================

def generate_benign_events(count: int = 2000) -> List[Dict]:
    """Генерирует benign события."""
    events = []

    benign_commands = [
        "notepad.exe document.txt",
        "calc.exe",
        "mspaint.exe",
        "explorer.exe /n,C:\\Users",
        "chrome.exe https://google.com",
        "firefox.exe",
        "code.exe project",
        "outlook.exe",
        "teams.exe",
        "winword.exe report.docx",
        "excel.exe data.xlsx",
        "git.exe pull",
        "python.exe script.py",
        "npm.exe install",
    ]

    benign_processes = [
        "notepad.exe", "calc.exe", "mspaint.exe", "explorer.exe",
        "chrome.exe", "firefox.exe", "code.exe", "outlook.exe",
        "teams.exe", "winword.exe", "excel.exe", "git.exe",
    ]

    users = ["john.doe", "jane.smith", "admin", "user1", "developer"]
    hostnames = ["WS-USER01", "WS-USER02", "DESKTOP-ABC", "LAPTOP-XYZ"]

    for i in range(count):
        events.append({
            "event_id": random.choice([4688, 4624, 1]),
            "hostname": random.choice(hostnames),
            "timestamp": f"2024-01-{random.randint(1,28):02d}T{random.randint(8,18):02d}:{random.randint(0,59):02d}:00Z",
            "channel": "Security",
            "process_name": random.choice(benign_processes),
            "command_line": random.choice(benign_commands),
            "user": random.choice(users),
            "source_file": "synthetic_benign",
            "source_type": "synthetic",
        })

    return events


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Подготовка данных для обучения")
    parser.add_argument("--no-mordor", action="store_true", help="Без Mordor")
    parser.add_argument("--no-sigma", action="store_true", help="Без Sigma")
    parser.add_argument("--no-synthetic", action="store_true", help="Без синтетики")
    parser.add_argument("--val-split", type=float, default=0.2, help="Доля валидации")
    args = parser.parse_args()

    print("=" * 70)
    print("ПОДГОТОВКА ДАННЫХ ДЛЯ ОБУЧЕНИЯ НЕЙРОСЕТИ")
    print("=" * 70)

    all_events = []
    all_labels = []

    # Sigma parser для разметки
    sigma_parser = None
    if SIGMA_AVAILABLE and not args.no_sigma:
        sigma_dir = DATASETS_DIR / "sigma"
        if sigma_dir.exists():
            print("\n[SIGMA] Загрузка Sigma Rules...")
            sigma_parser = SigmaRulesParser(str(sigma_dir))
            print(f"  Статистика: {sigma_parser.get_stats()}")

    # 1. EVTX
    print("\n[1/4] EVTX-ATTACK-SAMPLES")
    evtx_dir = DATASETS_DIR / "EVTX-ATTACK-SAMPLES"
    if evtx_dir.exists() and EVTX_AVAILABLE:
        evtx_events = parse_evtx_files(evtx_dir)
        for event in evtx_events:
            label = auto_label_event(event, sigma_parser)
            all_events.append(event)
            all_labels.append(label)
    else:
        print("  [SKIP] EVTX недоступен")

    # 2. Mordor
    print("\n[2/4] MORDOR SECURITY DATASETS")
    if MORDOR_AVAILABLE and not args.no_mordor:
        mordor_dir = DATASETS_DIR / "mordor"
        if mordor_dir.exists():
            mordor_events, mordor_labels = parse_mordor(str(mordor_dir))
            # Перепроверяем с Sigma
            for event, label in zip(mordor_events, mordor_labels):
                if sigma_parser:
                    sigma_label = sigma_parser.match_event(event)
                    if sigma_label:
                        label = sigma_label
                all_events.append(event)
                all_labels.append(label)
        else:
            print("  [SKIP] Mordor не найден")
    else:
        print("  [SKIP] Mordor отключен")

    # 3. Sigma synthetic
    print("\n[3/4] SIGMA SYNTHETIC EVENTS")
    if sigma_parser and not args.no_synthetic:
        sigma_events = sigma_parser.generate_synthetic_events(count_per_level=200)
        for event in sigma_events:
            label = SIGMA_LEVEL_TO_CLASS.get(event.get('sigma_level', 'medium'), 'suspicious_medium')
            all_events.append(event)
            all_labels.append(label)
        print(f"  Добавлено {len(sigma_events)} синтетических событий из Sigma")
    else:
        print("  [SKIP] Sigma synthetic отключен")

    # 4. Benign synthetic
    print("\n[4/4] BENIGN SYNTHETIC EVENTS")
    if not args.no_synthetic:
        # Генерируем достаточно benign для баланса
        malicious_count = sum(1 for l in all_labels if l != "benign")
        benign_needed = max(malicious_count, 2000)
        benign_events = generate_benign_events(benign_needed)
        for event in benign_events:
            all_events.append(event)
            all_labels.append("benign")
        print(f"  Добавлено {len(benign_events)} benign событий")
    else:
        print("  [SKIP] Synthetic отключен")

    # Статистика до split
    print("\n" + "=" * 70)
    print("СТАТИСТИКА")
    print("=" * 70)
    print(f"Всего событий: {len(all_events)}")

    label_stats = defaultdict(int)
    for label in all_labels:
        label_stats[label] += 1

    for label in EVENT_CLASSES:
        count = label_stats[label]
        pct = count / len(all_labels) * 100 if all_labels else 0
        print(f"  {label}: {count} ({pct:.1f}%)")

    # Split
    print("\n[SPLIT] Разделение на train/validation...")
    combined = list(zip(all_events, all_labels))
    random.shuffle(combined)

    split_idx = int(len(combined) * (1 - args.val_split))
    train_data = combined[:split_idx]
    val_data = combined[split_idx:]

    train_events = [e for e, l in train_data]
    train_labels = [l for e, l in train_data]
    val_events = [e for e, l in val_data]
    val_labels = [l for e, l in val_data]

    print(f"  Train: {len(train_events)}")
    print(f"  Validation: {len(val_events)}")

    # Save
    print("\n[SAVE] Сохранение...")

    with open(OUTPUT_DIR / "train_events.json", "w", encoding="utf-8") as f:
        json.dump(train_events, f, ensure_ascii=False, indent=2)

    with open(OUTPUT_DIR / "train_labels.json", "w", encoding="utf-8") as f:
        json.dump(train_labels, f, ensure_ascii=False)

    with open(OUTPUT_DIR / "val_events.json", "w", encoding="utf-8") as f:
        json.dump(val_events, f, ensure_ascii=False, indent=2)

    with open(OUTPUT_DIR / "val_labels.json", "w", encoding="utf-8") as f:
        json.dump(val_labels, f, ensure_ascii=False)

    # Stats file
    stats = {
        "total_events": len(all_events),
        "train_size": len(train_events),
        "val_size": len(val_events),
        "class_distribution": dict(label_stats),
        "created_at": datetime.now().isoformat(),
        "sources": {
            "evtx": sum(1 for e in all_events if e.get('source_type') == 'evtx'),
            "mordor": sum(1 for e in all_events if e.get('source_type') == 'mordor'),
            "synthetic": sum(1 for e in all_events if e.get('source_type') == 'synthetic'),
            "sigma": sum(1 for e in all_events if e.get('source_file') == 'sigma_synthetic'),
        }
    }

    with open(OUTPUT_DIR / "data_stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print(f"\n  Сохранено в: {OUTPUT_DIR}")

    print("\n" + "=" * 70)
    print("ГОТОВО!")
    print("=" * 70)
    print(f"\nСледующий шаг: python training/train.py")


# Для Sigma label mapping
SIGMA_LEVEL_TO_CLASS = {
    "critical": "malicious_critical",
    "high": "malicious_high",
    "medium": "suspicious_medium",
    "low": "suspicious_low",
    "informational": "benign",
}


if __name__ == "__main__":
    main()
