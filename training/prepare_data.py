"""
Скрипт подготовки данных для обучения нейросетевого классификатора.

ЗАПУСКАТЬ НА ЛЮБОМ КОМПЬЮТЕРЕ (GPU не нужен)

Этот скрипт:
1. Парсит EVTX файлы из datasets/EVTX-ATTACK-SAMPLES
2. Создаёт labeled dataset (events + labels)
3. Сохраняет в training/data/ для последующего обучения

Использование:
    python training/prepare_data.py

После выполнения в папке training/data/ будут файлы:
    - train_events.json    (события для обучения)
    - train_labels.json    (метки)
    - val_events.json      (события для валидации)
    - val_labels.json      (метки валидации)
    - data_stats.json      (статистика)
"""

import os
import sys
import json
import re
import random
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict
from datetime import datetime

# Добавляем корень проекта в path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Пути
EVTX_DIR = ROOT / "datasets" / "EVTX-ATTACK-SAMPLES"
OUTPUT_DIR = ROOT / "training" / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# МЕТКИ КЛАССОВ
# ============================================================================

# Классы для классификации событий
EVENT_CLASSES = [
    "benign",              # 0 - Нормальная активность
    "suspicious_low",      # 1 - Слабо подозрительно
    "suspicious_medium",   # 2 - Средне подозрительно
    "malicious_high",      # 3 - Вредоносно (высокий риск)
    "malicious_critical",  # 4 - Критически вредоносно
]

# Паттерны для автоматической разметки
# (на реальном проекте лучше размечать вручную или semi-supervised)

CRITICAL_PATTERNS = [
    r"mimikatz",
    r"sekurlsa",
    r"lsass.*dump",
    r"procdump.*lsass",
    r"vssadmin.*delete.*shadow",
    r"bcdedit.*recoveryenabled.*no",
    r"wmic.*shadowcopy.*delete",
    r"ransomware",
    r"encrypt.*files",
]

HIGH_PATTERNS = [
    r"powershell.*-enc",
    r"powershell.*downloadstring",
    r"powershell.*iex",
    r"cmd.*/c.*powershell",
    r"certutil.*-urlcache",
    r"bitsadmin.*transfer",
    r"mshta.*http",
    r"regsvr32.*/s.*/u",
    r"rundll32.*javascript",
    r"wmic.*process.*call.*create",
    r"psexec",
    r"cobalt",
    r"meterpreter",
    r"empire",
    r"beacon",
]

MEDIUM_PATTERNS = [
    r"powershell.*-w.*hidden",
    r"powershell.*bypass",
    r"cmd.*/c.*del",
    r"schtasks.*/create",
    r"sc.*create",
    r"reg.*add.*run",
    r"netsh.*firewall",
    r"whoami.*/priv",
    r"net.*user.*add",
    r"net.*localgroup.*admin",
]

LOW_PATTERNS = [
    r"powershell",
    r"cmd\.exe",
    r"wscript",
    r"cscript",
    r"net.*user",
    r"net.*share",
    r"ipconfig",
    r"systeminfo",
    r"tasklist",
    r"netstat",
]

# Процессы, которые почти всегда benign
BENIGN_PROCESSES = [
    "svchost.exe",
    "services.exe",
    "lsass.exe",  # сам по себе нормальный, подозрителен только доступ к нему
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "explorer.exe",
    "taskhostw.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
]


# ============================================================================
# ПАРСИНГ EVTX
# ============================================================================

def parse_evtx_file(file_path: Path) -> List[Dict[str, Any]]:
    """Парсит EVTX файл и возвращает список событий."""
    events = []

    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
        from xml.etree import ElementTree as ET
    except ImportError:
        print("ОШИБКА: Установите python-evtx: pip install python-evtx")
        return events

    try:
        with evtx.Evtx(str(file_path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)

                    # Извлекаем данные
                    event = extract_event_data(root, file_path.name)
                    if event:
                        events.append(event)

                except Exception as e:
                    continue  # Пропускаем битые записи

    except Exception as e:
        print(f"  Ошибка чтения {file_path.name}: {e}")

    return events


def extract_event_data(root, source_file: str) -> Dict[str, Any]:
    """Извлекает данные из XML события."""
    ns = {
        'e': 'http://schemas.microsoft.com/win/2004/08/events/event'
    }

    event = {"source_file": source_file}

    # System данные
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

    # EventData
    event_data = root.find('e:EventData', ns)
    if event_data is not None:
        for data in event_data.findall('e:Data', ns):
            name = data.get('Name', '')
            value = data.text or ''

            if name == 'CommandLine':
                event['command_line'] = value
            elif name == 'NewProcessName' or name == 'Image':
                event['process_name'] = value
            elif name == 'ParentImage':
                event['parent_image'] = value
            elif name == 'User' or name == 'SubjectUserName' or name == 'TargetUserName':
                if 'user' not in event:
                    event['user'] = value
            elif name == 'LogonType':
                event['logon_type'] = int(value) if value.isdigit() else 0
            elif name == 'DestinationIp':
                event['destination_ip'] = value
            elif name == 'DestinationPort':
                event['destination_port'] = int(value) if value.isdigit() else 0
            elif name == 'TargetFilename':
                event['file_path'] = value
            elif name == 'Hashes':
                event['hashes'] = value

    return event if len(event) > 2 else None


# ============================================================================
# АВТОМАТИЧЕСКАЯ РАЗМЕТКА
# ============================================================================

def auto_label_event(event: Dict[str, Any], is_attack_sample: bool = True) -> str:
    """
    Автоматически присваивает метку событию.

    Args:
        event: Словарь события
        is_attack_sample: True если из папки с атаками

    Returns:
        Метка класса
    """
    # Собираем текст для анализа
    text_parts = []

    cmdline = str(event.get('command_line', '')).lower()
    process = str(event.get('process_name', '')).lower()
    parent = str(event.get('parent_image', '')).lower()

    text_parts.extend([cmdline, process, parent])
    combined_text = ' '.join(text_parts)

    # Проверяем паттерны от самых опасных к наименее опасным

    # CRITICAL
    for pattern in CRITICAL_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            return "malicious_critical"

    # HIGH
    for pattern in HIGH_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            return "malicious_high"

    # MEDIUM
    for pattern in MEDIUM_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            return "suspicious_medium"

    # LOW
    for pattern in LOW_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            # Если из attack samples - скорее всего подозрительно
            if is_attack_sample:
                return "suspicious_low"
            return "benign"

    # Если из attack samples без явных паттернов - low suspicious
    if is_attack_sample and cmdline:
        return "suspicious_low"

    # По умолчанию benign
    return "benign"


# ============================================================================
# ГЕНЕРАЦИЯ СИНТЕТИЧЕСКИХ BENIGN СОБЫТИЙ
# ============================================================================

def generate_benign_events(count: int = 1000) -> List[Dict[str, Any]]:
    """Генерирует синтетические benign события для баланса."""
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
        "slack.exe",
        "spotify.exe",
        "vlc.exe movie.mp4",
        "winword.exe report.docx",
        "excel.exe data.xlsx",
        "powerpnt.exe presentation.pptx",
        "acrobat.exe document.pdf",
        "7zfm.exe",
        "git.exe pull",
        "git.exe push",
        "npm.exe install",
        "python.exe script.py",
        "java.exe -jar app.jar",
        "dotnet.exe build",
    ]

    benign_processes = [
        "notepad.exe", "calc.exe", "mspaint.exe", "explorer.exe",
        "chrome.exe", "firefox.exe", "msedge.exe", "code.exe",
        "outlook.exe", "teams.exe", "slack.exe", "spotify.exe",
        "winword.exe", "excel.exe", "powerpnt.exe", "acrobat.exe",
    ]

    users = ["john.doe", "jane.smith", "admin", "user1", "developer"]
    hostnames = ["WS-USER01", "WS-USER02", "DESKTOP-ABC", "LAPTOP-XYZ"]

    for i in range(count):
        event = {
            "event_id": random.choice([4688, 4624, 1]),
            "hostname": random.choice(hostnames),
            "timestamp": f"2024-01-{random.randint(1,28):02d}T{random.randint(8,18):02d}:{random.randint(0,59):02d}:00Z",
            "channel": "Security",
            "process_name": random.choice(benign_processes),
            "command_line": random.choice(benign_commands),
            "user": random.choice(users),
            "source_file": "synthetic_benign",
        }
        events.append(event)

    return events


# ============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================================

def main():
    print("=" * 70)
    print("ПОДГОТОВКА ДАННЫХ ДЛЯ ОБУЧЕНИЯ")
    print("=" * 70)

    all_events = []
    all_labels = []

    # 1. Парсим EVTX файлы с атаками
    print("\n[1/4] Парсинг EVTX файлов...")

    if not EVTX_DIR.exists():
        print(f"  ОШИБКА: Папка {EVTX_DIR} не найдена!")
        print("  Скачайте датасет: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES")
        return

    evtx_files = list(EVTX_DIR.glob("**/*.evtx"))
    print(f"  Найдено {len(evtx_files)} EVTX файлов")

    attack_events = []
    for i, evtx_file in enumerate(evtx_files):
        events = parse_evtx_file(evtx_file)
        attack_events.extend(events)

        if (i + 1) % 10 == 0:
            print(f"  Обработано {i+1}/{len(evtx_files)} файлов, событий: {len(attack_events)}")

    print(f"  Всего событий из атак: {len(attack_events)}")

    # 2. Размечаем события атак
    print("\n[2/4] Разметка событий атак...")

    for event in attack_events:
        label = auto_label_event(event, is_attack_sample=True)
        all_events.append(event)
        all_labels.append(label)

    # Статистика по атакам
    attack_stats = defaultdict(int)
    for label in all_labels:
        attack_stats[label] += 1
    print(f"  Распределение меток атак: {dict(attack_stats)}")

    # 3. Добавляем benign события для баланса
    print("\n[3/4] Генерация benign событий для баланса...")

    # Генерируем столько benign, чтобы было ~50% от общего
    benign_count = len(attack_events)
    benign_events = generate_benign_events(benign_count)

    for event in benign_events:
        all_events.append(event)
        all_labels.append("benign")

    print(f"  Добавлено {len(benign_events)} benign событий")

    # 4. Разделение на train/val
    print("\n[4/4] Разделение на train/validation...")

    # Перемешиваем
    combined = list(zip(all_events, all_labels))
    random.shuffle(combined)

    # 80% train, 20% val
    split_idx = int(len(combined) * 0.8)
    train_data = combined[:split_idx]
    val_data = combined[split_idx:]

    train_events = [e for e, l in train_data]
    train_labels = [l for e, l in train_data]
    val_events = [e for e, l in val_data]
    val_labels = [l for e, l in val_data]

    print(f"  Train: {len(train_events)} событий")
    print(f"  Validation: {len(val_events)} событий")

    # Сохраняем
    print("\n[СОХРАНЕНИЕ]")

    with open(OUTPUT_DIR / "train_events.json", "w", encoding="utf-8") as f:
        json.dump(train_events, f, ensure_ascii=False, indent=2)
    print(f"  [OK] {OUTPUT_DIR / 'train_events.json'}")

    with open(OUTPUT_DIR / "train_labels.json", "w", encoding="utf-8") as f:
        json.dump(train_labels, f, ensure_ascii=False)
    print(f"  [OK] {OUTPUT_DIR / 'train_labels.json'}")

    with open(OUTPUT_DIR / "val_events.json", "w", encoding="utf-8") as f:
        json.dump(val_events, f, ensure_ascii=False, indent=2)
    print(f"  [OK] {OUTPUT_DIR / 'val_events.json'}")

    with open(OUTPUT_DIR / "val_labels.json", "w", encoding="utf-8") as f:
        json.dump(val_labels, f, ensure_ascii=False)
    print(f"  [OK] {OUTPUT_DIR / 'val_labels.json'}")

    # Статистика
    final_stats = {
        "total_events": len(all_events),
        "train_size": len(train_events),
        "val_size": len(val_events),
        "class_distribution": {},
        "created_at": datetime.now().isoformat(),
        "evtx_files_processed": len(evtx_files),
    }

    for label in EVENT_CLASSES:
        final_stats["class_distribution"][label] = all_labels.count(label)

    with open(OUTPUT_DIR / "data_stats.json", "w", encoding="utf-8") as f:
        json.dump(final_stats, f, ensure_ascii=False, indent=2)
    print(f"  [OK] {OUTPUT_DIR / 'data_stats.json'}")

    # Итог
    print("\n" + "=" * 70)
    print("ГОТОВО!")
    print("=" * 70)
    print(f"\nВсего событий: {final_stats['total_events']}")
    print(f"Train: {final_stats['train_size']}")
    print(f"Validation: {final_stats['val_size']}")
    print(f"\nРаспределение классов:")
    for cls, count in final_stats["class_distribution"].items():
        pct = count / final_stats['total_events'] * 100
        print(f"  {cls}: {count} ({pct:.1f}%)")

    print(f"\nФайлы сохранены в: {OUTPUT_DIR}")
    print("\nСледующий шаг: запустите training/train.py на компьютере с GPU")


if __name__ == "__main__":
    main()
