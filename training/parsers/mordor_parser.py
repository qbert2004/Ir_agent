"""
Парсер для Mordor Security Datasets.

Mordor содержит записи атак в формате JSON,
организованные по MITRE ATT&CK тактикам.

Использование:
    from training.parsers.mordor_parser import parse_mordor
    events, labels = parse_mordor("datasets/mordor")
"""

import os
import json
import gzip
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict


# Маппинг MITRE тактик на классы
TACTIC_TO_CLASS = {
    "credential-access": "malicious_critical",
    "credential_access": "malicious_critical",
    "defense-evasion": "malicious_high",
    "defense_evasion": "malicious_high",
    "execution": "malicious_high",
    "persistence": "malicious_high",
    "privilege-escalation": "malicious_high",
    "privilege_escalation": "malicious_high",
    "lateral-movement": "malicious_critical",
    "lateral_movement": "malicious_critical",
    "exfiltration": "malicious_critical",
    "impact": "malicious_critical",
    "command-and-control": "malicious_high",
    "command_and_control": "malicious_high",
    "collection": "suspicious_medium",
    "discovery": "suspicious_medium",
    "initial-access": "malicious_high",
    "initial_access": "malicious_high",
    "reconnaissance": "suspicious_low",
}


def parse_mordor(mordor_path: str) -> Tuple[List[Dict], List[str]]:
    """
    Парсит Mordor датасет.

    Args:
        mordor_path: Путь к папке mordor (datasets/mordor)

    Returns:
        (events, labels) - списки событий и меток
    """
    mordor_dir = Path(mordor_path)

    if not mordor_dir.exists():
        print(f"  [ERROR] Mordor не найден: {mordor_dir}")
        return [], []

    events = []
    labels = []
    stats = defaultdict(int)

    # Ищем JSON файлы с данными
    # Mordor структура: datasets/atomic/_metadata/ или datasets/compound/
    data_paths = [
        mordor_dir / "datasets",
        mordor_dir / "data",
        mordor_dir,
    ]

    json_files = []
    for data_path in data_paths:
        if data_path.exists():
            # JSON файлы
            json_files.extend(data_path.glob("**/*.json"))
            # Сжатые JSON
            json_files.extend(data_path.glob("**/*.json.gz"))

    print(f"  Найдено {len(json_files)} JSON файлов в Mordor")

    for json_file in json_files:
        try:
            # Определяем тактику из пути
            tactic = extract_tactic_from_path(json_file)

            # Читаем файл
            if str(json_file).endswith('.gz'):
                with gzip.open(json_file, 'rt', encoding='utf-8') as f:
                    content = f.read()
            else:
                with open(json_file, 'r', encoding='utf-8') as f:
                    content = f.read()

            # Парсим JSON (может быть массив или NDJSON)
            file_events = parse_json_content(content)

            # Определяем label
            label = TACTIC_TO_CLASS.get(tactic, "suspicious_medium")

            for event in file_events:
                # Нормализуем событие
                normalized = normalize_mordor_event(event)
                if normalized:
                    normalized['source_file'] = json_file.name
                    normalized['source_tactic'] = tactic
                    events.append(normalized)
                    labels.append(label)
                    stats[label] += 1

        except Exception as e:
            continue  # Пропускаем битые файлы

    print(f"  Извлечено {len(events)} событий из Mordor")
    print(f"  Распределение: {dict(stats)}")

    return events, labels


def extract_tactic_from_path(file_path: Path) -> str:
    """Извлекает MITRE тактику из пути к файлу."""
    path_str = str(file_path).lower()

    tactics = [
        "credential-access", "credential_access",
        "defense-evasion", "defense_evasion",
        "execution", "persistence",
        "privilege-escalation", "privilege_escalation",
        "lateral-movement", "lateral_movement",
        "exfiltration", "impact",
        "command-and-control", "command_and_control",
        "collection", "discovery",
        "initial-access", "initial_access",
        "reconnaissance",
    ]

    for tactic in tactics:
        if tactic in path_str:
            return tactic

    return "unknown"


def parse_json_content(content: str) -> List[Dict]:
    """Парсит JSON контент (массив или NDJSON)."""
    events = []

    # Пробуем как обычный JSON
    try:
        data = json.loads(content)
        if isinstance(data, list):
            events.extend(data)
        elif isinstance(data, dict):
            # Может быть обёрнут в metadata
            if 'data' in data:
                events.extend(data['data'] if isinstance(data['data'], list) else [data['data']])
            elif 'events' in data:
                events.extend(data['events'] if isinstance(data['events'], list) else [data['events']])
            else:
                events.append(data)
        return events
    except json.JSONDecodeError:
        pass

    # Пробуем как NDJSON (newline-delimited JSON)
    for line in content.strip().split('\n'):
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events


def normalize_mordor_event(event: Dict) -> Dict[str, Any]:
    """Нормализует событие из Mordor в единый формат."""
    normalized = {}

    # Sysmon events
    if 'EventID' in event or 'event_id' in event:
        normalized['event_id'] = event.get('EventID') or event.get('event_id')

    # Process information
    for key in ['Image', 'ProcessName', 'process_name', 'NewProcessName']:
        if key in event and event[key]:
            normalized['process_name'] = event[key]
            break

    # Command line
    for key in ['CommandLine', 'command_line', 'ProcessCommandLine']:
        if key in event and event[key]:
            normalized['command_line'] = event[key]
            break

    # Parent process
    for key in ['ParentImage', 'parent_image', 'ParentProcessName']:
        if key in event and event[key]:
            normalized['parent_image'] = event[key]
            break

    # User
    for key in ['User', 'user', 'SubjectUserName', 'TargetUserName', 'UserName']:
        if key in event and event[key]:
            normalized['user'] = event[key]
            break

    # Hostname
    for key in ['ComputerName', 'Computer', 'hostname', 'host']:
        if key in event and event[key]:
            normalized['hostname'] = event[key]
            break

    # Timestamp
    for key in ['TimeCreated', 'UtcTime', 'timestamp', '@timestamp']:
        if key in event and event[key]:
            normalized['timestamp'] = str(event[key])
            break

    # Network
    for key in ['DestinationIp', 'destination_ip', 'dst_ip']:
        if key in event and event[key]:
            normalized['destination_ip'] = event[key]
            break

    for key in ['DestinationPort', 'destination_port', 'dst_port']:
        if key in event and event[key]:
            try:
                normalized['destination_port'] = int(event[key])
            except (ValueError, TypeError):
                pass
            break

    # Hashes
    for key in ['Hashes', 'hashes', 'Hash', 'md5', 'sha256']:
        if key in event and event[key]:
            normalized['hashes'] = event[key]
            break

    # Logon type
    for key in ['LogonType', 'logon_type']:
        if key in event and event[key]:
            try:
                normalized['logon_type'] = int(event[key])
            except (ValueError, TypeError):
                pass
            break

    # Channel
    for key in ['Channel', 'channel', 'log_name']:
        if key in event and event[key]:
            normalized['channel'] = event[key]
            break

    # Возвращаем только если есть полезные данные
    if normalized.get('command_line') or normalized.get('process_name'):
        return normalized

    return None


if __name__ == "__main__":
    # Тест
    events, labels = parse_mordor("datasets/mordor")
    print(f"\nВсего: {len(events)} событий")
    if events:
        print(f"Пример: {events[0]}")
