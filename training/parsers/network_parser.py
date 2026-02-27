"""
Парсер для Network Traffic Datasets (CICIDS2017, CICIDS2018, UNSW-NB15).

Эти датасеты содержат сетевой трафик в формате CSV с метками.
Они требуют ручного скачивания из-за размера.

Использование:
    from training.parsers.network_parser import parse_cicids, parse_unsw
    events, labels = parse_cicids("datasets/cicids2017")
"""

import os
import csv
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict


# Маппинг атак CICIDS на наши классы
CICIDS_ATTACK_TO_CLASS = {
    # Benign
    "benign": "benign",
    "normal": "benign",

    # Critical - активные атаки
    "bot": "malicious_critical",
    "infiltration": "malicious_critical",
    "heartbleed": "malicious_critical",

    # High - DoS и Brute Force
    "dos hulk": "malicious_high",
    "dos goldeneye": "malicious_high",
    "dos slowloris": "malicious_high",
    "dos slowhttptest": "malicious_high",
    "ddos": "malicious_high",
    "ftp-patator": "malicious_high",
    "ssh-patator": "malicious_high",

    # Medium - Web атаки
    "web attack – brute force": "suspicious_medium",
    "web attack – xss": "suspicious_medium",
    "web attack – sql injection": "suspicious_medium",
    "web attack brute force": "suspicious_medium",
    "web attack xss": "suspicious_medium",
    "web attack sql injection": "suspicious_medium",

    # Low - сканирование
    "portscan": "suspicious_low",
    "port scan": "suspicious_low",
}

# Маппинг UNSW-NB15 атак
UNSW_ATTACK_TO_CLASS = {
    "normal": "benign",
    "generic": "suspicious_low",
    "exploits": "malicious_critical",
    "fuzzers": "suspicious_medium",
    "dos": "malicious_high",
    "reconnaissance": "suspicious_low",
    "analysis": "suspicious_medium",
    "backdoor": "malicious_critical",
    "shellcode": "malicious_critical",
    "worms": "malicious_critical",
}


def parse_cicids(cicids_path: str, max_events: int = 50000) -> Tuple[List[Dict], List[str]]:
    """
    Парсит CICIDS2017/2018 датасет.

    Args:
        cicids_path: Путь к папке с CSV файлами
        max_events: Максимальное количество событий (датасет очень большой)

    Returns:
        (events, labels) - списки событий и меток
    """
    cicids_dir = Path(cicids_path)

    if not cicids_dir.exists():
        print(f"  [ERROR] CICIDS не найден: {cicids_dir}")
        return [], []

    events = []
    labels = []
    stats = defaultdict(int)

    # Ищем CSV файлы
    csv_files = list(cicids_dir.glob("**/*.csv"))
    print(f"  Найдено {len(csv_files)} CSV файлов в CICIDS")

    for csv_file in csv_files:
        if len(events) >= max_events:
            break

        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Пробуем определить разделитель
                sample = f.read(4096)
                f.seek(0)

                delimiter = ',' if sample.count(',') > sample.count(';') else ';'
                reader = csv.DictReader(f, delimiter=delimiter)

                for row in reader:
                    if len(events) >= max_events:
                        break

                    # Нормализуем событие
                    event, label = normalize_cicids_event(row)
                    if event:
                        event['source_file'] = csv_file.name
                        event['source_type'] = 'cicids'
                        events.append(event)
                        labels.append(label)
                        stats[label] += 1

        except Exception as e:
            continue

    print(f"  Извлечено {len(events)} событий из CICIDS")
    print(f"  Распределение: {dict(stats)}")

    return events, labels


def normalize_cicids_event(row: Dict) -> Tuple[Dict, str]:
    """Нормализует событие CICIDS."""
    event = {}

    # Ищем колонку с меткой
    label_col = None
    for col in ['Label', 'label', ' Label', 'Attack', 'attack_cat']:
        if col in row:
            label_col = col
            break

    if not label_col:
        return None, "benign"

    raw_label = str(row[label_col]).strip().lower()
    label = CICIDS_ATTACK_TO_CLASS.get(raw_label, "suspicious_medium")

    # Извлекаем сетевые поля
    field_mapping = {
        # IP адреса
        ('Source IP', 'Src IP', ' Source IP', 'src_ip'): 'source_ip',
        ('Destination IP', 'Dst IP', ' Destination IP', 'dst_ip'): 'destination_ip',

        # Порты
        ('Source Port', 'Src Port', ' Source Port', 'src_port'): 'source_port',
        ('Destination Port', 'Dst Port', ' Destination Port', 'dst_port'): 'destination_port',

        # Протокол
        ('Protocol', 'protocol', ' Protocol'): 'protocol',

        # Flow данные
        ('Flow Duration', 'flow_duration', ' Flow Duration'): 'flow_duration',
        ('Total Fwd Packets', 'tot_fwd_pkts', ' Total Fwd Packets'): 'fwd_packets',
        ('Total Backward Packets', 'tot_bwd_pkts', ' Total Backward Packets'): 'bwd_packets',
        ('Flow Bytes/s', 'flow_byts_s', ' Flow Bytes/s'): 'bytes_per_sec',
        ('Flow Packets/s', 'flow_pkts_s', ' Flow Packets/s'): 'packets_per_sec',
    }

    for source_cols, target_col in field_mapping.items():
        for col in source_cols:
            if col in row and row[col]:
                value = row[col]
                # Конвертируем числа
                if target_col in ('source_port', 'destination_port', 'fwd_packets', 'bwd_packets'):
                    try:
                        value = int(float(value))
                    except:
                        continue
                elif target_col in ('flow_duration', 'bytes_per_sec', 'packets_per_sec'):
                    try:
                        value = float(value)
                    except:
                        continue
                event[target_col] = value
                break

    # Добавляем сырую метку для анализа
    event['raw_label'] = raw_label

    if event:
        return event, label
    return None, label


def parse_unsw(unsw_path: str, max_events: int = 50000) -> Tuple[List[Dict], List[str]]:
    """
    Парсит UNSW-NB15 датасет.

    Args:
        unsw_path: Путь к папке с CSV файлами
        max_events: Максимальное количество событий

    Returns:
        (events, labels) - списки событий и меток
    """
    unsw_dir = Path(unsw_path)

    if not unsw_dir.exists():
        print(f"  [ERROR] UNSW-NB15 не найден: {unsw_dir}")
        return [], []

    events = []
    labels = []
    stats = defaultdict(int)

    csv_files = list(unsw_dir.glob("**/*.csv"))
    print(f"  Найдено {len(csv_files)} CSV файлов в UNSW-NB15")

    for csv_file in csv_files:
        if len(events) >= max_events:
            break

        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    if len(events) >= max_events:
                        break

                    event, label = normalize_unsw_event(row)
                    if event:
                        event['source_file'] = csv_file.name
                        event['source_type'] = 'unsw'
                        events.append(event)
                        labels.append(label)
                        stats[label] += 1

        except Exception as e:
            continue

    print(f"  Извлечено {len(events)} событий из UNSW-NB15")
    print(f"  Распределение: {dict(stats)}")

    return events, labels


def normalize_unsw_event(row: Dict) -> Tuple[Dict, str]:
    """Нормализует событие UNSW-NB15."""
    event = {}

    # Метка
    raw_label = str(row.get('attack_cat', row.get('label', 'normal'))).strip().lower()
    label = UNSW_ATTACK_TO_CLASS.get(raw_label, "suspicious_medium")

    # Поля
    field_mapping = {
        'srcip': 'source_ip',
        'dstip': 'destination_ip',
        'sport': 'source_port',
        'dsport': 'destination_port',
        'proto': 'protocol',
        'dur': 'duration',
        'sbytes': 'src_bytes',
        'dbytes': 'dst_bytes',
        'sttl': 'src_ttl',
        'dttl': 'dst_ttl',
        'sloss': 'src_loss',
        'dloss': 'dst_loss',
        'service': 'service',
        'sload': 'src_load',
        'dload': 'dst_load',
        'spkts': 'src_packets',
        'dpkts': 'dst_packets',
    }

    for src, dst in field_mapping.items():
        if src in row and row[src]:
            value = row[src]
            if dst in ('source_port', 'destination_port', 'src_bytes', 'dst_bytes',
                      'src_packets', 'dst_packets', 'src_ttl', 'dst_ttl'):
                try:
                    value = int(float(value))
                except:
                    continue
            elif dst in ('duration', 'src_load', 'dst_load'):
                try:
                    value = float(value)
                except:
                    continue
            event[dst] = value

    event['raw_label'] = raw_label

    if event:
        return event, label
    return None, label


def convert_network_to_text(event: Dict) -> str:
    """
    Конвертирует сетевое событие в текстовое описание
    для использования с transformer embeddings.
    """
    parts = []

    # IP адреса
    src_ip = event.get('source_ip', 'unknown')
    dst_ip = event.get('destination_ip', 'unknown')
    parts.append(f"Connection from {src_ip} to {dst_ip}")

    # Порты
    src_port = event.get('source_port', '')
    dst_port = event.get('destination_port', '')
    if dst_port:
        parts.append(f"destination port {dst_port}")
    if src_port:
        parts.append(f"source port {src_port}")

    # Протокол
    protocol = event.get('protocol', '')
    if protocol:
        parts.append(f"protocol {protocol}")

    # Сервис
    service = event.get('service', '')
    if service:
        parts.append(f"service {service}")

    # Объём данных
    bytes_sent = event.get('src_bytes', event.get('fwd_packets', 0))
    bytes_recv = event.get('dst_bytes', event.get('bwd_packets', 0))
    if bytes_sent or bytes_recv:
        parts.append(f"bytes sent {bytes_sent} received {bytes_recv}")

    # Метрики трафика
    bps = event.get('bytes_per_sec', 0)
    pps = event.get('packets_per_sec', 0)
    if bps:
        parts.append(f"rate {bps:.0f} bytes/sec")
    if pps:
        parts.append(f"{pps:.0f} packets/sec")

    return " ".join(parts)


if __name__ == "__main__":
    # Тест CICIDS
    print("Тестирование парсера CICIDS...")
    events, labels = parse_cicids("datasets/cicids2017", max_events=100)
    if events:
        print(f"\nПример события: {events[0]}")
        print(f"Текстовое представление: {convert_network_to_text(events[0])}")

    # Тест UNSW
    print("\nТестирование парсера UNSW-NB15...")
    events, labels = parse_unsw("datasets/unsw-nb15", max_events=100)
    if events:
        print(f"\nПример события: {events[0]}")
