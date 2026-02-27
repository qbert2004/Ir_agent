"""
Парсер для Sigma Rules.

Sigma Rules используются для:
1. Генерации паттернов детекции
2. Автоматической разметки событий
3. Создания синтетических malicious событий

Использование:
    from training.parsers.sigma_parser import SigmaRulesParser
    parser = SigmaRulesParser("datasets/sigma")
    patterns = parser.get_detection_patterns()
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# Маппинг Sigma level на наши классы
SIGMA_LEVEL_TO_CLASS = {
    "critical": "malicious_critical",
    "high": "malicious_high",
    "medium": "suspicious_medium",
    "low": "suspicious_low",
    "informational": "benign",
}


class SigmaRulesParser:
    """Парсер Sigma правил для генерации паттернов и разметки."""

    def __init__(self, sigma_path: str):
        """
        Args:
            sigma_path: Путь к папке sigma (datasets/sigma)
        """
        self.sigma_dir = Path(sigma_path)
        self.rules = []
        self.patterns = defaultdict(list)

        if not YAML_AVAILABLE:
            print("  [WARNING] PyYAML не установлен. pip install pyyaml")
            return

        self._load_rules()

    def _load_rules(self):
        """Загружает все Sigma правила."""
        if not self.sigma_dir.exists():
            print(f"  [ERROR] Sigma не найден: {self.sigma_dir}")
            return

        # Sigma rules находятся в rules/
        rules_dir = self.sigma_dir / "rules"
        if not rules_dir.exists():
            rules_dir = self.sigma_dir

        yaml_files = list(rules_dir.glob("**/*.yml")) + list(rules_dir.glob("**/*.yaml"))
        print(f"  Найдено {len(yaml_files)} Sigma правил")

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Некоторые файлы содержат несколько документов
                for doc in yaml.safe_load_all(content):
                    if doc and isinstance(doc, dict):
                        rule = self._parse_rule(doc, yaml_file)
                        if rule:
                            self.rules.append(rule)

            except Exception as e:
                continue  # Пропускаем битые файлы

        print(f"  Загружено {len(self.rules)} правил")
        self._build_patterns()

    def _parse_rule(self, doc: Dict, file_path: Path) -> Optional[Dict]:
        """Парсит одно Sigma правило."""
        # Проверяем обязательные поля
        if 'detection' not in doc:
            return None

        rule = {
            'id': doc.get('id', ''),
            'title': doc.get('title', ''),
            'description': doc.get('description', ''),
            'level': doc.get('level', 'medium'),
            'status': doc.get('status', 'experimental'),
            'logsource': doc.get('logsource', {}),
            'detection': doc.get('detection', {}),
            'tags': doc.get('tags', []),
            'file': file_path.name,
        }

        # Извлекаем MITRE ATT&CK теги
        mitre_tags = [t for t in rule['tags'] if t.startswith('attack.')]
        rule['mitre'] = mitre_tags

        return rule

    def _build_patterns(self):
        """Строит паттерны детекции из правил."""
        for rule in self.rules:
            level = rule['level']
            detection = rule['detection']

            # Извлекаем паттерны из detection
            patterns = self._extract_patterns(detection)

            for pattern_type, pattern_values in patterns.items():
                for value in pattern_values:
                    self.patterns[level].append({
                        'type': pattern_type,
                        'value': value,
                        'rule_id': rule['id'],
                        'rule_title': rule['title'],
                        'mitre': rule['mitre'],
                    })

    def _extract_patterns(self, detection: Dict) -> Dict[str, List[str]]:
        """Извлекает паттерны из блока detection."""
        patterns = defaultdict(list)

        def extract_recursive(obj, current_field=''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in ('condition', 'timeframe'):
                        continue

                    field = key.lower()
                    extract_recursive(value, field)

            elif isinstance(obj, list):
                for item in obj:
                    extract_recursive(item, current_field)

            elif isinstance(obj, str):
                # Это паттерн
                if current_field and obj:
                    # Убираем wildcard для использования как regex
                    pattern = obj.replace('*', '.*')
                    patterns[current_field].append(pattern)

        extract_recursive(detection)
        return dict(patterns)

    def get_detection_patterns(self) -> Dict[str, List[Dict]]:
        """Возвращает все паттерны детекции по уровням."""
        return dict(self.patterns)

    def get_commandline_patterns(self) -> Dict[str, List[str]]:
        """Возвращает паттерны для командной строки."""
        result = defaultdict(list)

        for level, patterns in self.patterns.items():
            for p in patterns:
                if p['type'] in ('commandline', 'command_line', 'originalfilename', 'image'):
                    result[level].append(p['value'])

        return dict(result)

    def match_event(self, event: Dict) -> Optional[str]:
        """
        Проверяет событие на соответствие правилам.

        Returns:
            Класс (malicious_critical, etc.) или None
        """
        cmdline = str(event.get('command_line', '')).lower()
        process = str(event.get('process_name', '')).lower()
        parent = str(event.get('parent_image', '')).lower()

        combined = f"{cmdline} {process} {parent}"

        # Проверяем от высокого уровня к низкому
        for level in ['critical', 'high', 'medium', 'low']:
            for pattern_info in self.patterns.get(level, []):
                pattern = pattern_info['value'].lower()
                try:
                    if re.search(pattern, combined, re.IGNORECASE):
                        return SIGMA_LEVEL_TO_CLASS[level]
                except re.error:
                    # Невалидный regex
                    if pattern in combined:
                        return SIGMA_LEVEL_TO_CLASS[level]

        return None

    def generate_synthetic_events(self, count_per_level: int = 100) -> List[Dict]:
        """
        Генерирует синтетические события на основе Sigma паттернов.

        Args:
            count_per_level: Количество событий на уровень

        Returns:
            Список событий
        """
        import random

        events = []
        cmdline_patterns = self.get_commandline_patterns()

        for level, patterns in cmdline_patterns.items():
            if not patterns:
                continue

            for i in range(min(count_per_level, len(patterns) * 3)):
                pattern = random.choice(patterns)

                # Преобразуем паттерн в примерную командную строку
                cmdline = pattern.replace('.*', 'test').replace('\\', '')

                event = {
                    'event_id': 4688,
                    'hostname': f"WS-{random.choice(['USER', 'ADMIN', 'SRV'])}{random.randint(1,10):02d}",
                    'timestamp': f"2024-01-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z",
                    'process_name': self._guess_process(pattern),
                    'command_line': cmdline,
                    'user': random.choice(['john', 'admin', 'SYSTEM', 'user1']),
                    'source_file': 'sigma_synthetic',
                    'sigma_level': level,
                }
                events.append(event)

        return events

    def _guess_process(self, pattern: str) -> str:
        """Угадывает имя процесса по паттерну."""
        pattern_lower = pattern.lower()

        if 'powershell' in pattern_lower:
            return 'powershell.exe'
        elif 'cmd' in pattern_lower:
            return 'cmd.exe'
        elif 'wmic' in pattern_lower:
            return 'wmic.exe'
        elif 'certutil' in pattern_lower:
            return 'certutil.exe'
        elif 'bitsadmin' in pattern_lower:
            return 'bitsadmin.exe'
        elif 'mshta' in pattern_lower:
            return 'mshta.exe'
        elif 'regsvr32' in pattern_lower:
            return 'regsvr32.exe'
        elif 'rundll32' in pattern_lower:
            return 'rundll32.exe'
        elif 'schtasks' in pattern_lower:
            return 'schtasks.exe'
        elif 'net' in pattern_lower:
            return 'net.exe'
        else:
            return 'unknown.exe'

    def get_stats(self) -> Dict:
        """Возвращает статистику по правилам."""
        stats = {
            'total_rules': len(self.rules),
            'by_level': defaultdict(int),
            'by_status': defaultdict(int),
            'total_patterns': sum(len(p) for p in self.patterns.values()),
        }

        for rule in self.rules:
            stats['by_level'][rule['level']] += 1
            stats['by_status'][rule['status']] += 1

        return {
            'total_rules': stats['total_rules'],
            'total_patterns': stats['total_patterns'],
            'by_level': dict(stats['by_level']),
            'by_status': dict(stats['by_status']),
        }


def parse_sigma(sigma_path: str) -> SigmaRulesParser:
    """Создаёт и возвращает парсер Sigma."""
    return SigmaRulesParser(sigma_path)


if __name__ == "__main__":
    # Тест
    parser = SigmaRulesParser("datasets/sigma")
    print(f"\nСтатистика: {parser.get_stats()}")

    # Тест матчинга
    test_event = {
        'command_line': 'powershell.exe -enc SGVsbG8gV29ybGQ=',
        'process_name': 'powershell.exe',
    }
    result = parser.match_event(test_event)
    print(f"\nТест матчинга: {result}")
