"""
Полный пайплайн подготовки и обучения нейросети.

Выполняет все шаги:
1. Проверка зависимостей
2. Скачивание датасетов (если нужно)
3. Подготовка данных
4. Валидация данных
5. Аугментация (опционально)
6. Обучение

Использование:
    python training/run_pipeline.py              # Полный пайплайн
    python training/run_pipeline.py --prepare-only  # Только подготовка
    python training/run_pipeline.py --train-only    # Только обучение
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent
TRAINING_DIR = ROOT / "training"
DATA_DIR = TRAINING_DIR / "data"
MODELS_DIR = TRAINING_DIR / "models"


def print_header(text: str):
    """Печатает заголовок."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def run_script(script_path: str, args: list = None, check: bool = True) -> bool:
    """Запускает Python скрипт."""
    cmd = [sys.executable, script_path]
    if args:
        cmd.extend(args)

    try:
        result = subprocess.run(cmd, check=check)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False


def check_dependencies() -> bool:
    """Проверяет зависимости."""
    print_header("ШАГ 1: ПРОВЕРКА ЗАВИСИМОСТЕЙ")

    required = ["torch", "numpy", "sklearn", "yaml", "tqdm"]
    missing = []

    for pkg in required:
        try:
            __import__(pkg.replace("-", "_"))
            print(f"  ✓ {pkg}")
        except ImportError:
            print(f"  ✗ {pkg}")
            missing.append(pkg)

    if missing:
        print(f"\n  Отсутствуют: {missing}")
        print("  Запустите: python training/install_deps.py")
        return False

    # Проверяем GPU
    try:
        import torch
        if torch.cuda.is_available():
            print(f"\n  GPU: {torch.cuda.get_device_name(0)}")
        else:
            print("\n  GPU: недоступен (будет использован CPU)")
    except:
        pass

    return True


def check_datasets() -> dict:
    """Проверяет наличие датасетов."""
    print_header("ШАГ 2: ПРОВЕРКА ДАТАСЕТОВ")

    datasets = {
        "EVTX-ATTACK-SAMPLES": ROOT / "datasets" / "EVTX-ATTACK-SAMPLES",
        "mordor": ROOT / "datasets" / "mordor",
        "sigma": ROOT / "datasets" / "sigma",
    }

    status = {}
    for name, path in datasets.items():
        exists = path.exists()
        status[name] = exists
        icon = "✓" if exists else "✗"
        print(f"  {icon} {name}: {path}")

    if not any(status.values()):
        print("\n  [WARNING] Ни один датасет не найден!")
        print("  Запустите: python scripts/download_datasets.py --all")

    return status


def prepare_data(args) -> bool:
    """Подготавливает данные."""
    print_header("ШАГ 3: ПОДГОТОВКА ДАННЫХ")

    script = TRAINING_DIR / "prepare_data_full.py"
    if not script.exists():
        script = TRAINING_DIR / "prepare_data.py"

    if not script.exists():
        print("  [ERROR] Скрипт подготовки данных не найден!")
        return False

    print(f"  Запуск: {script.name}")
    return run_script(str(script))


def validate_data() -> bool:
    """Валидирует данные."""
    print_header("ШАГ 4: ВАЛИДАЦИЯ ДАННЫХ")

    # Проверяем наличие файлов
    required = ["train_events.json", "train_labels.json", "val_events.json", "val_labels.json"]
    missing = [f for f in required if not (DATA_DIR / f).exists()]

    if missing:
        print(f"  [ERROR] Отсутствуют файлы: {missing}")
        return False

    script = TRAINING_DIR / "validate_data.py"
    if script.exists():
        return run_script(str(script))

    print("  [SKIP] Скрипт валидации не найден")
    return True


def augment_data(args) -> bool:
    """Аугментирует данные."""
    print_header("ШАГ 5: АУГМЕНТАЦИЯ ДАННЫХ")

    if not args.augment:
        print("  [SKIP] Аугментация отключена (используйте --augment)")
        return True

    script = TRAINING_DIR / "augment_data.py"
    if not script.exists():
        print("  [SKIP] Скрипт аугментации не найден")
        return True

    aug_args = ["--balance", f"--factor={args.augment_factor}"]
    print(f"  Запуск: {script.name} {' '.join(aug_args)}")
    return run_script(str(script), aug_args)


def train_model(args) -> bool:
    """Обучает модель."""
    print_header("ШАГ 6: ОБУЧЕНИЕ МОДЕЛИ")

    script = TRAINING_DIR / "train.py"
    if not script.exists():
        print("  [ERROR] Скрипт обучения не найден!")
        return False

    train_args = []
    if args.epochs:
        train_args.extend(["--epochs", str(args.epochs)])
    if args.batch_size:
        train_args.extend(["--batch-size", str(args.batch_size)])
    if args.augment:
        train_args.extend(["--train-events", "train_events_augmented.json"])

    print(f"  Запуск: {script.name} {' '.join(train_args)}")
    return run_script(str(script), train_args if train_args else None)


def main():
    parser = argparse.ArgumentParser(description="Полный пайплайн обучения")
    parser.add_argument("--prepare-only", action="store_true", help="Только подготовка данных")
    parser.add_argument("--train-only", action="store_true", help="Только обучение")
    parser.add_argument("--skip-validation", action="store_true", help="Пропустить валидацию")
    parser.add_argument("--augment", action="store_true", help="Применить аугментацию")
    parser.add_argument("--augment-factor", type=float, default=1.5, help="Фактор аугментации")
    parser.add_argument("--epochs", type=int, help="Количество эпох")
    parser.add_argument("--batch-size", type=int, help="Размер батча")
    args = parser.parse_args()

    print("=" * 70)
    print("  ПОЛНЫЙ ПАЙПЛАЙН ОБУЧЕНИЯ НЕЙРОСЕТИ")
    print("=" * 70)
    print(f"  Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Директория: {ROOT}")

    # 1. Зависимости
    if not check_dependencies():
        print("\n[ABORT] Установите зависимости и запустите снова.")
        sys.exit(1)

    # 2. Датасеты
    dataset_status = check_datasets()

    # Если только обучение - пропускаем подготовку
    if args.train_only:
        if not validate_data():
            print("\n[ABORT] Данные не готовы. Запустите без --train-only")
            sys.exit(1)
        if not train_model(args):
            print("\n[ABORT] Ошибка обучения.")
            sys.exit(1)
        print_header("ГОТОВО!")
        print("  Модель обучена и сохранена.")
        return

    # 3. Подготовка данных
    if any(dataset_status.values()):
        if not prepare_data(args):
            print("\n[ABORT] Ошибка подготовки данных.")
            sys.exit(1)
    else:
        print("\n[WARNING] Нет датасетов для подготовки!")
        print("  Скачайте датасеты: python scripts/download_datasets.py --all")

    # 4. Валидация
    if not args.skip_validation:
        if not validate_data():
            print("\n[WARNING] Валидация не пройдена, но продолжаем...")

    # Если только подготовка - останавливаемся
    if args.prepare_only:
        print_header("ПОДГОТОВКА ЗАВЕРШЕНА!")
        print("  Данные готовы для обучения.")
        print("  Следующий шаг: python training/train.py")
        return

    # 5. Аугментация
    if args.augment:
        if not augment_data(args):
            print("\n[WARNING] Ошибка аугментации, продолжаем без неё...")

    # 6. Обучение
    if not train_model(args):
        print("\n[ABORT] Ошибка обучения.")
        sys.exit(1)

    print_header("ПАЙПЛАЙН ЗАВЕРШЁН!")
    print("  Модель обучена и сохранена.")
    print(f"  Путь: {MODELS_DIR}")


if __name__ == "__main__":
    main()
