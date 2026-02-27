"""
Установка зависимостей для обучения нейросети.

Использование:
    python training/install_deps.py          # Установить всё
    python training/install_deps.py --check  # Только проверить
    python training/install_deps.py --gpu    # С поддержкой GPU (CUDA)
"""

import subprocess
import sys
import argparse


# Базовые зависимости (работают на CPU)
BASE_DEPS = [
    ("torch", "PyTorch (CPU)"),
    ("numpy", "NumPy"),
    ("scikit-learn", "Scikit-Learn"),
    ("pyyaml", "PyYAML"),
    ("tqdm", "TQDM progress bars"),
    ("python-evtx", "EVTX parser"),
    ("sentence-transformers", "Sentence Transformers"),
]

# GPU зависимости
GPU_DEPS = [
    # PyTorch с CUDA устанавливается отдельно
]

# Опциональные зависимости
OPTIONAL_DEPS = [
    ("transformers", "Hugging Face Transformers"),
    ("datasets", "Hugging Face Datasets"),
    ("accelerate", "Hugging Face Accelerate"),
    ("bitsandbytes", "8-bit optimization (Linux only)"),
    ("peft", "Parameter-Efficient Fine-Tuning"),
    ("wandb", "Weights & Biases logging"),
    ("tensorboard", "TensorBoard logging"),
]


def check_package(package: str) -> bool:
    """Проверяет установлен ли пакет."""
    try:
        __import__(package.replace("-", "_"))
        return True
    except ImportError:
        return False


def check_cuda() -> bool:
    """Проверяет доступность CUDA."""
    try:
        import torch
        return torch.cuda.is_available()
    except ImportError:
        return False


def install_package(package: str) -> bool:
    """Устанавливает пакет через pip."""
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", package, "-q"
        ])
        return True
    except subprocess.CalledProcessError:
        return False


def install_pytorch_cuda():
    """Устанавливает PyTorch с поддержкой CUDA."""
    print("\n[GPU] Установка PyTorch с CUDA...")
    print("  Это может занять несколько минут...")

    try:
        # Для Windows/Linux с CUDA 11.8
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "torch", "torchvision", "torchaudio",
            "--index-url", "https://download.pytorch.org/whl/cu118"
        ])
        return True
    except subprocess.CalledProcessError:
        print("  [ERROR] Не удалось установить PyTorch с CUDA")
        print("  Посетите https://pytorch.org для инструкций")
        return False


def main():
    parser = argparse.ArgumentParser(description="Установка зависимостей")
    parser.add_argument("--check", action="store_true", help="Только проверить")
    parser.add_argument("--gpu", action="store_true", help="Установить с GPU поддержкой")
    parser.add_argument("--all", action="store_true", help="Установить всё включая опциональное")
    args = parser.parse_args()

    print("=" * 70)
    print("УСТАНОВКА ЗАВИСИМОСТЕЙ ДЛЯ ОБУЧЕНИЯ")
    print("=" * 70)

    # Проверка Python версии
    print(f"\nPython: {sys.version}")
    if sys.version_info < (3, 8):
        print("[ERROR] Требуется Python 3.8+")
        sys.exit(1)

    # Проверяем базовые зависимости
    print("\n[1] БАЗОВЫЕ ЗАВИСИМОСТИ")
    missing_base = []
    for package, desc in BASE_DEPS:
        pkg_name = package.split("==")[0]
        installed = check_package(pkg_name)
        status = "✓" if installed else "✗"
        print(f"  {status} {desc} ({package})")
        if not installed:
            missing_base.append(package)

    # Проверяем CUDA
    print("\n[2] GPU (CUDA)")
    cuda_available = check_cuda()
    if cuda_available:
        import torch
        print(f"  ✓ CUDA доступен: {torch.cuda.get_device_name(0)}")
        print(f"    CUDA version: {torch.version.cuda}")
        print(f"    PyTorch version: {torch.__version__}")
    else:
        print("  ✗ CUDA недоступен (будет использован CPU)")

    # Проверяем опциональные
    print("\n[3] ОПЦИОНАЛЬНЫЕ ЗАВИСИМОСТИ")
    missing_optional = []
    for package, desc in OPTIONAL_DEPS:
        pkg_name = package.split("==")[0]
        installed = check_package(pkg_name)
        status = "✓" if installed else "-"
        print(f"  {status} {desc} ({package})")
        if not installed:
            missing_optional.append(package)

    if args.check:
        print("\n" + "=" * 70)
        print("ИТОГО")
        print("=" * 70)
        print(f"  Отсутствует базовых: {len(missing_base)}")
        print(f"  Отсутствует опциональных: {len(missing_optional)}")
        if missing_base:
            print("\n  Для установки запустите:")
            print("    python training/install_deps.py")
        return

    # Установка
    if missing_base:
        print("\n" + "=" * 70)
        print("УСТАНОВКА БАЗОВЫХ ЗАВИСИМОСТЕЙ")
        print("=" * 70)

        # Если нужен GPU, сначала ставим PyTorch с CUDA
        if args.gpu and "torch" in [p.split("==")[0] for p in missing_base]:
            missing_base = [p for p in missing_base if not p.startswith("torch")]
            install_pytorch_cuda()

        for package in missing_base:
            print(f"\n  Установка {package}...")
            if install_package(package):
                print(f"  ✓ {package} установлен")
            else:
                print(f"  ✗ Ошибка установки {package}")

    if args.all and missing_optional:
        print("\n" + "=" * 70)
        print("УСТАНОВКА ОПЦИОНАЛЬНЫХ ЗАВИСИМОСТЕЙ")
        print("=" * 70)

        for package in missing_optional:
            # Пропускаем bitsandbytes на Windows
            if package == "bitsandbytes" and sys.platform == "win32":
                print(f"\n  [SKIP] {package} (не поддерживается на Windows)")
                continue

            print(f"\n  Установка {package}...")
            if install_package(package):
                print(f"  ✓ {package} установлен")
            else:
                print(f"  ✗ Ошибка установки {package}")

    # Финальная проверка
    print("\n" + "=" * 70)
    print("ПРОВЕРКА ПОСЛЕ УСТАНОВКИ")
    print("=" * 70)

    all_ok = True
    for package, desc in BASE_DEPS:
        pkg_name = package.split("==")[0]
        if not check_package(pkg_name):
            print(f"  ✗ {desc} не установлен")
            all_ok = False

    if all_ok:
        print("  ✓ Все базовые зависимости установлены")

        # Проверяем CUDA снова
        if args.gpu:
            cuda_now = check_cuda()
            if cuda_now:
                import torch
                print(f"  ✓ CUDA готов: {torch.cuda.get_device_name(0)}")
            else:
                print("  ✗ CUDA не работает. Проверьте драйверы NVIDIA.")

    print("\n" + "=" * 70)
    print("ГОТОВО!")
    print("=" * 70)

    if all_ok:
        print("\nСледующие шаги:")
        print("  1. python scripts/download_datasets.py --all")
        print("  2. python training/prepare_data_full.py")
        print("  3. python training/validate_data.py")
        print("  4. python training/train.py")
    else:
        print("\nУстановите отсутствующие зависимости вручную:")
        print("  pip install <package>")


if __name__ == "__main__":
    main()
