"""
Скрипт для скачивания датасетов для обучения нейросети.

Использование:
    python scripts/download_datasets.py --all
    python scripts/download_datasets.py --mordor
    python scripts/download_datasets.py --sigma
"""

import os
import sys
import subprocess
import argparse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATASETS_DIR = ROOT / "datasets"
DATASETS_DIR.mkdir(exist_ok=True)


def run_git_clone(url: str, target: Path, name: str):
    """Клонирует git репозиторий."""
    if target.exists():
        print(f"  [SKIP] {name} уже существует: {target}")
        return True

    print(f"  [CLONE] {name}...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(target)],
            check=True,
            capture_output=True
        )
        print(f"  [OK] {name} скачан")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [ERROR] Ошибка клонирования {name}: {e}")
        return False
    except FileNotFoundError:
        print(f"  [ERROR] Git не установлен!")
        return False


def download_file(url: str, target: Path, name: str):
    """Скачивает файл."""
    if target.exists():
        print(f"  [SKIP] {name} уже существует")
        return True

    print(f"  [DOWNLOAD] {name}...")
    try:
        urllib.request.urlretrieve(url, target)
        print(f"  [OK] {name} скачан")
        return True
    except Exception as e:
        print(f"  [ERROR] Ошибка скачивания {name}: {e}")
        return False


def download_mordor():
    """Скачивает Mordor Security Datasets."""
    print("\n[1] MORDOR SECURITY DATASETS")
    print("    Описание: Записи атак по MITRE ATT&CK")
    print("    Размер: ~2-5 GB")

    return run_git_clone(
        "https://github.com/OTRF/Security-Datasets.git",
        DATASETS_DIR / "mordor",
        "Mordor"
    )


def download_atomic_red_team():
    """Скачивает Atomic Red Team."""
    print("\n[2] ATOMIC RED TEAM")
    print("    Описание: Тесты атак по MITRE ATT&CK")
    print("    Размер: ~500 MB")

    return run_git_clone(
        "https://github.com/redcanaryco/atomic-red-team.git",
        DATASETS_DIR / "atomic-red-team",
        "Atomic Red Team"
    )


def download_sigma():
    """Скачивает Sigma Rules."""
    print("\n[3] SIGMA RULES")
    print("    Описание: 3000+ правил детекции")
    print("    Размер: ~100 MB")

    return run_git_clone(
        "https://github.com/SigmaHQ/sigma.git",
        DATASETS_DIR / "sigma",
        "Sigma Rules"
    )


def download_mitre_attack():
    """Скачивает MITRE ATT&CK data."""
    print("\n[4] MITRE ATT&CK DATA")
    print("    Описание: Enterprise ATT&CK в формате STIX")
    print("    Размер: ~50 MB")

    mitre_dir = DATASETS_DIR / "mitre-attack"
    mitre_dir.mkdir(exist_ok=True)

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    target = mitre_dir / "enterprise-attack.json"

    return download_file(url, target, "MITRE ATT&CK")


def download_apt_simulator():
    """Скачивает APT Simulator."""
    print("\n[5] APT SIMULATOR")
    print("    Описание: Симуляция APT атак")
    print("    Размер: ~50 MB")

    return run_git_clone(
        "https://github.com/NextronSystems/APTSimulator.git",
        DATASETS_DIR / "apt-simulator",
        "APT Simulator"
    )


def download_evtx_attack_samples():
    """Скачивает EVTX Attack Samples."""
    print("\n[6] EVTX ATTACK SAMPLES")
    print("    Описание: Реальные EVTX файлы атак")
    print("    Размер: ~500 MB")

    target = DATASETS_DIR / "EVTX-ATTACK-SAMPLES"
    if target.exists():
        print(f"  [SKIP] Уже существует: {target}")
        return True

    return run_git_clone(
        "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git",
        target,
        "EVTX Attack Samples"
    )


def print_summary():
    """Выводит информацию о скачанных датасетах."""
    print("\n" + "=" * 70)
    print("СКАЧАННЫЕ ДАТАСЕТЫ")
    print("=" * 70)

    datasets = [
        ("EVTX-ATTACK-SAMPLES", "Windows Event Logs атак"),
        ("mordor", "Security Datasets (MITRE)"),
        ("atomic-red-team", "Atomic Red Team тесты"),
        ("sigma", "Sigma Detection Rules"),
        ("mitre-attack", "MITRE ATT&CK data"),
        ("apt-simulator", "APT Simulator"),
    ]

    for name, desc in datasets:
        path = DATASETS_DIR / name
        if path.exists():
            size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
            size_mb = size / (1024 * 1024)
            print(f"  [OK] {name}: {desc} ({size_mb:.1f} MB)")
        else:
            print(f"  [--] {name}: не скачан")


def print_manual_downloads():
    """Выводит инструкции для ручного скачивания."""
    print("\n" + "=" * 70)
    print("ДАТАСЕТЫ ДЛЯ РУЧНОГО СКАЧИВАНИЯ")
    print("=" * 70)
    print("""
Следующие датасеты требуют ручного скачивания:

1. CICIDS2017 (50+ GB)
   URL: https://www.unb.ca/cic/datasets/ids-2017.html
   Описание: Labeled network traffic

2. CICIDS2018 (80+ GB)
   URL: https://www.unb.ca/cic/datasets/ids-2018.html
   Описание: Improved IDS dataset

3. UNSW-NB15 (2 GB)
   URL: https://research.unsw.edu.au/projects/unsw-nb15-dataset
   Описание: Modern network intrusion dataset

4. MalwareBazaar (varies)
   URL: https://bazaar.abuse.ch/export/
   Описание: Malware samples metadata

5. VirusShare (requires registration)
   URL: https://virusshare.com/
   Описание: Malware samples
""")


def main():
    parser = argparse.ArgumentParser(description="Скачивание датасетов")
    parser.add_argument("--all", action="store_true", help="Скачать все датасеты")
    parser.add_argument("--mordor", action="store_true", help="Скачать Mordor")
    parser.add_argument("--atomic", action="store_true", help="Скачать Atomic Red Team")
    parser.add_argument("--sigma", action="store_true", help="Скачать Sigma Rules")
    parser.add_argument("--mitre", action="store_true", help="Скачать MITRE ATT&CK")
    parser.add_argument("--apt", action="store_true", help="Скачать APT Simulator")
    parser.add_argument("--evtx", action="store_true", help="Скачать EVTX samples")
    args = parser.parse_args()

    print("=" * 70)
    print("СКАЧИВАНИЕ ДАТАСЕТОВ ДЛЯ ОБУЧЕНИЯ НЕЙРОСЕТИ")
    print("=" * 70)
    print(f"Директория: {DATASETS_DIR}")

    # Если ничего не выбрано - показать help
    if not any([args.all, args.mordor, args.atomic, args.sigma, args.mitre, args.apt, args.evtx]):
        print("\nИспользование:")
        print("  python scripts/download_datasets.py --all     # Скачать всё")
        print("  python scripts/download_datasets.py --mordor  # Только Mordor")
        print("  python scripts/download_datasets.py --sigma   # Только Sigma")
        print_summary()
        print_manual_downloads()
        return

    # Скачиваем выбранные датасеты
    if args.all or args.evtx:
        download_evtx_attack_samples()

    if args.all or args.mordor:
        download_mordor()

    if args.all or args.atomic:
        download_atomic_red_team()

    if args.all or args.sigma:
        download_sigma()

    if args.all or args.mitre:
        download_mitre_attack()

    if args.all or args.apt:
        download_apt_simulator()

    print_summary()

    if args.all:
        print_manual_downloads()

    print("\n" + "=" * 70)
    print("ГОТОВО!")
    print("=" * 70)
    print("\nСледующий шаг: python training/prepare_data.py")


if __name__ == "__main__":
    main()
