#!/usr/bin/env python3
"""
Build the IR-Agent installer EXE using PyInstaller.

Run from the project root:
    python installer/build_installer.py

Output: dist/ir_agent_setup.exe
"""

import subprocess
import sys
import os
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "installer" / "ir_agent_setup.py"
DIST = ROOT / "dist"
ICON = ROOT / "installer" / "icon.ico"  # optional


def main():
    print("[*] Building IR-Agent Installer EXE...")
    print(f"    Source: {SCRIPT}")
    print(f"    Output: {DIST / 'ir_agent_setup.exe'}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",               # single EXE
        "--console",               # console app (shows output)
        "--clean",                 # clean build cache
        "--name", "ir_agent_setup",
        "--distpath", str(DIST),
        "--workpath", str(ROOT / "build" / "installer"),
        "--specpath", str(ROOT / "build"),
    ]

    # Add icon if available
    if ICON.exists():
        cmd.extend(["--icon", str(ICON)])

    cmd.append(str(SCRIPT))

    print(f"\n[*] Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=ROOT)

    if result.returncode == 0:
        exe_path = DIST / "ir_agent_setup.exe"
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"\n[+] SUCCESS: {exe_path}")
            print(f"    Size: {size_mb:.1f} MB")
            print(f"\n    Usage:")
            print(f"      ir_agent_setup.exe              # install + launch")
            print(f"      ir_agent_setup.exe --install     # install only")
            print(f"      ir_agent_setup.exe --run         # launch only")
            print(f"      ir_agent_setup.exe --update      # git pull + pip update")
        else:
            print(f"\n[!] Build reported success but EXE not found at {exe_path}")
    else:
        print(f"\n[x] Build FAILED with exit code {result.returncode}")
        sys.exit(1)


if __name__ == '__main__':
    main()
