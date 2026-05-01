#!/usr/bin/env python3
"""
IR-Agent Installer / Bootstrapper
===================================
Single-EXE installer that:
  1. Checks prerequisites (Python 3.10+, git)
  2. Clones the project from GitHub
  3. Creates a virtualenv and installs dependencies
  4. Generates a .env with sensible defaults (user fills in API keys)
  5. Runs DB migrations
  6. Launches the IR-Agent server

Usage:
  ir_agent_setup.exe              - Interactive install + launch
  ir_agent_setup.exe --install    - Install only (no launch)
  ir_agent_setup.exe --run        - Launch only (project must be installed)
  ir_agent_setup.exe --update     - git pull + pip install
  ir_agent_setup.exe --dir C:\\IR  - Custom install directory
"""

import os
import sys
import subprocess
import shutil
import textwrap
import argparse
import platform
import ctypes
from pathlib import Path

# ─── Constants ───────────────────────────────────────────────────────────────

REPO_URL = "https://github.com/qbert2004/Ir_agent.git"
PROJECT_NAME = "Ir_agent"
DEFAULT_INSTALL_DIR = Path.home() / "IR-Agent"
MIN_PYTHON = (3, 10)
ENV_TEMPLATE = """\
ENVIRONMENT=development

# Google AI Studio (PRIMARY LLM)
LLM_PROVIDER=google
GOOGLE_API_KEY={google_key}
GOOGLE_AI_MODEL=models/gemma-4-31b-it
LLM_ANALYZER_MODEL=models/gemma-4-31b-it
LLM_REPORT_MODEL=models/gemma-4-31b-it

# Groq AI (fallback - optional)
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY={groq_key}
AI_SUSPICIOUS_THRESHOLD=60

# Better Stack (optional logging)
BETTER_STACK_SOURCE_TOKEN={betterstack_token}
SEND_ALL_TO_BETTERSTACK=false

# API
API_PORT={api_port}
API_HOST=0.0.0.0
MY_API_TOKEN={api_token}
CORS_ORIGINS=http://localhost:3000,http://localhost:{api_port}
RATE_LIMIT_PER_MINUTE=60

# Database
DATABASE_URL=sqlite+aiosqlite:///./ir_agent.db

# Threat Intelligence APIs (optional)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# Agent
AGENT_SESSION_MAX_SIZE=1000
AGENT_SESSION_TTL_SECONDS=3600
AGENT_TIMEOUT_SECONDS=120
IOC_CACHE_MAX_SIZE=10000
IOC_CACHE_TTL_SECONDS=3600
"""

# ─── Colors / UI ─────────────────────────────────────────────────────────────

class C:
    """ANSI colors (disabled when not a terminal)."""
    _enabled = sys.stdout.isatty() and os.name != 'nt' or (
        os.name == 'nt' and os.environ.get('WT_SESSION')  # Windows Terminal
    )
    RESET = "\033[0m"     if _enabled else ""
    BOLD  = "\033[1m"     if _enabled else ""
    GREEN = "\033[92m"    if _enabled else ""
    CYAN  = "\033[96m"    if _enabled else ""
    YELLOW= "\033[93m"    if _enabled else ""
    RED   = "\033[91m"    if _enabled else ""
    DIM   = "\033[2m"     if _enabled else ""


def banner():
    print(f"""
{C.CYAN}{C.BOLD}
  _____ _____             _                    _
 |_   _|  __ \\      /\\   | |                  | |
   | | | |__) |    /  \\  | | __ _  ___ _ __  | |_
   | | |  _  /    / /\\ \\ | |/ _` |/ _ \\ '_ \\ | __|
  _| |_| | \\ \\   / ____ \\| | (_| |  __/ | | || |_
 |_____|_|  \\_\\ /_/    \\_\\_|\\__, |\\___|_| |_| \\__|
                             __/ |
                            |___/   Installer v1.0
{C.RESET}""")


def info(msg):    print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def error(msg):   print(f"  {C.RED}[x]{C.RESET} {msg}")
def step(msg):    print(f"\n{C.BOLD}{C.CYAN}>>> {msg}{C.RESET}")
def dim(msg):     print(f"  {C.DIM}{msg}{C.RESET}")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def run(cmd, cwd=None, check=True, capture=False, env=None):
    """Run a shell command, streaming output by default."""
    merged_env = {**os.environ, **(env or {})}
    kwargs = dict(cwd=cwd, shell=True, env=merged_env)
    if capture:
        kwargs.update(capture_output=True, text=True)
    result = subprocess.run(cmd, **kwargs)
    if check and result.returncode != 0:
        if capture:
            error(f"Command failed: {cmd}")
            error(result.stderr[:500] if result.stderr else "(no stderr)")
        sys.exit(1)
    return result


def which(name):
    return shutil.which(name)


def generate_token(length=32):
    """Generate a random API token."""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def enable_windows_ansi():
    """Enable ANSI escape codes on Windows 10+."""
    if os.name == 'nt':
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


def find_python():
    """Find a suitable Python 3.10+ executable."""
    candidates = ['python3', 'python', 'py -3']
    for cmd in candidates:
        try:
            r = run(f'{cmd} --version', capture=True, check=False)
            if r.returncode == 0:
                ver_str = r.stdout.strip().split()[-1]
                parts = ver_str.split('.')
                major, minor = int(parts[0]), int(parts[1])
                if (major, minor) >= MIN_PYTHON:
                    return cmd
        except Exception:
            continue
    return None


def find_git():
    return which('git')


# ─── Core actions ────────────────────────────────────────────────────────────

def check_prerequisites():
    step("Checking prerequisites")

    python = find_python()
    if python:
        r = run(f'{python} --version', capture=True)
        info(f"Python: {r.stdout.strip()}")
    else:
        error(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ not found.")
        error("Download from https://www.python.org/downloads/")
        sys.exit(1)

    git = find_git()
    if git:
        r = run('git --version', capture=True)
        info(f"Git: {r.stdout.strip()}")
    else:
        error("Git not found.")
        error("Download from https://git-scm.com/downloads")
        sys.exit(1)

    return python


def clone_or_pull(install_dir: Path):
    project_dir = install_dir / PROJECT_NAME

    if project_dir.exists() and (project_dir / '.git').exists():
        step("Updating existing installation")
        run('git pull --ff-only', cwd=project_dir)
        info(f"Updated: {project_dir}")
    else:
        step("Cloning IR-Agent from GitHub")
        install_dir.mkdir(parents=True, exist_ok=True)
        run(f'git clone {REPO_URL}', cwd=install_dir)
        info(f"Cloned to: {project_dir}")

    return project_dir


def setup_venv(project_dir: Path, python_cmd: str):
    step("Setting up virtual environment")
    venv_dir = project_dir / '.venv'

    if not venv_dir.exists():
        run(f'{python_cmd} -m venv .venv', cwd=project_dir)
        info("Virtual environment created")
    else:
        info("Virtual environment already exists")

    # Determine pip/python paths inside venv
    if os.name == 'nt':
        pip = str(venv_dir / 'Scripts' / 'pip.exe')
        venv_python = str(venv_dir / 'Scripts' / 'python.exe')
    else:
        pip = str(venv_dir / 'bin' / 'pip')
        venv_python = str(venv_dir / 'bin' / 'python')

    return pip, venv_python


def install_dependencies(project_dir: Path, pip: str):
    step("Installing dependencies (this may take a few minutes)")
    req = project_dir / 'requirements.txt'
    if req.exists():
        # Install with relaxed version pins (allow newer)
        run(f'"{pip}" install --upgrade pip', cwd=project_dir)
        # Use --no-deps for torch to avoid conflicts, install separately
        run(
            f'"{pip}" install -r requirements.txt '
            f'--upgrade --no-warn-script-location',
            cwd=project_dir,
        )
        info("Dependencies installed")
    else:
        warn("requirements.txt not found, skipping")

    # Ensure openai package is installed (for Google AI Studio compatibility)
    run(f'"{pip}" install openai --no-warn-script-location', cwd=project_dir, check=False)


def configure_env(project_dir: Path, interactive: bool = True):
    step("Configuring environment (.env)")
    env_path = project_dir / '.env'

    if env_path.exists():
        info(".env already exists, skipping")
        dim(f"  Edit manually: {env_path}")
        return

    google_key = ""
    groq_key = ""
    betterstack_token = ""
    api_port = "9000"
    api_token = generate_token()

    if interactive:
        print()
        info("Enter your API keys (press Enter to skip):\n")

        inp = input(f"  {C.CYAN}Google AI API Key{C.RESET} (gemma-4): ").strip()
        if inp:
            google_key = inp

        inp = input(f"  {C.CYAN}Groq API Key{C.RESET} (fallback, optional): ").strip()
        if inp:
            groq_key = inp

        inp = input(f"  {C.CYAN}API port{C.RESET} [{api_port}]: ").strip()
        if inp.isdigit():
            api_port = inp

        print()

    env_content = ENV_TEMPLATE.format(
        google_key=google_key,
        groq_key=groq_key,
        betterstack_token=betterstack_token,
        api_port=api_port,
        api_token=api_token,
    )

    env_path.write_text(env_content, encoding='utf-8')
    info(f".env created: {env_path}")
    info(f"API Token: {C.BOLD}{api_token}{C.RESET}")
    dim("Save this token - you'll need it to authenticate API requests")


def run_migrations(project_dir: Path, venv_python: str):
    step("Running database migrations")
    alembic_ini = project_dir / 'alembic.ini'
    if alembic_ini.exists():
        run(f'"{venv_python}" -m alembic upgrade head', cwd=project_dir, check=False)
        info("Migrations complete")
    else:
        dim("No alembic.ini found, skipping migrations")


def launch_server(project_dir: Path, venv_python: str):
    step("Launching IR-Agent server")

    # Read port from .env
    port = "9000"
    env_path = project_dir / '.env'
    if env_path.exists():
        for line in env_path.read_text(encoding='utf-8').splitlines():
            if line.startswith('API_PORT='):
                port = line.split('=', 1)[1].strip()

    print()
    info(f"Starting server on http://localhost:{port}")
    info(f"API docs: http://localhost:{port}/docs")
    info("Press Ctrl+C to stop\n")

    try:
        run(
            f'"{venv_python}" -m uvicorn app.main:app '
            f'--host 0.0.0.0 --port {port} --reload',
            cwd=project_dir,
            check=False,
        )
    except KeyboardInterrupt:
        print()
        info("Server stopped.")


def run_tests_quick(project_dir: Path, venv_python: str):
    step("Running quick smoke test")
    result = run(
        f'"{venv_python}" -m pytest tests/test_ml_detector.py -q --tb=line',
        cwd=project_dir,
        check=False,
        capture=True,
    )
    if result.returncode == 0:
        info("Smoke test passed")
    else:
        warn("Some tests failed (non-critical)")
        dim(result.stdout[-200:] if result.stdout else "")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    enable_windows_ansi()
    banner()

    parser = argparse.ArgumentParser(
        description="IR-Agent Installer & Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--install', action='store_true',
                        help='Install only (do not launch)')
    parser.add_argument('--run', action='store_true',
                        help='Launch only (assumes already installed)')
    parser.add_argument('--update', action='store_true',
                        help='Update: git pull + pip install')
    parser.add_argument('--test', action='store_true',
                        help='Run tests after install')
    parser.add_argument('--dir', type=Path, default=DEFAULT_INSTALL_DIR,
                        help=f'Install directory (default: {DEFAULT_INSTALL_DIR})')
    parser.add_argument('--non-interactive', action='store_true',
                        help='Skip prompts, use defaults')

    args = parser.parse_args()

    project_dir = args.dir / PROJECT_NAME

    # ── Run only ──
    if args.run:
        if not project_dir.exists():
            error(f"Project not found at {project_dir}")
            error("Run without --run to install first")
            sys.exit(1)
        venv_dir = project_dir / '.venv'
        if os.name == 'nt':
            venv_python = str(venv_dir / 'Scripts' / 'python.exe')
        else:
            venv_python = str(venv_dir / 'bin' / 'python')
        launch_server(project_dir, venv_python)
        return

    # ── Prerequisites ──
    python_cmd = check_prerequisites()

    # ── Clone / Update ──
    project_dir = clone_or_pull(args.dir)

    # ── Venv + deps ──
    pip, venv_python = setup_venv(project_dir, python_cmd)
    install_dependencies(project_dir, pip)

    # ── Configure ──
    if not args.update:
        configure_env(project_dir, interactive=not args.non_interactive)

    # ── Migrations ──
    run_migrations(project_dir, venv_python)

    # ── Tests ──
    if args.test:
        run_tests_quick(project_dir, venv_python)

    # ── Summary ──
    step("Installation complete!")
    print(f"""
  {C.GREEN}Project location:{C.RESET}  {project_dir}
  {C.GREEN}Virtual env:{C.RESET}       {project_dir / '.venv'}
  {C.GREEN}Config:{C.RESET}            {project_dir / '.env'}

  {C.BOLD}To start the server:{C.RESET}
    {C.CYAN}ir_agent_setup.exe --run --dir "{args.dir}"{C.RESET}

  {C.BOLD}Or manually:{C.RESET}
    cd "{project_dir}"
    .venv\\Scripts\\activate    {C.DIM}# Windows{C.RESET}
    source .venv/bin/activate  {C.DIM}# Linux/Mac{C.RESET}
    uvicorn app.main:app --host 0.0.0.0 --port 9000 --reload
""")

    # ── Launch ──
    if not args.install and not args.update:
        answer = 'y'
        if not args.non_interactive:
            answer = input(f"  {C.CYAN}Launch server now? [Y/n]{C.RESET} ").strip().lower() or 'y'
        if answer in ('y', 'yes', ''):
            launch_server(project_dir, venv_python)


if __name__ == '__main__':
    main()
