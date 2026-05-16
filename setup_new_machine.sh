#!/bin/bash
# IR-Agent setup script for a new Linux/macOS machine
# Run once after cloning/copying the project

set -e
cd "$(dirname "$0")"

echo "============================================================"
echo " IR-Agent -- New Machine Setup"
echo "============================================================"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python3 not found. Install Python 3.11+."
    exit 1
fi

echo "[1/4] Creating virtual environment..."
python3 -m venv .venv

echo "[2/4] Installing dependencies..."
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "[3/4] Setting up .env..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo ""
    echo "[!] Edit .env and fill in your API keys:"
    echo "    GOOGLE_API_KEY=..."
    echo "    MY_API_TOKEN=...   (any random string for auth)"
    echo ""
fi

echo "[4/4] Initializing database..."
.venv/bin/python -c "
import asyncio
try:
    from app.db.database import init_db
    asyncio.run(init_db())
    print('DB initialized.')
except Exception as e:
    print(f'[WARN] DB init skipped: {e}')
"

echo ""
echo "============================================================"
echo " Setup complete! Run: bash start_server.sh"
echo "============================================================"
