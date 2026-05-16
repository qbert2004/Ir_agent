#!/bin/bash
# IR-Agent startup script for Linux/macOS
# Usage: bash start_server.sh

set -e
cd "$(dirname "$0")"

echo "============================================================"
echo " IR-Agent startup"
echo "============================================================"

# Check venv
if [ ! -f ".venv/bin/python" ]; then
    echo "[ERROR] Virtual environment not found."
    echo "Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi

# Check .env
if [ ! -f ".env" ]; then
    echo "[WARN] .env not found, copying from .env.example"
    cp .env.example .env
fi

echo "[*] Starting IR-Agent on http://localhost:9000"
echo "[*] Swagger UI: http://localhost:9000/docs"
echo "[*] Dashboard:  http://localhost:9000/dashboard"
echo "[*] Press Ctrl+C to stop"
echo ""

.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 9000
