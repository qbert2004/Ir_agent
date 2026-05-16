@echo off
REM IR-Agent setup script for a new Windows machine
REM Run once after cloning/copying the project

cd /d "%~dp0"

echo ============================================================
echo  IR-Agent — New Machine Setup
echo ============================================================

REM Check Python
python --version 2>nul || (
    echo [ERROR] Python not found. Install Python 3.11+ from python.org
    pause
    exit /b 1
)

echo [1/4] Creating virtual environment...
python -m venv .venv

echo [2/4] Installing dependencies...
.venv\Scripts\pip install --upgrade pip
.venv\Scripts\pip install -r requirements.txt

echo [3/4] Setting up .env...
if not exist ".env" (
    copy .env.example .env
    echo.
    echo [!] Edit .env and fill in your API keys:
    echo     GOOGLE_API_KEY=...
    echo     MY_API_TOKEN=...   (any random string for auth)
    echo.
    notepad .env
)

echo [4/4] Initializing database...
.venv\Scripts\python.exe -c "import asyncio; from app.db.database import init_db; asyncio.run(init_db())" 2>nul || echo [WARN] DB init skipped (will init on first start)

echo.
echo ============================================================
echo  Setup complete! Run start_server.bat to start the server.
echo ============================================================
pause
