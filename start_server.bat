@echo off
REM IR-Agent startup script for Windows
REM Usage: double-click or run from project root

cd /d "%~dp0"

echo ============================================================
echo  IR-Agent startup
echo ============================================================

REM Check venv
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found.
    echo Run: python -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

REM Check .env
if not exist ".env" (
    echo [WARN] .env not found, copying from .env.example
    copy .env.example .env
)

echo [*] Starting IR-Agent on http://localhost:9000
echo [*] Swagger UI: http://localhost:9000/docs
echo [*] Dashboard:  http://localhost:9000/dashboard
echo [*] Press Ctrl+C to stop
echo.

.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 9000
pause
