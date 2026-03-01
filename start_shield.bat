@echo off
chcp 65001 >nul
cls

echo.
echo  +----------------------------------------------------------+
echo  ^|         ShieldSentinel AI  --  Enterprise Security       ^|
echo  +----------------------------------------------------------+
echo.

:: ── Step 1: Change to project directory ───────────────────────────────────
cd /d "%~dp0"
if errorlevel 1 (
    echo  [ERROR] Failed to enter project directory.
    echo  Path: %~dp0
    pause
    exit /b 1
)

:: ── Step 2: Check npm is available ────────────────────────────────────────
where npm >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] npm not found. Please install Node.js first.
    echo  Download: https://nodejs.org/
    pause
    exit /b 1
)

:: ── Step 3: Release port 3001 if already occupied ─────────────────────────
echo  Checking port 3001...
for /f "tokens=5" %%p in ('netstat -aon 2^>nul ^| findstr ":3001 "') do (
    echo  Found existing process on port 3001 (PID %%p), releasing...
    taskkill /F /PID %%p >nul 2>&1
)

:: ── Step 4: Open browser after server is ready (4-second delay) ───────────
echo  Scheduling browser launch in 4 seconds...
start /b cmd /c "timeout /t 4 /nobreak >nul && start "" http://localhost:3001/admin"

:: ── Step 5: Print access info and start server ────────────────────────────
echo.
echo  Server starting on port 3001 — browser will open automatically.
echo.
echo  Access points:
echo.
echo    [ADMIN]  http://localhost:3001/admin   -- Security Dashboard
echo    [CHAT]   http://localhost:3001/chat    -- AI Gateway Terminal
echo    [HOME]   http://localhost:3001         -- Landing Page
echo.
echo  Press Ctrl+C to stop the server.
echo  ----------------------------------------------------------
echo.

npm run dev

:: ── Server stopped (Ctrl+C or crash) ──────────────────────────────────────
echo.
echo  Server stopped.
echo  Press any key to close this window...
pause >nul
