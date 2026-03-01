@echo off
chcp 65001 > nul
title ShieldSentinel AI
cd /d "%~dp0"
if errorlevel 1 (
    echo [ERROR] Cannot enter project directory: %~dp0
    pause
    exit /b 1
)
echo --------------------------------------------------
echo [ShieldSentinel AI] Starting security gateway...
echo --------------------------------------------------
echo Chat:  http://localhost:3001/chat
echo Admin: http://localhost:3001/admin
echo --------------------------------------------------
npm run dev
pause