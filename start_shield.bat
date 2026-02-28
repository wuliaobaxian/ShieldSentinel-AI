@echo off
chcp 65001 >nul
cls
echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║         ShieldSentinel AI  —  Enterprise Security        ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.
echo    Starting development server on port 3001...
echo.
echo    Access points:
echo.
echo    [ADMIN]  http://localhost:3001/admin   ← Security Dashboard
echo    [CHAT]   http://localhost:3001/chat    ← AI Gateway Terminal
echo    [HOME]   http://localhost:3001         ← Landing Page
echo.
echo  ──────────────────────────────────────────────────────────
echo.
cd /d "%~dp0"
npm run dev
