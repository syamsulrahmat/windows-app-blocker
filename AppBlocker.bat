@echo off
:: ── Check for admin privileges ──
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: ── Run AppBlocker ──
cd /d "%~dp0"
echo Starting AppBlocker...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0AppBlocker.ps1"

:: ── If it crashes, show the error ──
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] AppBlocker exited with error code %errorlevel%
    pause
)
