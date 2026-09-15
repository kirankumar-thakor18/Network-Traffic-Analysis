@echo off
title Network Traffic Analyzer - Web Dashboard
color 0B

cd /d "%~dp0"

echo ============================================
echo  Starting Network Traffic Analyzer Web App
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found on PATH.
    echo         Install Python 3.8+ and tick "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

echo [1/2] Installing dependencies if needed...
pip install -q -r requirements.txt

echo [2/2] Starting web server...
echo.
echo   URL: http://127.0.0.1:5000
echo.
echo   Keep this window open while using the dashboard.
echo   Press CTRL+C to stop the server.
echo.
start "" "http://127.0.0.1:5000"
echo.

python app.py