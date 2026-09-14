@echo off
title Network Traffic Analyzer - Threat Detection
color 0B

cd /d "%~dp0"

echo ============================================
echo  Starting Network Traffic Analyzer
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

echo [1/3] Installing dependencies if needed...
pip install -q -r requirements.txt

echo [2/3] Running analysis...
echo.
python scripts\analyzer.py

echo.
echo [3/3] Done. Reports saved in the "reports" folder.
echo.

choice /c YN /n /m "Open the reports folder and charts now? (Y/N): "
if errorlevel 2 goto end

start "" "%~dp0reports"
start "" "%~dp0reports\protocol_chart.png"
start "" "%~dp0reports\top_ports_chart.png"

:end
echo.
pause