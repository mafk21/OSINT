@echo off
title OSINT Monster — Local Web App
cd /d "%~dp0"

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py -3 scripts\server.py --host 127.0.0.1 --port 8000 --auto-port --open
    goto :eof
)

where python3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python3 scripts\server.py --host 127.0.0.1 --port 8000 --auto-port --open
    goto :eof
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python scripts\server.py --host 127.0.0.1 --port 8000 --auto-port --open
    goto :eof
)

echo [ERROR] Python 3.9+ was not found on PATH. Install Python from https://www.python.org/downloads/
pause
