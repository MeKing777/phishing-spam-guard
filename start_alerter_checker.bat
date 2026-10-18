@echo off
setlocal
cd /d "%~dp0"

echo Starting Alerter's local phishing and spam checker...
echo Keep this window open while using the Alerter extension.
echo Press Ctrl+C here to stop the checker.
echo.

if exist "%~dp0.venv312\Scripts\python.exe" (
    "%~dp0.venv312\Scripts\python.exe" -m src.local_api_server
    if errorlevel 1 pause
    goto :done
)

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -m src.local_api_server
    if errorlevel 1 pause
    goto :done
)

where py >nul 2>nul
if not errorlevel 1 (
    py -3 -m src.local_api_server
    if errorlevel 1 pause
    goto :done
)

where python >nul 2>nul
if not errorlevel 1 (
    python -m src.local_api_server
    if errorlevel 1 pause
    goto :done
)

echo Python was not found. Install Python 3 and run this file again.
pause

:done
endlocal
