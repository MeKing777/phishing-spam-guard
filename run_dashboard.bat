@echo off
setlocal
cd /d "%~dp0"

set "PYTHONPATH=%~dp0.runtime_packages;%~dp0.runtime_ml;%~dp0.runtime_packages_extra;%~dp0.runtime_googleauth;%~dp0"
set "HF_HOME=%~dp0.runtime_ml\hf_cache"

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found. Install Python 3.14 from python.org and try again.
    pause
    exit /b 1
)

python -c "import sys; assert sys.version_info[:2] == (3, 14); import streamlit" >nul 2>nul
if errorlevel 1 (
    echo Python 3.14 or Streamlit is not available in the project's local package folder.
    echo Installing the dashboard requirements now...
    python -m pip install --target "%~dp0.runtime_packages" -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo Dependency installation failed. Check your internet connection and try again.
        pause
        exit /b 1
    )
)

echo Starting Phishing and Spam Guard...
echo Your browser will open at http://127.0.0.1:8502
python -m streamlit run "%~dp0app.py" --server.address=127.0.0.1 --server.port=8502 --global.developmentMode=false --browser.gatherUsageStats=false

if errorlevel 1 (
    echo.
    echo The dashboard stopped with an error. Read the message above, then press any key to close.
    pause >nul
)

endlocal
