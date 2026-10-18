@echo off
setlocal
cd /d "%~dp0"
set "DOTNET_CLI_HOME=%~dp0desktop_browser\windows\.dotnet"
set "NUGET_PACKAGES=%~dp0desktop_browser\windows\.nuget"
set "APP=%~dp0desktop_browser\release\PhishingGuardBrowser.exe"

if not exist "%APP%" (
    echo Building the Guard Browser desktop application...
    call "%~dp0build_browser.bat"
    if errorlevel 1 (
        echo.
        echo Guard Browser could not be built. Check the messages above and try again.
        pause
        exit /b 1
    )
)

if not exist "%APP%" (
    echo Guard Browser executable was not created.
    pause
    exit /b 1
)

start "" "%APP%"
endlocal
