@echo off
setlocal
cd /d "%~dp0"
set "DOTNET_CLI_HOME=%~dp0desktop_browser\windows\.dotnet"
set "NUGET_PACKAGES=%~dp0desktop_browser\windows\.nuget"

where dotnet >nul 2>nul
if errorlevel 1 (
    echo .NET 9 SDK was not found. Install the .NET 9 SDK, then run this file again.
    exit /b 1
)

dotnet publish "%~dp0desktop_browser\windows\PhishingGuardBrowser.csproj" --configuration Release --output "%~dp0desktop_browser\release"
if errorlevel 1 exit /b 1

echo.
echo Guard Browser is ready:
echo %~dp0desktop_browser\release\PhishingGuardBrowser.exe
endlocal
