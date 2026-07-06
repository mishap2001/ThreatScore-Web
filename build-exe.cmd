@echo off
setlocal
cd /d "%~dp0"
rem Build a standalone ThreatScore.exe with PyInstaller (one-time setup installs it).

set "PY="
for %%V in (313 312 311 310) do if not defined PY if exist "%LocalAppData%\Programs\Python\Python%%V\python.exe" set "PY=%LocalAppData%\Programs\Python\Python%%V\python.exe"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python 3.10+ was not found. Install it from https://python.org and try again.
  pause
  exit /b 1
)

echo Installing PyInstaller (one-time, may take a minute)...
"%PY%" -m pip install --upgrade pyinstaller
if errorlevel 1 ( echo pip install failed. & pause & exit /b 1 )

echo.
echo Building ThreatScore.exe ...
"%PY%" -m PyInstaller --onefile --name ThreatScore --add-data "ui.html;." server.py
if errorlevel 1 ( echo Build failed. & pause & exit /b 1 )

echo.
echo Done. Your standalone app is at:
echo   %~dp0dist\ThreatScore.exe
echo Double-click it to run (no Python needed). It opens http://localhost:8736 in your browser.
pause
