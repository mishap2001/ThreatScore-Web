@echo off
setlocal
rem ThreatScore (Python) launcher - finds Python, runs the local server.

set "PY="
rem Prefer a real per-user install (avoids the Microsoft Store python stub).
for %%V in (313 312 311 310) do if not defined PY if exist "%LocalAppData%\Programs\Python\Python%%V\python.exe" set "PY=%LocalAppData%\Programs\Python\Python%%V\python.exe"
if not defined PY where python >nul 2>nul && set "PY=python"

if not defined PY (
  echo Python 3.10+ was not found. Install it from https://python.org ^(tick "Add to PATH"^) and try again.
  pause
  exit /b 1
)

"%PY%" "%~dp0server.py"
echo.
echo ThreatScore server stopped.
pause
