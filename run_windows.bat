@echo off
setlocal EnableExtensions
title SORM Telecom Infrastructure Simulation
cd /d "%~dp0"

echo ==============================================================
echo   SORM: THE TELECOM INFRASTRUCTURE - Windows launcher
echo ==============================================================
echo.

REM Step 1: locate a working Python 3 interpreter
set "PYCMD="
py -3 --version >nul 2>&1
if not errorlevel 1 set "PYCMD=py -3"
if not defined PYCMD (
    python --version >nul 2>&1
    if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD goto :nopython

REM Step 2: require Python 3.8 or newer
%PYCMD% -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
if errorlevel 1 goto :oldpython
echo [OK] Python found: %PYCMD%

REM Step 3: create the virtual environment if missing
if not exist ".venv\Scripts\activate.bat" (
    echo [INFO] Creating virtual environment in .venv ...
    %PYCMD% -m venv .venv
    if errorlevel 1 goto :venvfail
)
call ".venv\Scripts\activate.bat"
if errorlevel 1 goto :venvfail
echo [OK] Virtual environment active

REM Step 4: install dependencies (standard library only, so this is quick)
python -m pip install --upgrade pip --quiet >nul 2>&1
python -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [WARN] Dependency step reported a problem. The project uses only the
    echo        Python standard library, so it will still try to run.
) else (
    echo [OK] Dependencies ready
)

REM Step 5: launch the project
echo.
echo [INFO] Launching SORM simulation ...
echo.
python main.py %*
echo.
pause
exit /b 0

:nopython
echo [ERROR] Python was not found on this computer.
echo         Install Python 3.8 or newer from https://www.python.org/downloads/
echo         During setup, tick the box named Add python.exe to PATH.
echo         Then run this file again.
pause
exit /b 1

:oldpython
echo [ERROR] Python 3.8 or newer is required. Please upgrade Python.
pause
exit /b 1

:venvfail
echo [ERROR] Could not create or activate the virtual environment.
echo         Try deleting the .venv folder and running this file again.
pause
exit /b 1
