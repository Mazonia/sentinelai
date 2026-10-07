@echo off
setlocal enabledelayedexpansion
title SentinelAI - Windows Automated Installer & Environment Setup
chcp 65001 >nul
cls

echo ===============================================================================
echo  🛡️  SENTINELAI - NATIVE WINDOWS AUTOMATED INSTALLATION & SETUP
echo ===============================================================================
echo.

:: 1. Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not found in your system PATH!
    echo Please install Python 3.10 or newer from https://www.python.org/downloads/
    echo Make sure to check the box "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PYTHON_VER=%%i
echo [*] Detected Python environment: %PYTHON_VER%

:: 2. Create or verify virtual environment (.venv)
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo [*] Creating virtual environment in .venv ...
    python -m venv "%~dp0.venv"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment!
        pause
        exit /b 1
    )
    echo [+] Virtual environment created successfully.
) else (
    echo [+] Existing virtual environment detected in .venv.
)

:: 3. Upgrade pip
echo [*] Upgrading pip ...
"%~dp0.venv\Scripts\python.exe" -m pip install --upgrade pip --quiet

:: 4. Install dependencies
echo [*] Installing required security and framework packages from requirements.txt ...
"%~dp0.venv\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 (
    echo [ERROR] Failed to install requirements!
    pause
    exit /b 1
)
echo [+] All Python packages installed successfully.

:: 5. Install SentinelAI package in editable mode (registers 'sentinelai' & 'sentinel' console scripts)
echo [*] Registering SentinelAI commands into virtual environment ...
"%~dp0.venv\Scripts\python.exe" -m pip install -e "%~dp0." --quiet
if errorlevel 1 (
    echo [WARNING] Could not register editable package, fallback batch launcher will be used.
) else (
    echo [+] Console commands 'sentinelai' and 'sentinel' successfully registered!
)

:: 6. Check Windows Package Manager (winget)
winget --version >nul 2>&1
if not errorlevel 1 (
    echo [+] Windows Package Manager (winget) detected. 1-click external tool installation enabled.
) else (
    echo [i] Windows Package Manager (winget) not found. Tools can still be installed via pip.
)

echo.
echo ===============================================================================
echo  ✔ SENTINELAI SETUP COMPLETE!
echo ===============================================================================
echo.
echo  How to run SentinelAI:
echo    1. Simply double-click 'run_cli.bat' or 'sentinelai.bat'
echo    2. Or open PowerShell / Command Prompt in this folder and type:
echo         sentinelai           (Opens Interactive Numbered Console)
echo         sentinelai scan URL  (Runs Full Automated Scan)
echo         sentinelai copilot   (Launches AI Security Copilot)
echo         sentinelai tools     (Opens 26+ Curated Security Arsenal)
echo.
set /p LAUNCH="Would you like to launch SentinelAI now? (Y/n): "
if /i "%LAUNCH%"=="n" (
    echo Goodbye!
    exit /b 0
)

cls
"%~dp0.venv\Scripts\python.exe" -X utf8 -m sentinelai.cli.main
