<#
.SYNOPSIS
SentinelAI Native Windows Setup & Installation Script (PowerShell)
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host " 🛡️  SENTINELAI - NATIVE WINDOWS AUTOMATED INSTALLATION (PowerShell)" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
try {
    $pythonVer = & python --version 2>&1
    Write-Host "[*] Detected Python: $pythonVer" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed or not in PATH!" -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://www.python.org/downloads/"
    exit 1
}

$venvPath = Join-Path $PSScriptRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

# 2. Virtual Environment
if (-not (Test-Path $venvPython)) {
    Write-Host "[*] Creating virtual environment in $venvPath..." -ForegroundColor Yellow
    & python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to create virtual environment." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Virtual environment created." -ForegroundColor Green
} else {
    Write-Host "[+] Virtual environment already exists." -ForegroundColor Green
}

# 3. Upgrade pip & install requirements
Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
& $venvPython -m pip install --upgrade pip --quiet

Write-Host "[*] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
$reqFile = Join-Path $PSScriptRoot "requirements.txt"
& $venvPython -m pip install -r $reqFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to install requirements." -ForegroundColor Red
    exit 1
}
Write-Host "[+] All requirements installed successfully." -ForegroundColor Green

# 4. Register editable package
Write-Host "[*] Registering 'sentinelai' command..." -ForegroundColor Yellow
& $venvPython -m pip install -e $PSScriptRoot --quiet

# 5. Check winget
$winget = Get-Command winget -ErrorAction SilentlyContinue
if ($winget) {
    Write-Host "[+] Windows Package Manager (winget) is available!" -ForegroundColor Green
} else {
    Write-Host "[i] winget not detected. Tools can be installed via pip." -ForegroundColor Gray
}

Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host " ✔ SentinelAI Setup Finished! Run: .\sentinelai.ps1 or sentinelai" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
