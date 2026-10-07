@echo off
setlocal
chcp 65001 >nul
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -X utf8 -m sentinelai.cli.main %*
) else (
    python -X utf8 -m sentinelai.cli.main %*
)
endlocal
