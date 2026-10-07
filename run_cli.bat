@echo off
title SentinelAI - AI Offensive Security and Vulnerability Arsenal
chcp 65001 >nul
cls

if exist .venv\Scripts\python.exe (
    set PYTHON_CMD=.venv\Scripts\python.exe
) else (
    set PYTHON_CMD=python
)

%PYTHON_CMD% -X utf8 -m sentinelai.cli.main %*
