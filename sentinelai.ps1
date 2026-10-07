<#
.SYNOPSIS
SentinelAI Native PowerShell Launcher
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if (Test-Path $VenvPython) {
    & $VenvPython -X utf8 -m sentinelai.cli.main @Arguments
} else {
    & python -X utf8 -m sentinelai.cli.main @Arguments
}
