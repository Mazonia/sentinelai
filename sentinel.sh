#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
if [ -f "$DIR/.venv/bin/python" ]; then
    "$DIR/.venv/bin/python" -m sentinelai.cli.main "$@"
elif [ -f "$DIR/.venv/Scripts/python.exe" ]; then
    "$DIR/.venv/Scripts/python.exe" -m sentinelai.cli.main "$@"
else
    python3 -m sentinelai.cli.main "$@"
fi
