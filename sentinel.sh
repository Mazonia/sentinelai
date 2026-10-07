#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
if [ -f "$DIR/.venv/bin/python" ]; then
    exec "$DIR/.venv/bin/python" -m sentinelai.cli.main "$@"
elif [ -f "$DIR/.venv/Scripts/python.exe" ]; then
    exec "$DIR/.venv/Scripts/python.exe" -m sentinelai.cli.main "$@"
elif command -v sentinelai &> /dev/null; then
    exec sentinelai "$@"
else
    exec python3 -m sentinelai.cli.main "$@"
fi
