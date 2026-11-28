#!/usr/bin/env bash
# One-command launcher. Binds to 127.0.0.1:8080 unless SIEM_HOST / SIEM_PORT are set.
set -euo pipefail
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "Watchpost needs Python 3.10 or newer. Install Python 3 from python.org and retry." >&2; exit 1; }
python3 - <<'PYTHON'
import sqlite3
import sys

if sys.version_info < (3, 10) or sqlite3.sqlite_version_info < (3, 35):
    sys.exit("Watchpost needs Python 3.10+ with SQLite 3.35+. Install a current Python 3 from python.org and retry.")
PYTHON
if [[ "${1:-}" == "--demo" ]]; then
  shift
  exec python3 -m watchpost.demo "$@"
fi
exec python3 main.py
