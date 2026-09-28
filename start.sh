#!/usr/bin/env bash
# One-command launcher. Binds to 127.0.0.1:8080 unless SIEM_HOST / SIEM_PORT are set.
set -euo pipefail
cd "$(dirname "$0")"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ required")'
exec python3 main.py
