#!/usr/bin/env bash
# Run the full automated suite, then the end-to-end smoke check against a throwaway server.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest discover -s tests -t . -v
python3 scripts/smoke.py
