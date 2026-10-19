#!/usr/bin/env bash
# Run the full automated suite, then the end-to-end smoke check against a throwaway server.
set -euo pipefail
cd "$(dirname "$0")"
# Modules run in parallel processes (~8x faster); SERIAL=1 for the old one-process verbose run.
if [ -n "${SERIAL:-}" ]; then
  python3 -m unittest discover -s tests -t . -v
else
  python3 scripts/run_tests_parallel.py
fi
python3 scripts/smoke.py
