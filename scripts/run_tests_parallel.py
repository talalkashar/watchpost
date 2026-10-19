#!/usr/bin/env python3
"""Run the unittest suite with one process per test module, several at a time.

Each module already isolates itself (temp directories, port 0, :memory: databases),
so modules can run side by side. Output ends the same way as `unittest discover`:
"Ran N tests in Xs" then "OK" or "FAILED", and a failing module's full output is printed.

Usage: python3 scripts/run_tests_parallel.py [-j JOBS]   (default: half the CPU count)
"""

import argparse
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Real sockets with short timeouts: flaky when CPU-starved by other modules (CI and locally), so run alone after.
RUN_ALONE = {"tests.test_live_ingest"}


def run_module(module):
    start = time.monotonic()
    proc = subprocess.run([sys.executable, "-m", "unittest", "-q", module], cwd=ROOT,
                          capture_output=True, text=True)
    ran = re.search(r"^Ran (\d+) tests?", proc.stderr, re.M)
    return module, proc.returncode, int(ran.group(1)) if ran else 0, time.monotonic() - start, proc.stderr + proc.stdout


def main():
    parser = argparse.ArgumentParser()
    # Half the CPUs: at full CPU count the timing-sensitive syslog/live-ingest tests flaked (2 of 7 local runs).
    parser.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 4) // 2))
    args = parser.parse_args()

    files = sorted((ROOT / "tests").glob("test_*.py"), key=lambda p: -p.stat().st_size)  # biggest first
    modules = [f"tests.{p.stem}" for p in files]
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(run_module, [m for m in modules if m not in RUN_ALONE]))
    results += [run_module(m) for m in modules if m in RUN_ALONE]

    failed = [r for r in results if r[1] != 0]
    for module, _, _, _, output in failed:
        print(f"\n===== {module} =====\n{output}", file=sys.stderr)
    for module, _, count, secs, _ in sorted(results, key=lambda r: -r[3])[:5]:
        print(f"{secs:6.1f}s  {count:4d} tests  {module}", file=sys.stderr)
    print("-" * 70, file=sys.stderr)
    print(f"Ran {sum(r[2] for r in results)} tests in {time.monotonic() - start:.3f}s", file=sys.stderr)
    if failed:
        print(f"\nFAILED (modules: {', '.join(r[0] for r in failed)})", file=sys.stderr)
        return 1
    print("\nOK", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
