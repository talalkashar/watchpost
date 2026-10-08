#!/usr/bin/env python3
"""Run detection-as-code checks against a Watchpost rule export."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watchpost import detection_tests, portability  # noqa: E402


def _read(path):
    if path == "-":
        raw = sys.stdin.buffer.read(portability.MAX_IMPORT_BYTES + 1)
    else:
        try:
            with open(path, "rb") as stream:
                raw = stream.read(portability.MAX_IMPORT_BYTES + 1)
        except OSError as exc:
            raise detection_tests.ValidationError(str(exc)) from exc
    if len(raw) > portability.MAX_IMPORT_BYTES:
        raise detection_tests.ValidationError(f"export exceeds {portability.MAX_IMPORT_BYTES} bytes")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise detection_tests.ValidationError(f"invalid JSON: {exc}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", help="rule export JSON file, or - for standard input")
    parser.add_argument("--seed", type=int, default=7, help="synthetic sample seed (default: 7)")
    args = parser.parse_args(argv)
    try:
        result = detection_tests.check(_read(args.export), seed=args.seed)
    except detection_tests.ValidationError as exc:
        result = {"ok": False, "error": {"type": "validation", "message": str(exc)}}
        code = 2
    else:
        code = 0 if result["ok"] else 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
