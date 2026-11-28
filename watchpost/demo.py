"""Run the detection engine against a bundled synthetic log, entirely in memory."""

import argparse
from contextlib import closing

from . import engine
from .config import RESOURCE_DIR
from .db import connect, init_schema
from .normalize import parse_payload

SAMPLES = {
    "ssh": ("auth.log", "authlog"),
    "windows": ("windows_security.jsonl", "jsonl"),
    "firewall": ("firewall.csv", "csv"),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", nargs="?", choices=SAMPLES, default="ssh")
    filename, fmt = SAMPLES[parser.parse_args(argv).sample]
    source = f"demo:{filename}"
    path = RESOURCE_DIR / "samples" / filename
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        parser.exit(1, f"Missing sample {path}. Restore the samples directory or reinstall Watchpost.\n")

    with closing(connect(":memory:")) as conn:
        init_schema(conn)
        engine.seed_rules(conn)
        events, rejected = parse_payload(text, fmt, source, year=2026)
        result = engine.ingest(conn, events, rejected, source, fmt, "demo", synthetic=True)
        run = result["detection"]
        if run["status"] != "ok" or run["correlation"]["status"] != "ok":
            parser.exit(1, f"Detection or correlation did not complete for {filename}.\n")
        print(f"samples/{filename} (synthetic)")
        print(f"{result['accepted']} accepted | {result['rejected']} rejected | alerts: {run['alerts_created']}")
        for rejection in rejected:
            print(f"Record {rejection['index']}: {rejection['reason']}")
        for row in conn.execute("SELECT severity, rule_id, explanation FROM alerts ORDER BY id"):
            print(f"\n[{row['severity']}] {row['rule_id']}")
            print(row["explanation"])


if __name__ == "__main__":
    main()
