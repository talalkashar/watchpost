# Contributing

The runtime uses the Python standard library (3.10+ with SQLite 3.35+). CI runs on Python 3.11 through 3.14.

## Run it

```bash
git clone https://github.com/talalkashar/watchpost.git
cd watchpost
./start.sh
```

## Test

```bash
./run_tests.sh
```

This runs the full unit and integration suite plus the end-to-end smoke check. Every change should leave it green.

## Sending a change

1. Open an issue first for anything larger than a small fix.
2. Branch from `main`, keep the change focused, and add or update tests for new behavior.
3. Keep dependencies at zero. The standard library is a project constraint.
4. Open a pull request that references the issue. CI must pass before merge.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
