# Live ingestion: point a Linux box at Watchpost

Watchpost can take real logs as they are written, in two ways:

| Path | Transport | Auth | Best for |
|---|---|---|---|
| **Syslog listener** (`SIEM_SYSLOG=1`) | UDP or TCP syslog, RFC 3164 and RFC 5424 | none (address allow list only) | the Watchpost host itself, or boxes on a private network or SSH tunnel |
| **File shipper** (`scripts/shipper.py`) | HTTPS `POST /api/ingest/upload` | ingest-only API token | any box, including over the internet behind HTTPS |

Events from both paths are real, so they are stored with `synthetic=0`. They go through the same parser as uploaded files: sshd and sudo lines become `auth_failure`, `auth_success`, and `privilege_use`, and detection runs on every batch.

Both paths use only the Python standard library. The instructions below were written for Debian 12 and Ubuntu 22.04/24.04.

---

## 1. Syslog listener

### Turn it on

```bash
export SIEM_SYSLOG=1              # start the listener with the web server
export SIEM_SYSLOG_PORT=5514      # UDP and TCP; ports below 1024 need root, so the default is 5514
./start.sh
```

| Variable | Default | Purpose |
|---|---|---|
| `SIEM_SYSLOG` | `0` | `1` starts the UDP and TCP listener from `main.py` |
| `SIEM_SYSLOG_BIND` | `127.0.0.1` | Bind address. Use `::1` or `::` for IPv6 |
| `SIEM_SYSLOG_PORT` | `5514` | Same port number for UDP and TCP |
| `SIEM_SYSLOG_ALLOW` | empty (any sender) | Comma-separated IPs or CIDR networks allowed to send, e.g. `10.0.0.0/24,192.0.2.7`. Other senders are counted as `denied` and dropped. An invalid entry stops the listener from starting, so it fails closed |

What the listener does with each message:

1. It reads the frame. UDP takes one message per datagram. TCP accepts newline-terminated messages and RFC 6587 octet-counted messages (`LEN SP MSG`). Frames longer than 16 KB are truncated.
2. It parses PRI and the RFC 5424 or RFC 3164 header. A missing hostname falls back to the sender's IP, and a missing timestamp falls back to the receive time.
3. It tries the existing auth.log parser first. Lines it does not recognize become `event_type=syslog`. Their severity comes from PRI: emerg, alert, and crit map to `critical`, err to `high`, warning to `medium`, notice to `low`, and info and debug to `info`.
4. Every 2 seconds, everything queued is handed to the engine as one batch. The batch source is `syslog` and the submitter is `syslog-listener`, so it shows up under **Ingest > Recent batches**.

The listener shows up as the `syslog` component on the Health page and in `GET /api/health`:

| Status | When |
|---|---|
| `ok` | listening; the details give ports, frames received, events ingested, rejected, denied, and dropped |
| `degraded` | the last batch failed to store, or frames were dropped in the last 10 minutes because the 50,000-frame queue was full |
| `failing` | the port could not be bound, `SIEM_SYSLOG_ALLOW` is invalid, or a listener thread stopped |

A listener failure is logged to the Errors list. It never stops the web server.

### rsyslog forwarding (Debian and Ubuntu)

Ubuntu ships rsyslog. **Debian 12 does not**: it logs to the journal only, and there is no `/var/log/auth.log`. Install rsyslog first:

```bash
sudo apt-get update && sudo apt-get install -y rsyslog     # Debian 12; already present on Ubuntu
```

Create `/etc/rsyslog.d/60-watchpost.conf`:

```
# Forward authentication logs to Watchpost as RFC 5424 over TCP.
# RFC 5424 timestamps carry the time zone, so Watchpost stores the correct UTC time.
# The disk-assisted queue holds messages while Watchpost is down and resends them.
auth,authpriv.*  action(
    type="omfwd"
    target="127.0.0.1" port="5514" protocol="tcp"
    TCP_Framing="octet-counted"
    template="RSYSLOG_SyslogProtocol23Format"
    queue.type="LinkedList" queue.filename="watchpost_fwd"
    queue.maxDiskSpace="100m" queue.saveOnShutdown="on"
    action.resumeRetryCount="-1"
)
```

To forward everything instead of only auth logs, replace `auth,authpriv.*` with `*.*`. Expect many more `syslog` events.

Check the file and apply it:

```bash
sudo rsyslogd -N1                       # syntax check
sudo systemctl restart rsyslog
logger -p auth.warning "watchpost test from $(hostname)"
```

Within a few seconds, **Events** with `source=syslog` shows the test message as a `syslog` event with severity `medium`. A failed SSH login (`ssh nosuchuser@localhost`) shows up as `auth_failure`.

UDP needs one line, but it loses messages whenever Watchpost is down or busy, and it has no queue:

```
auth,authpriv.*  @127.0.0.1:5514
```

You can also send a test message without rsyslog:

```bash
logger --server 127.0.0.1 --port 5514 --tcp --rfc5424 -p auth.notice "hello watchpost"
```

### Sending from another machine

Syslog has no authentication or encryption. Pick one of these:

- **SSH tunnel (recommended).** Keep Watchpost on loopback. On the log source, open a tunnel and point rsyslog at `127.0.0.1:5514` over TCP. UDP does not travel over SSH.
  ```bash
  ssh -N -L 5514:127.0.0.1:5514 you@watchpost-host      # or run autossh from a systemd unit
  ```
- **Private network with an allow list.** Set `SIEM_SYSLOG_BIND=0.0.0.0` and `SIEM_SYSLOG_ALLOW=<source IPs>` on the Watchpost host, and open the port only to those sources in the firewall:
  ```bash
  sudo ufw allow from 10.0.0.12 to any port 5514 proto tcp
  ```
  Watchpost logs a warning at startup if it listens beyond loopback without an allow list.
- **Over the internet:** use the file shipper with HTTPS instead.

### Time zones

RFC 3164 timestamps (`Sep 28 10:00:01`) have no year and no zone. Watchpost treats them as UTC in the current year, the same rule it applies to uploaded auth.log files. If the sending box runs on local time, use the `RSYSLOG_SyslogProtocol23Format` template shown above. It sends RFC 5424 timestamps with an offset.

---

## 2. File shipper

`scripts/shipper.py` is one file with no dependencies. It tails one or more files and posts complete new lines to `POST /api/ingest/upload` with an ingest token.

- **Batching:** up to 500 lines or 1 MB per request, polled every 2 seconds.
- **Position file:** after each accepted batch, the byte offset and inode of every file are written atomically. A restart resumes where it stopped.
- **Rotation:** when the file is renamed and a new one created, the shipper drains the old file and then switches. It also handles truncation in place (`copytruncate`).
- **Backoff:** network errors, 5xx responses, and 401/403 retry the same batch with exponential backoff, from 1 s up to 60 s, with jitter. Nothing is skipped.
- **Bad batches:** when the server refuses a batch as invalid (400, 413, 415, or 422), the shipper logs the reason and skips that batch, so one malformed line cannot stall the file forever. The rejection reasons are also kept on the server under **Ingest > Recent batches**.
- **Secrets:** the token comes from `$WATCHPOST_TOKEN` or `--token-file`, never from the command line, and it is never logged. The shipper refuses to send the token over plain HTTP to a non-loopback host unless you pass `--allow-insecure-http`.

### Create a token

In Watchpost, sign in as admin and open **Admin > API tokens**, or call `POST /api/tokens` with `{"name": "web01-shipper"}`. The token is shown once and can only ingest. It cannot read data.

### Install on the log source (Debian or Ubuntu)

```bash
sudo install -m 0755 scripts/shipper.py /usr/local/bin/watchpost-shipper
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --groups adm watchpost-shipper  # adm can read /var/log
sudo install -d -m 0750 -o watchpost-shipper /etc/watchpost-shipper /var/lib/watchpost-shipper
sudo sh -c 'umask 077; printf "%s\n" "wp_...paste token..." > /etc/watchpost-shipper/token'
sudo chown watchpost-shipper /etc/watchpost-shipper/token
```

Try one pass by hand:

```bash
sudo -u watchpost-shipper watchpost-shipper --url https://siem.example.internal \
    --token-file /etc/watchpost-shipper/token --state /var/lib/watchpost-shipper/positions.json \
    --file /var/log/auth.log:authlog --from-start --once
```

`/etc/systemd/system/watchpost-shipper.service`:

```ini
[Unit]
Description=Watchpost log shipper
After=network-online.target
Wants=network-online.target

[Service]
User=watchpost-shipper
ExecStart=/usr/bin/python3 /usr/local/bin/watchpost-shipper \
    --url https://siem.example.internal \
    --token-file /etc/watchpost-shipper/token \
    --state /var/lib/watchpost-shipper/positions.json \
    --file /var/log/auth.log:authlog
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/watchpost-shipper
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now watchpost-shipper
journalctl -u watchpost-shipper -f
```

### Options

| Option | Meaning |
|---|---|
| `--url` | Watchpost base URL. Use `https://` for anything that is not loopback |
| `--file PATH[:FORMAT[:SOURCE]]` | Repeatable. `FORMAT` is passed through to the server (`auto`, `authlog`, `json`, `jsonl`, `csv`, and any format the server adds later). `SOURCE` defaults to `<hostname>-<file stem>` |
| `--state` | Position file (default `./watchpost-shipper-positions.json`) |
| `--token-env` / `--token-file` | Where the token comes from (default env `WATCHPOST_TOKEN`) |
| `--from-start` | Ship the existing content of a file seen for the first time. Default: only lines written from now on |
| `--year` | Year for BSD syslog lines, which carry none |
| `--once` / `--max-retries N` | Ship what is there and exit, giving up after N retries. Useful for cron and for tests |
| `--cafile` | CA bundle, e.g. for a self-signed HTTPS certificate on the demo VM |
| `--interval`, `--batch-lines` | Poll interval (default 2 s) and lines per request (default 500) |

**nginx access logs:** `--file /var/log/nginx/access.log:<format>` works once the server has a web access log parser; workstream A adds one. Until then, the server refuses those batches with 400 ("could not detect format"), and the shipper logs and skips them.

---

## Limits

- Syslog is unauthenticated and unencrypted. There is no TLS syslog (RFC 5425). Use loopback, an SSH tunnel, or an allow list and firewall.
- UDP syslog loses messages silently when the network or Watchpost drops them. Prefer TCP with an rsyslog queue.
- If storing a syslog batch fails (for example, the disk is full), its frames are lost. They are counted as `lost_on_failure`, and the health component turns `degraded`. rsyslog does not know about the loss, because the listener has already accepted the frames.
- The shipper can lose lines in these cases:
  - A file was rotated while the shipper was stopped, and the old file had unsent lines. On restart, the new file is read from the start, but the old file's tail is not.
  - A file was rotated twice between two polls.
  - A file was truncated and grew past the old offset between two polls.
- One process and SQLite, as with the rest of Watchpost: a lab and demo setup, not a fleet collector.
