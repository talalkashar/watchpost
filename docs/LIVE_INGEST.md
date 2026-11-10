# Live ingestion: point a Linux box at Watchpost

Watchpost can take real logs as they are written, over syslog (plain or TLS) or from the file shipper:

| Path | Transport | Auth | Best for |
|---|---|---|---|
| **Syslog listener** (`SIEM_SYSLOG=1`) | UDP or TCP syslog, RFC 3164 and RFC 5424 | none (address allow list only) | the Watchpost host itself, or boxes on a private network or SSH tunnel |
| **Syslog over TLS** (add `SIEM_SYSLOG_TLS_CERT` and `SIEM_SYSLOG_TLS_KEY`) | the same syslog inside TLS 1.2+, RFC 5425 | the listener's certificate; sender certificates with `SIEM_SYSLOG_TLS_CLIENT_CA` | other machines that already run rsyslog |
| **File shipper** (`scripts/shipper.py`) | HTTPS `POST /api/ingest/upload` | ingest-only API token | any box, including over the internet behind HTTPS |

Events from all of these are real, so they are stored with `synthetic=0`. They go through the same parsers as uploaded files: sshd and sudo lines become `auth_failure`, `auth_success`, `privilege_use`, and `privilege_escalation`; UFW/iptables lines become `fw_deny` and `fw_allow`; OpenVPN logins become `vpn_login`; nginx/Apache access lines become `web_request`, `web_scan`, and `web_error`. Detection runs on every batch.

All of it uses only the Python standard library. The instructions below were written for Debian 12 and Ubuntu 22.04/24.04.

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
| `SIEM_SYSLOG_TLS_CERT` / `SIEM_SYSLOG_TLS_KEY` | unset | PEM certificate (with any intermediates) and its private key, without a passphrase. Setting both starts the TLS listener. See [Syslog over TLS](#syslog-over-tls) |
| `SIEM_SYSLOG_TLS_PORT` | `6514` | TCP port for syslog over TLS |
| `SIEM_SYSLOG_TLS_CLIENT_CA` | unset | PEM CA bundle. When set, a sender must present a certificate signed by it |
| `SIEM_SYSLOG_PLAINTEXT` | `1` without TLS, `0` with it | Whether the plaintext UDP and TCP listeners run. TLS replaces them unless this is `1` |

What the listener does with each message:

1. It reads the frame. UDP takes one message per datagram. TCP accepts newline-terminated messages and RFC 6587 octet-counted messages (`LEN SP MSG`). TLS carries the TCP framing. Frames longer than 16 KB are truncated.
2. It parses PRI and the RFC 5424 or RFC 3164 header. A missing hostname falls back to the sender's IP, and a missing timestamp falls back to the receive time.
3. It tries the auth.log parser first (sshd, sudo/su, useradd, auditd, UFW/iptables firewall, OpenVPN). A message that parser does not recognize is tried as an nginx/Apache combined access line, so `access_log syslog:server=127.0.0.1:5514 combined;` in nginx gives `web_request`/`web_scan`/`web_error` events with the host from the syslog header and the time from the access line. Lines neither parser recognizes become `event_type=syslog`. Their severity comes from PRI: emerg, alert, and crit map to `critical`, err to `high`, warning to `medium`, notice to `low`, and info and debug to `info`.
4. Every 2 seconds, everything queued is handed to the engine as one batch. The batch source is `syslog` and the submitter is `syslog-listener`, so it shows up under **Ingest > Recent batches**.

The listener shows up as the `syslog` component on the Health page and in `GET /api/health`:

| Status | When |
|---|---|
| `ok` | listening; the details give ports, frames received, events ingested, rejected, denied, dropped, and TLS handshakes refused (`tls_failed`, with the latest reason in `last_tls_failure`) |
| `degraded` | the last batch failed to store, or frames were dropped in the last 10 minutes because the 50,000-frame queue was full |
| `failing` | a port could not be bound, `SIEM_SYSLOG_ALLOW` is invalid, the TLS certificate, key or client CA could not be loaded, or a listener thread stopped |

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

Plain syslog has no authentication and no encryption. Pick one of these:

- **TLS with client certificates (recommended).** The stream is encrypted, the sender checks the listener's certificate, and the listener reads frames only from senders that hold a certificate from your CA. See [Syslog over TLS](#syslog-over-tls).
- **SSH tunnel.** Keep Watchpost on loopback. On the log source, open a tunnel and point rsyslog at `127.0.0.1:5514` over TCP. UDP does not travel over SSH.
  ```bash
  ssh -N -L 5514:127.0.0.1:5514 you@watchpost-host      # or run autossh from a systemd unit
  ```
- **Private network with an allow list.** Set `SIEM_SYSLOG_BIND=0.0.0.0` and `SIEM_SYSLOG_ALLOW=<source IPs>` on the Watchpost host, and open the port only to those sources in the firewall:
  ```bash
  sudo ufw allow from 10.0.0.12 to any port 5514 proto tcp
  ```
  Watchpost logs a warning at startup if it listens beyond loopback without an allow list.
- **Over the internet:** use the file shipper with HTTPS, or TLS with client certificates and the port open only to the senders' addresses.

### Syslog over TLS

With a certificate, the listener takes syslog over TLS ([RFC 5425](https://www.rfc-editor.org/rfc/rfc5425)) on TCP port 6514: the same messages and framing as plain TCP, inside TLS 1.2 or 1.3.

| Setting | What it adds |
|---|---|
| `SIEM_SYSLOG_TLS_CERT` and `SIEM_SYSLOG_TLS_KEY` | Encryption, and proof of the listener's identity to a sender that checks its certificate |
| `SIEM_SYSLOG_TLS_CLIENT_CA` | Sender authentication. The handshake fails unless the sender presents a certificate signed by this CA, so nothing is read from anyone else |

Two rules to know before you set it up:

- **TLS replaces plaintext.** Once a certificate is set, the plaintext UDP and TCP listeners no longer start: a host that asks for certificates should not also take unauthenticated frames on the next port. `SIEM_SYSLOG_PLAINTEXT=1` keeps them running, for example while you move senders over one at a time.
- **TLS settings fail closed.** If the certificate, key or client CA cannot be loaded (a missing file, wrong permissions, a key with a passphrase, a key that does not match), the listener does not start at all. The `syslog` health component turns `failing` and names the reason. No plaintext listener starts in its place.

#### 1. Create the certificates

Any CA works. For a lab, a private CA made with `openssl` is enough. These commands were run with OpenSSL 3.0 (Debian 12, Ubuntu 22.04 and 24.04) and 3.5:

```bash
mkdir watchpost-tls && cd watchpost-tls

# A CA used only for Watchpost syslog. Whoever holds ca.key can create senders: keep it off the servers.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=Watchpost syslog CA" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout ca.key -out ca.pem

# The listener's certificate. subjectAltName is the name senders check: the Watchpost host's DNS name.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "/CN=siem.example.internal" -keyout server.key -out server.csr
printf '%s\n' "basicConstraints=critical,CA:FALSE" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid" \
    "extendedKeyUsage=serverAuth" "subjectAltName=DNS:siem.example.internal" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 \
    -extfile server.ext -out server.pem

# One certificate per sender (here: web01).
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "/CN=web01" -keyout web01.key -out web01.csr
printf '%s\n' "basicConstraints=critical,CA:FALSE" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid" \
    "extendedKeyUsage=clientAuth" > sender.ext
openssl x509 -req -in web01.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 \
    -extfile sender.ext -out web01.pem
```

`extendedKeyUsage` keeps the two roles apart: a sender's certificate cannot pass as the listener, and the listener's cannot pass as a sender. The keys have no passphrase, because neither Watchpost nor rsyslog can ask for one. File permissions are what protect them.

#### 2. Configure Watchpost

Put `server.pem`, `server.key` and `ca.pem` where the account that runs Watchpost can read them and other accounts cannot. With the [deploy kit](../deploy/README.md) that account is `watchpost`:

```bash
sudo install -d -m 0750 -g watchpost /etc/watchpost-tls
sudo install -m 0640 -g watchpost server.pem server.key ca.pem /etc/watchpost-tls/
```

Then set these (in `/etc/watchpost.env` for the deploy kit) and restart Watchpost:

```bash
SIEM_SYSLOG=1
SIEM_SYSLOG_BIND=0.0.0.0                                 # reachable from other machines
SIEM_SYSLOG_TLS_CERT=/etc/watchpost-tls/server.pem
SIEM_SYSLOG_TLS_KEY=/etc/watchpost-tls/server.key
SIEM_SYSLOG_TLS_CLIENT_CA=/etc/watchpost-tls/ca.pem      # leave out to take any sender, encrypted only
```

Open TCP 6514 to the senders and to nobody else, for example `sudo ufw allow from 10.0.0.12 to any port 6514 proto tcp`. The Health page then shows the `syslog` component as `listening on 0.0.0.0 (tls 6514, client certificates required)`.

#### 3. Configure rsyslog on the sender

```bash
sudo apt-get install -y rsyslog-gnutls                     # rsyslog's TLS driver
sudo install -d /etc/rsyslog.d/watchpost-tls
sudo install -m 0644 ca.pem web01.pem /etc/rsyslog.d/watchpost-tls/
sudo install -m 0600 web01.key /etc/rsyslog.d/watchpost-tls/
sudo chown syslog /etc/rsyslog.d/watchpost-tls/web01.key   # Ubuntu only: rsyslog runs as `syslog` there, as root on Debian
```

Keep the files under `/etc/rsyslog.d/`. Ubuntu 24.04 confines rsyslog with AppArmor, and that directory is one it may read. rsyslog loads only `*.conf` files from it, so the certificates are not mistaken for configuration.

Create `/etc/rsyslog.d/60-watchpost.conf`:

```
# Forward authentication logs to Watchpost over TLS (RFC 5425), with a client certificate.
auth,authpriv.*  action(
    type="omfwd"
    target="siem.example.internal" port="6514" protocol="tcp"
    StreamDriver="gtls" StreamDriverMode="1"
    StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="siem.example.internal"
    StreamDriver.CAFile="/etc/rsyslog.d/watchpost-tls/ca.pem"
    StreamDriver.CertFile="/etc/rsyslog.d/watchpost-tls/web01.pem"
    StreamDriver.KeyFile="/etc/rsyslog.d/watchpost-tls/web01.key"
    TCP_Framing="octet-counted"
    template="RSYSLOG_SyslogProtocol23Format"
    queue.type="LinkedList" queue.filename="watchpost_fwd"
    queue.maxDiskSpace="100m" queue.saveOnShutdown="on"
    action.resumeRetryCount="-1"
)
```

`StreamDriverAuthMode="x509/name"` with `StreamDriverPermittedPeers` is what makes rsyslog check the listener's certificate and name before it sends anything. Leave out the `CertFile` and `KeyFile` lines when Watchpost has no client CA.

```bash
sudo rsyslogd -N1 && sudo systemctl restart rsyslog
logger -p auth.warning "watchpost TLS test from $(hostname)"
```

This configuration was run against Watchpost with rsyslog 8.2112 (Ubuntu 22.04), 8.2302 (Debian 12) and 8.2312 (Ubuntu 24.04).

#### Check it without rsyslog

```bash
printf '<86>1 %s web01 sshd 1 - - Accepted publickey for alice from 198.51.100.7 port 22 ssh2\n' "$(date -u +%FT%TZ)" |
  openssl s_client -quiet -no_ign_eof -connect siem.example.internal:6514 \
      -verify_return_error -verify_hostname siem.example.internal \
      -CAfile ca.pem -cert web01.pem -key web01.key
```

An `auth_success` event for `alice` on host `web01` shows up under **Events** with `source=syslog`. Run it again without `-cert` and `-key`: nothing arrives, and `tls_failed` in the `syslog` health details goes up by one.

#### When it does not work

| Symptom | Cause |
|---|---|
| `tls_failed` rises in the `syslog` health details | `last_tls_failure` next to it gives the sender's address and the reason, such as `peer did not return a certificate` or `certificate has expired` |
| rsyslog logs `peer name not authorized` | `StreamDriverPermittedPeers` does not match a name in the listener certificate's `subjectAltName` |
| rsyslog logs `error reading file` | rsyslog cannot read its key. On Ubuntu it runs as `syslog`: see the `chown` above |
| rsyslog logs `Connection refused` although the port is open | rsyslog uses only the first address the `target` name resolves to. If that is an IPv6 address and Watchpost is bound to `0.0.0.0`, set `target` to the IPv4 address. `StreamDriverPermittedPeers` still checks the certificate's name |

#### What TLS covers here, and what it does not

- TLS 1.2 is the minimum. Protocol versions and ciphers are the defaults of Python and OpenSSL. There is no setting for them.
- The handshake completes before any frame is read. `SIEM_SYSLOG_ALLOW` is checked before the handshake.
- Every certificate the client CA has signed is admitted. Use a CA that signs syslog senders and nothing else. There is no per-name list and no revocation check (CRL or OCSP). To cut off one sender, block its address with `SIEM_SYSLOG_ALLOW` or the firewall, or replace the CA.
- A certificate authenticates the connection, not the content. An admitted sender can still put any host name in its syslog header, and Watchpost records that name.
- Certificates are read at start. Restart Watchpost after renewing them. Nothing warns before one expires.
- UDP stays plaintext. There is no DTLS.
- A connection that ends without a TLS `close_notify` may have been cut in transit, so a last message that was still incomplete is dropped, not stored. The complete messages before it are kept.
- A connection that stays silent for 5 minutes is closed, as for plain TCP. rsyslog notices and reconnects before its next message. The listener sends no TLS session tickets and no `close_notify` of its own when it closes a silent connection: with either, rsyslog 8.2302 took the closed connection for a live one and lost the first message after every pause.

### Firewalls over syslog

Point a firewall's remote syslog at the listener and its traffic lines become `fw_deny` and `fw_allow` events with source, destination and port. Those are the events the port sweep and large data transfer rules read. Admin and VPN logins on the firewall become `auth_failure` and `auth_success`.

| Firewall | What is read | Becomes |
|---|---|---|
| Linux UFW / iptables | `[UFW BLOCK]`, `[UFW ALLOW]` and the same prefixes from iptables `LOG` rules | `fw_deny`, `fw_allow` |
| pfSense / OPNsense | `filterlog` lines, IPv4 and IPv6 (`block`, `reject`, `pass`) | `fw_deny`, `fw_allow` |
| FortiGate | `type="traffic"` lines (`action` deny, accept, close and the like), with `sentbyte` as the byte count; `type="event"` admin logins | `fw_deny`, `fw_allow`, `auth_failure`, `auth_success` |
| Cisco ASA / FTD | Denies 106001, 106006, 106007, 106015, 106023, 710003; ACL hits 106100; built connections 302013 and 302015; AAA 113004 and 113005; logins 605004 and 605005 | `fw_deny`, `fw_allow`, `auth_failure`, `auth_success` |
| Palo Alto | `TRAFFIC` logs in the default comma-separated format, with bytes sent as the byte count | `fw_deny`, `fw_allow` |

Any other line from these devices is stored as a generic `syslog` event, so nothing is dropped. FortiGate lines carry their own device name and time (`devname`, `date`, `time`, `tz`), and those are used instead of the sender's address and the receive time.

On the firewall, turn on remote syslog and give it the Watchpost address and port. Use TCP, or TLS on port 6514 where the device offers it (FortiGate "reliable" mode with encryption, Cisco ASA `logging host ... secure`, Palo Alto transport SSL). pfSense and OPNsense send UDP unless a syslog-ng package is added. A firewall is another machine, so the choices under [Sending from another machine](#sending-from-another-machine) apply.

Limits:

- The parsers follow the vendors' published log formats and are tested on synthetic lines. They have not been run against the devices themselves.
- Only the default log formats are read. A custom log format on the device will not match, and its lines stay generic `syslog` events.
- Cisco connection teardown lines (302014, 302016) are not read, so Cisco events carry no byte counts. Palo Alto `THREAT` logs are not read.
- `samples/firewall_syslog.log` has pfSense and Cisco lines to try by upload. FortiGate and Palo Alto lines have no syslog program tag, so they are read from the listener only.

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
| `--file PATH[:FORMAT[:SOURCE]]` | Repeatable. `FORMAT` is passed through to the server (`auto`, `authlog`, `weblog`, `json`, `jsonl`, `csv`, and any format the server adds later). `SOURCE` defaults to `<hostname>-<file stem>` |
| `--state` | Position file (default `./watchpost-shipper-positions.json`) |
| `--token-env` / `--token-file` | Where the token comes from (default env `WATCHPOST_TOKEN`) |
| `--from-start` | Ship the existing content of a file seen for the first time. Default: only lines written from now on |
| `--year` | Year for BSD syslog lines, which carry none |
| `--once` / `--max-retries N` | Ship what is there and exit, giving up after N retries. Useful for cron and for tests |
| `--cafile` | CA bundle, e.g. for a self-signed HTTPS certificate on the demo VM |
| `--interval`, `--batch-lines` | Poll interval (default 2 s) and lines per request (default 500) |

**nginx access logs:** `--file /var/log/nginx/access.log:weblog` ships nginx/Apache combined access lines as `web_request`, `web_scan`, and `web_error` events (`auto` detects the format too). The combined format has no host field, so give the file a `SOURCE` that names the box, e.g. `--file /var/log/nginx/access.log:weblog:web01-nginx`. **Firewall logs:** UFW and iptables write to syslog (`/var/log/ufw.log` or `kern.log`), so ship them as `authlog`; firewall CSV exports go as `csv`.

---

## Limits

- Plain UDP and TCP syslog are unauthenticated and unencrypted. Use loopback, an SSH tunnel, an allow list and firewall, or TLS. The limits of the TLS listener are listed under [What TLS covers here, and what it does not](#what-tls-covers-here-and-what-it-does-not).
- Every TCP or TLS connection gets its own thread, and there is no connection limit. Keep the ports reachable only by your senders.
- UDP syslog loses messages silently when the network or Watchpost drops them. Prefer TCP with an rsyslog queue.
- If storing a syslog batch fails (for example, the disk is full), its frames are lost. They are counted as `lost_on_failure`, and the health component turns `degraded`. rsyslog does not know about the loss, because the listener has already accepted the frames.
- The shipper can lose lines in these cases:
  - A file was rotated while the shipper was stopped, and the old file had unsent lines. On restart, the new file is read from the start, but the old file's tail is not.
  - A file was rotated twice between two polls.
  - A file was truncated and grew past the old offset between two polls.
- One process and SQLite, as with the rest of Watchpost: a lab and demo setup, not a fleet collector.
