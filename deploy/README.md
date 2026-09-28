# Deploying Watchpost on a Debian 12 VM

This folder turns a fresh Debian 12 (bookworm) VM into a public, read-only Watchpost demo:

| File | Installed to | Purpose |
|---|---|---|
| `install.sh` | (run from the checkout) | Idempotent installer. Re-run it to update. |
| `watchpost.service` | `/etc/systemd/system/watchpost.service` | systemd unit: runs `main.py` as the `watchpost` user on `127.0.0.1:8080`, hardened (read-only system, no capabilities) |
| `watchpost.env.example` | `/etc/watchpost.env` (root:watchpost, 0640) | Settings template. It has **no secrets**; you add passwords on the VM only. Written once, never overwritten |
| `Caddyfile` | `/etc/caddy/Caddyfile` | HTTPS with an automatic Let's Encrypt certificate, when you have a domain |
| `nginx-selfsigned.conf` | `/etc/nginx/sites-available/watchpost` | HTTPS with a self-signed certificate, for a bare IP |

The app itself never listens on a public interface. `SIEM_HOST=127.0.0.1` is forced in the unit, and Caddy or nginx
terminates HTTPS in front of it.

Tested in a cloud container with a stubbed `systemctl` (no systemd there): the install, re-install, env-file
permissions, the service user, the viewer account, nginx with the self-signed cert (redirect, HTTPS, secure cookie,
SSE streaming, per-client 429s), and `caddy validate` on Caddy 2.6.2 (the Debian 12 version). `systemd-analyze verify`
accepts the unit. It has **not** yet run on a real Debian 12 VM with systemd, so check the first run's output.

## What you need

- A Debian 12 VM (an e2-small or similar is plenty) with a public IP. The VM needs outbound HTTPS for `apt`.
- Firewall rules that allow inbound TCP 80 and 443 (and 22 for SSH). On GCP, for example:
  `gcloud compute firewall-rules create allow-web --allow=tcp:80,tcp:443 --target-tags=web`, then add the `web`
  network tag to the VM.
- Optional: a domain name with an A record that points at the VM's public IP (for a real certificate).

## Steps

1. **Get the code onto the VM.**

   ```bash
   sudo apt-get update && sudo apt-get install -y git
   git clone https://github.com/talalkashar/watchpost.git ~/watchpost
   cd ~/watchpost
   ```

2. **Run the installer.** Pick one:

   ```bash
   sudo ./deploy/install.sh --caddy demo.example.org       # you have a domain: Let's Encrypt via Caddy
   sudo ./deploy/install.sh --nginx-selfsigned 203.0.113.10 # bare IP: nginx + self-signed cert for that IP
   sudo ./deploy/install.sh                                # app only on 127.0.0.1:8080 (bring your own proxy)
   ```

   The script installs `python3`, `rsync`, and `curl` (plus `caddy`, or `nginx` and `openssl`) from apt if they are
   missing. It creates the `watchpost` system user and copies the repository to `/opt/watchpost` (without `data/`
   or `.git`). It writes `/etc/watchpost.env` from the template if the file doesn't exist yet, then installs,
   enables, and starts `watchpost.service`, configures the proxy, and waits for `/api/health`. With
   `--nginx-selfsigned`, pass the VM's **public** IP so it goes in the certificate. Without it, the script uses the
   first local address, which on GCP is the internal one.

3. **Collect the generated passwords.** On the first start, with no passwords in `/etc/watchpost.env`, Watchpost
   generates the `admin` and `analyst` passwords:

   ```bash
   sudo cat /var/lib/watchpost/initial_credentials.txt   # store them in a password manager
   sudo rm /var/lib/watchpost/initial_credentials.txt
   ```

   To choose them yourself, set `SIEM_ADMIN_PASSWORD` and `SIEM_ANALYST_PASSWORD` in `/etc/watchpost.env`
   **before** the first start. They are only read while the database is empty. To start over:
   `sudo systemctl stop watchpost && sudo rm /var/lib/watchpost/watchpost.db*`, then start it again.

4. **Create the public read-only account.** Edit `/etc/watchpost.env`:

   ```bash
   sudoedit /etc/watchpost.env        # uncomment and set: SIEM_VIEWER_PASSWORD=<12+ characters>
   sudo systemctl restart watchpost
   ```

   On start, a `viewer` user is created if none exists. Changing the variable later does **not** reset an existing
   viewer's password. This viewer login is the one to put in a public post. Viewers can see the dashboard, events,
   alerts, incidents, reports, ATT&CK coverage, and health. They cannot ingest, triage, run demo data or storylines,
   or change rules, settings, tokens, or users.

5. **Load data and check.** Open `https://<domain or IP>/`. The self-signed option shows a browser warning; accept it.
   Sign in as `admin`, then use **Admin → Attack storyline (synthetic) → Start storyline** (or **Load synthetic demo data** for everything at once). For an unattended demo, set `SIEM_DEMO_LOOP=15` in `/etc/watchpost.env` to replay the storyline every 15 minutes. Sign
   out and sign in as `viewer` to see what visitors see.

## Updating

```bash
cd ~/watchpost && git pull
sudo ./deploy/install.sh --caddy demo.example.org   # same flags as before; safe to re-run
```

Re-running recopies the code (`rsync --delete`), reinstalls the unit, and restarts the service. It keeps
`/etc/watchpost.env`, the database in `/var/lib/watchpost`, and an existing self-signed certificate. The Caddy option
backs up a pre-existing `/etc/caddy/Caddyfile` once, to `Caddyfile.pre-watchpost`.

## Rate limits

Every client IP gets two in-memory token buckets. `POST /api/auth/login` allows a burst of 10, then 10 a minute.
Every other request (API and static files) allows a burst of 300, then 1200 a minute. Over the limit, the answer is
HTTP 429 with JSON `{"error", "retry_after"}` and a `Retry-After` header. The template sets `SIEM_TRUST_PROXY=1` so the
client IP comes from the proxy: the **last** `X-Forwarded-For` entry, and only on connections from loopback. The nginx
config overwrites that header with `$remote_addr`, and Caddy sets it itself, so clients cannot spoof it. Tune the
limits with the `SIEM_*RATE*` variables in `/etc/watchpost.env`. The buckets reset on restart.

Account lockout (5 failures lock the account for 15 minutes) still applies on top of the rate limit.

## Operating it

```bash
sudo systemctl status watchpost
sudo journalctl -u watchpost -f          # request log (paths only), errors
curl -s http://127.0.0.1:8080/api/health # from the VM
sudo systemctl restart watchpost         # after editing /etc/watchpost.env
```

Backups: the whole state is `/var/lib/watchpost/watchpost.db` (SQLite, WAL mode). To copy it consistently:
`sudo -u watchpost python3 -c "import sqlite3; s=sqlite3.connect('/var/lib/watchpost/watchpost.db'); d=sqlite3.connect('/var/lib/watchpost/backup.db'); s.backup(d)"`.

## Troubleshooting

- **`watchpost did not become healthy`**: `journalctl -u watchpost -n 50`. A password shorter than 12 characters in
  `/etc/watchpost.env` stops the first start.
- **nginx: `socket() [::]:80 failed (97: Address family not supported)`**: the kernel has IPv6 disabled. Delete the two
  `listen [::]:...` lines in `/etc/nginx/sites-available/watchpost`, then `sudo nginx -t && sudo systemctl reload nginx`.
- **Caddy cannot get a certificate**: the domain's A record must point at the VM and ports 80 and 443 must be open.
  Check with `journalctl -u caddy -n 50`.
- **Changed `SIEM_PORT`**: also change `127.0.0.1:8080` in the Caddyfile or nginx config.
- **Everything is rate limited behind the proxy**: make sure `SIEM_TRUST_PROXY=1` is set. Without it, every visitor
  shares the proxy's address, 127.0.0.1.

## Removing it

```bash
sudo systemctl disable --now watchpost
sudo rm /etc/systemd/system/watchpost.service && sudo systemctl daemon-reload
sudo rm -rf /opt/watchpost /etc/watchpost.env     # add /var/lib/watchpost to delete the data too
sudo userdel watchpost
# then remove /etc/nginx/sites-enabled/watchpost or restore /etc/caddy/Caddyfile.pre-watchpost
```
