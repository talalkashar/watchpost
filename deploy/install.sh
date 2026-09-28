#!/usr/bin/env bash
# Install or update Watchpost as a systemd service on Debian 12. Safe to re-run.
#
#   sudo ./deploy/install.sh                          # app only, on 127.0.0.1:8080
#   sudo ./deploy/install.sh --caddy demo.example.org # plus Caddy with a Let's Encrypt cert
#   sudo ./deploy/install.sh --nginx-selfsigned [IP]  # plus nginx with a self-signed cert (bare IP);
#                                                     # IP (the public address) goes in the cert
#
# What it does, each step skipped or refreshed when already done:
#   1. installs python3 and rsync from apt if missing
#   2. creates the `watchpost` system user (no shell, no login)
#   3. copies this repository to /opt/watchpost (root-owned, read-only for the service;
#      data/ and .git are not copied)
#   4. writes /etc/watchpost.env from deploy/watchpost.env.example, only if it does not
#      exist yet (the template has no secrets; your edits are never overwritten)
#   5. installs deploy/watchpost.service, enables it, and (re)starts it
#   6. optionally configures Caddy or nginx as the HTTPS reverse proxy
#   7. waits for GET /api/health on 127.0.0.1
set -euo pipefail

APP_DIR=/opt/watchpost
STATE_DIR=/var/lib/watchpost
ENV_FILE=/etc/watchpost.env
UNIT=/etc/systemd/system/watchpost.service
SERVICE_USER=watchpost
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROXY=none
DOMAIN=""
CERT_IP=""

usage() {
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --caddy)
            [ $# -ge 2 ] || { echo "--caddy needs a domain" >&2; usage 2; }
            PROXY=caddy; DOMAIN="$2"; shift 2 ;;
        --nginx-selfsigned)
            PROXY=nginx; shift
            if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then CERT_IP="$1"; shift; fi ;;
        -h|--help)
            usage 0 ;;
        *)
            echo "unknown option: $1" >&2; usage 2 ;;
    esac
done

log() { printf '==> %s\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0 $*" >&2
    exit 1
fi
if [ "$PROXY" = caddy ] && ! printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'; then
    echo "invalid domain: $DOMAIN" >&2
    exit 2
fi
if [ -n "$CERT_IP" ] && ! python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$CERT_IP" 2>/dev/null; then
    echo "invalid IP address: $CERT_IP" >&2
    exit 2
fi
if [ -r /etc/os-release ] && ! grep -q '^VERSION_CODENAME=bookworm' /etc/os-release; then
    echo "warning: written for Debian 12 (bookworm); continuing anyway" >&2
fi
[ -f "$SRC/main.py" ] && [ -d "$SRC/watchpost" ] || { echo "run from a Watchpost checkout" >&2; exit 1; }

apt_install() {
    local missing=()
    for pkg in "$@"; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log "installing ${missing[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}"
    fi
}

# 1. Packages.
apt_install python3 rsync curl
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ required")'

# 2. Service user.
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "user $SERVICE_USER exists"
else
    log "creating system user $SERVICE_USER"
    useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home \
        --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR"

# 3. Application code.
if [ "$SRC" != "$APP_DIR" ]; then
    log "copying $SRC to $APP_DIR"
    install -d -o root -g root -m 0755 "$APP_DIR"
    rsync -a --delete --chown=root:root --chmod=D755,F644 \
        --exclude '.git/' --exclude 'data/' --exclude '__pycache__/' --exclude '*.pyc' \
        "$SRC/" "$APP_DIR/"
    chmod 0755 "$APP_DIR"/*.sh "$APP_DIR"/deploy/*.sh "$APP_DIR"/scripts/*.py
fi

# 4. Environment file (never overwritten).
if [ -e "$ENV_FILE" ]; then
    log "$ENV_FILE exists; leaving it unchanged"
else
    log "writing $ENV_FILE from the template (no secrets)"
    install -o root -g "$SERVICE_USER" -m 0640 "$APP_DIR/deploy/watchpost.env.example" "$ENV_FILE"
fi
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

# 5. systemd unit.
log "installing $UNIT"
install -o root -g root -m 0644 "$APP_DIR/deploy/watchpost.service" "$UNIT"
systemctl daemon-reload
systemctl enable watchpost.service >/dev/null
systemctl restart watchpost.service

# 6. Reverse proxy.
case "$PROXY" in
    caddy)
        apt_install caddy
        log "configuring Caddy for $DOMAIN"
        tmp="$(mktemp)"
        sed "s/watchpost\.example\.com/$DOMAIN/" "$APP_DIR/deploy/Caddyfile" > "$tmp"
        if [ -f /etc/caddy/Caddyfile ] && ! cmp -s "$tmp" /etc/caddy/Caddyfile \
                && [ ! -f /etc/caddy/Caddyfile.pre-watchpost ]; then
            cp -p /etc/caddy/Caddyfile /etc/caddy/Caddyfile.pre-watchpost
        fi
        install -o root -g root -m 0644 "$tmp" /etc/caddy/Caddyfile
        rm -f "$tmp"
        install -d -o caddy -g caddy -m 0755 /var/log/caddy
        if ! out="$(caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1)"; then
            printf '%s\n' "$out" >&2
            exit 1
        fi
        systemctl enable caddy >/dev/null
        systemctl reload-or-restart caddy
        ;;
    nginx)
        apt_install nginx openssl
        if [ ! -s /etc/ssl/watchpost/watchpost.crt ] || [ ! -s /etc/ssl/watchpost/watchpost.key ]; then
            ip="${CERT_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
            ip="${ip:-127.0.0.1}"
            log "creating a self-signed certificate for $ip (valid 825 days)"
            install -d -o root -g root -m 0755 /etc/ssl/watchpost
            (umask 077 && openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 \
                -subj "/CN=watchpost" -addext "subjectAltName=IP:$ip" \
                -keyout /etc/ssl/watchpost/watchpost.key -out /etc/ssl/watchpost/watchpost.crt 2>/dev/null)
            chmod 0644 /etc/ssl/watchpost/watchpost.crt
        else
            log "self-signed certificate exists; keeping it"
        fi
        log "configuring nginx"
        install -o root -g root -m 0644 "$APP_DIR/deploy/nginx-selfsigned.conf" /etc/nginx/sites-available/watchpost
        ln -sfn /etc/nginx/sites-available/watchpost /etc/nginx/sites-enabled/watchpost
        rm -f /etc/nginx/sites-enabled/default
        nginx -t -q
        systemctl enable nginx >/dev/null
        systemctl reload-or-restart nginx
        ;;
esac

# 7. Health.
port="$(sed -n 's/^SIEM_PORT=\([0-9]*\).*/\1/p' "$ENV_FILE" | tail -n 1)"
port="${port:-8080}"
log "waiting for http://127.0.0.1:$port/api/health"
for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$port/api/health" >/dev/null 2>&1; then
        log "watchpost is up: $(curl -fsS "http://127.0.0.1:$port/api/health")"
        if [ -f "$STATE_DIR/initial_credentials.txt" ]; then
            log "generated passwords are in $STATE_DIR/initial_credentials.txt (read them, then delete the file)"
        fi
        exit 0
    fi
    sleep 1
done
echo "watchpost did not become healthy; see: journalctl -u watchpost -n 50" >&2
exit 1
