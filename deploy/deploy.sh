#!/usr/bin/env bash
# CryptIRC deployment script
# Usage: sudo bash deploy/deploy.sh yourdomain.com admin@yourdomain.com
#
# Tested on Ubuntu 22.04 / 24.04 and Debian 12
# Run as root or with sudo

set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────

DOMAIN="${1:-}"
EMAIL="${2:-}"

if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
    echo "Usage: sudo bash deploy.sh <domain> <email>"
    echo "Example: sudo bash deploy.sh cryptirc.example.com admin@example.com"
    exit 1
fi

INSTALL_DIR="/opt/cryptirc"
DATA_DIR="/var/lib/cryptirc"
LOG_DIR="/var/log/cryptirc"
SERVICE_USER="cryptirc"

echo ""
echo "╔══════════════════════════════════╗"
echo "║  CryptIRC Deployment             ║"
echo "╠══════════════════════════════════╣"
echo "║  Domain : $DOMAIN"
echo "║  Email  : $EMAIL"
echo "║  Install: $INSTALL_DIR"
echo "║  Data   : $DATA_DIR"
echo "╚══════════════════════════════════╝"
echo ""

# ── System dependencies ───────────────────────────────────────────────────────

echo "[1/9] Installing system dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl ca-certificates git build-essential pkg-config \
    libssl-dev postfix libsasl2-dev \
    debian-keyring debian-archive-keyring apt-transport-https

# ── Rust ──────────────────────────────────────────────────────────────────────

echo "[2/9] Installing Rust..."
if ! command -v rustc &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
else
    echo "  Rust already installed: $(rustc --version)"
fi

# ── Caddy ─────────────────────────────────────────────────────────────────────

echo "[3/9] Installing Caddy..."
if ! command -v caddy &>/dev/null; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y caddy
else
    echo "  Caddy already installed: $(caddy version)"
fi

# ── Postfix (basic local relay) ───────────────────────────────────────────────

echo "[4/9] Configuring Postfix for local relay..."
# Set hostname for outbound mail
postconf -e "myhostname = $DOMAIN"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = \$mydomain"
postconf -e "inet_interfaces = loopback-only"
postconf -e "inet_protocols = ipv4"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject"
systemctl enable --now postfix
echo "  Postfix configured for local relay on 127.0.0.1:25"

# ── Service user ──────────────────────────────────────────────────────────────

echo "[5/9] Creating service user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
    echo "  Created user: $SERVICE_USER"
else
    echo "  User $SERVICE_USER already exists"
fi

# ── Directories ───────────────────────────────────────────────────────────────

echo "[6/9] Creating directories..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR" /var/log/caddy
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"
echo "  Directories ready"

# ── Build CryptIRC ────────────────────────────────────────────────────────────

echo "[7/9] Building CryptIRC (this takes a few minutes)..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

cd "$REPO_DIR"
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release 2>&1 | tail -5

cp target/release/cryptirc "$INSTALL_DIR/cryptirc"
chmod 755 "$INSTALL_DIR/cryptirc"
chown root:root "$INSTALL_DIR/cryptirc"
echo "  Binary installed at $INSTALL_DIR/cryptirc"

# ── Caddy config ──────────────────────────────────────────────────────────────

echo "[8/9] Writing Caddy config..."
cat > /etc/caddy/Caddyfile << CADDY
{
    email $EMAIL
    admin off
}

$DOMAIN {
    reverse_proxy localhost:9000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        health_uri /manifest.json
        health_interval 30s
        health_timeout 5s
    }

    encode zstd gzip

    @static {
        path /icon.svg /manifest.json
    }
    header @static Cache-Control "public, max-age=3600"

    @sw {
        path /sw.js
    }
    header @sw Cache-Control "public, max-age=0"

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Robots-Tag "noindex, nofollow"
        -Server
    }

    log {
        output file /var/log/caddy/cryptirc.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}
CADDY

# Validate config
caddy validate --config /etc/caddy/Caddyfile
echo "  Caddy config written and validated"

# ── Systemd service ───────────────────────────────────────────────────────────

echo "[9/9] Installing and starting services..."
cat > /etc/systemd/system/cryptirc.service << UNIT
[Unit]
Description=CryptIRC — Encrypted IRC Client
After=network-online.target caddy.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/cryptirc
ExecStop=/bin/kill -s TERM \$MAINPID
TimeoutStopSec=30
KillMode=mixed
Restart=on-failure
RestartSec=5
StartLimitInterval=60
StartLimitBurst=5

Environment=CRYPTIRC_DATA=$DATA_DIR
Environment=CRYPTIRC_BASE_URL=https://$DOMAIN
Environment=RUST_LOG=info

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$DATA_DIR
ReadWritePaths=$LOG_DIR
ProtectHome=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
ProtectClock=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectHostname=true
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now cryptirc
systemctl reload-or-restart caddy

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  CryptIRC deployed successfully!                 ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║                                                  ║"
echo "║  URL    : https://$DOMAIN"
echo "║  Data   : $DATA_DIR"
echo "║  Logs   : journalctl -u cryptirc -f"
echo "║                                                  ║"
echo "║  Caddy will automatically obtain a TLS cert.     ║"
echo "║  This takes ~30 seconds on first visit.          ║"
echo "║                                                  ║"
echo "║  Useful commands:                                ║"
echo "║    systemctl status cryptirc                     ║"
echo "║    systemctl status caddy                        ║"
echo "║    journalctl -u cryptirc -f                     ║"
echo "║    journalctl -u caddy -f                        ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
