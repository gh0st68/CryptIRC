#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CryptIRC Installer  (Arch Linux, rolling)
#
# Usage:
#   sudo bash deploy/deploy-arch.sh                       # interactive (recommended)
#   sudo bash deploy/deploy-arch.sh irc.example.com you@example.com   # domain + free Let's Encrypt TLS
#   sudo bash deploy/deploy-arch.sh 203.0.113.10          # bare IP + self-signed cert (no domain needed)
#
# Pass a DOMAIN as the 1st argument for a non-interactive install (no prompts).
# Pass a bare IP as the 1st argument to install on that IP with a self-signed
# certificate. With no arguments the script walks you through everything.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors / output helpers ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
die()  { echo -e "\n${RED}Error:${NC} $*\n" >&2; exit 1; }
step() { echo -e "\n${BOLD}$*${NC}\n"; }

INSTALL_DIR="/opt/cryptirc"
DATA_DIR="/var/lib/cryptirc"
LOG_DIR="/var/log/cryptirc"
SERVICE_USER="cryptirc"
SS_DIR="/etc/caddy/selfsigned"
RUN_LOG="/tmp/cryptirc-install.log"

run() {
  local desc="$1"; shift
  echo -e "  ${DIM}${desc}...${NC}"
  if ! "$@" >"$RUN_LOG" 2>&1; then
    echo -e "  ${RED}✗ ${desc} failed.${NC} Last lines:" >&2
    tail -n 15 "$RUN_LOG" >&2
    die "Step failed. Full output: $RUN_LOG"
  fi
}

is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ipv6() { [[ "$1" == *:* ]]; }
is_ip()   { is_ipv4 "$1" || is_ipv6 "$1"; }
url_host() { if is_ipv6 "$1"; then echo "[$1]"; else echo "$1"; fi; }

[[ $EUID -eq 0 ]] || die "This script must be run as root:  sudo bash deploy/deploy-arch.sh"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}${BOLD}          CryptIRC Installer v0.6 (Arch)              ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${NC}${DIM}          End-to-end encrypted IRC client              ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"

# ── Step 1: where will this run? (domain vs bare IP / self-signed) ─────────────
DOMAIN="${1:-}"
EMAIL="${2:-}"
INTERACTIVE=true; [[ -n "$DOMAIN" ]] && INTERACTIVE=false
SELF_SIGNED=false
HOSTADDR=""

SERVER_IP=$(curl -s --max-time 5 ip.me 2>/dev/null \
         || curl -s --max-time 5 ifconfig.me 2>/dev/null \
         || curl -s --max-time 5 icanhazip.com 2>/dev/null \
         || echo "")

if [[ "$INTERACTIVE" == true ]]; then
    step "[1/6] Server address"
    [[ -n "$SERVER_IP" ]] && echo -e "  Detected public IP: ${GREEN}${SERVER_IP}${NC}\n"
    echo -e "  ${DIM}A domain gives you a free, browser-trusted Let's Encrypt certificate."
    echo -e "  No domain? Just press Enter to serve on your IP with a self-signed cert —"
    echo -e "  it works fine; browsers only show a one-time \"proceed anyway\" warning.${NC}\n"
    read -rp "  Domain name (or press Enter to use the IP): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        SELF_SIGNED=true
        read -rp "  Address to serve on [${SERVER_IP:-type an IP/hostname}]: " HOSTADDR
        HOSTADDR="${HOSTADDR:-$SERVER_IP}"
        [[ -n "$HOSTADDR" ]] || die "No address provided."
        DOMAIN="$HOSTADDR"
        echo -e "\n  ${CYAN}→ Self-signed mode:${NC} https://$(url_host "$HOSTADDR")  ${DIM}(no domain, no email needed)${NC}"
    else
        read -rp "  Your email (for Let's Encrypt renewal notices): " EMAIL
        [[ -n "$EMAIL" ]] || die "An email is required for a Let's Encrypt domain."
    fi
else
    if is_ip "$DOMAIN"; then
        SELF_SIGNED=true; HOSTADDR="$DOMAIN"
        echo -e "\n  ${CYAN}→ Self-signed mode on ${HOSTADDR}${NC}"
    else
        [[ -n "$EMAIL" ]] || die "Domain install needs an email:  sudo bash deploy/deploy-arch.sh <domain> <email>"
        echo -e "  Domain : ${GREEN}${DOMAIN}${NC}"
        echo -e "  Email  : ${GREEN}${EMAIL}${NC}"
    fi
fi

URL_HOST="$(url_host "$DOMAIN")"

# ── Step 2: DNS check (domain mode only) ──────────────────────────────────────
if [[ "$SELF_SIGNED" == false ]]; then
    step "[2/6] Checking DNS"

    check_dns() {
        local r=""
        if command -v dig &>/dev/null; then
            r=$(dig +short A "$DOMAIN" 2>/dev/null | grep -E '^[0-9]' | head -1)
            [[ -z "$r" ]] && r=$(dig +short AAAA "$DOMAIN" 2>/dev/null | grep -E '^[0-9a-fA-F:]' | head -1)
        fi
        [[ -z "$r" ]] && command -v host &>/dev/null && r=$(host "$DOMAIN" 2>/dev/null | grep -E 'has (IPv6 )?address' | head -1 | awk '{print $NF}')
        [[ -z "$r" ]] && r=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1)
        echo "$r"
    }

    DOMAIN_IP=$(check_dns)
    if [[ -n "$SERVER_IP" && "$DOMAIN_IP" == "$SERVER_IP" ]]; then
        ok "DNS points here: ${DOMAIN} → ${SERVER_IP}"
    else
        warn "${DOMAIN} doesn't appear to resolve to this server (${SERVER_IP:-unknown})."
        echo -e "  ${DIM}If you use Cloudflare's proxy or IPv6-only DNS this check can be wrong — that's fine.${NC}"
        echo -e "  ${DIM}Create an A record:  ${DOMAIN} → ${SERVER_IP:-<your server IP>}${NC}"
        if [[ "$INTERACTIVE" == true ]]; then
            echo ""
            read -rp "  Press Enter to wait for DNS (up to ~10 min), or type 'skip' to continue now: " DNS_CHOICE
            if [[ "$DNS_CHOICE" != skip ]]; then
                for ((i=1; i<=20; i++)); do
                    DOMAIN_IP=$(check_dns)
                    if [[ "$DOMAIN_IP" == "$SERVER_IP" ]]; then ok "DNS resolved! ${DOMAIN} → ${SERVER_IP}"; break; fi
                    echo -e "  ${DIM}waiting… (${i}/20, currently: ${DOMAIN_IP:-nothing})${NC}"
                    sleep 30
                done
                [[ "$DOMAIN_IP" == "$SERVER_IP" ]] || warn "Still not matching — continuing. Let's Encrypt will keep retrying once DNS is correct."
            fi
        else
            warn "Continuing (non-interactive). Let's Encrypt issues the cert once DNS points here."
        fi
    fi
fi

# ── Step 3: registration mode ─────────────────────────────────────────────────
step "[3/6] Registration"
ENABLE_EMAIL=false
REG_CODE=""
REG_MODE="1"

if [[ "$SELF_SIGNED" == true ]]; then
    echo -e "  ${GREEN}→ Invite only${NC} ${DIM}(open registration needs a domain for email; create users with adduser.sh)${NC}"
elif [[ "$INTERACTIVE" == true ]]; then
    echo "  How should new users register?"
    echo -e "    ${BOLD}1)${NC} ${GREEN}Invite only${NC} — you create accounts manually (most secure)"
    echo -e "    ${BOLD}2)${NC} ${CYAN}Open${NC} — anyone can register with email verification"
    echo ""
    read -rp "  Choose [1/2] (default 1): " REG_MODE
    REG_MODE="${REG_MODE:-1}"
    if [[ "$REG_MODE" == "2" ]]; then
        ENABLE_EMAIL=true
        echo -e "  ${CYAN}→ Open registration. Postfix will be configured for email.${NC}"
        read -rp "  Require a registration code? (y/N): " WANT_CODE
        if [[ "$WANT_CODE" =~ ^[Yy] ]]; then
            read -rp "  Registration code: " REG_CODE
            [[ -n "$REG_CODE" ]] && echo -e "  ${CYAN}→ Users must enter '${REG_CODE}' to register.${NC}"
        fi
    else
        echo -e "  ${GREEN}→ Invite only.${NC} ${DIM}Add users with adduser.sh.${NC}"
    fi
else
    echo -e "  ${GREEN}→ Invite only${NC} ${DIM}(default for non-interactive installs; add users with adduser.sh)${NC}"
fi

# ── Step 4: dependencies ──────────────────────────────────────────────────────
step "[4/6] Installing dependencies"
# Full system upgrade — `pacman -Sy` alone is an unsupported partial upgrade on
# rolling Arch (a later `pacman -S` would link against not-yet-installed libs).
run "Updating system" pacman -Syu --noconfirm
run "Installing system packages" pacman -S --needed --noconfirm \
    base-devel curl git openssl python python-pip bind-tools ffmpeg

pip install argon2-cffi --quiet --break-system-packages 2>/dev/null \
    || pip install argon2-cffi --quiet 2>/dev/null || true

if [[ "$ENABLE_EMAIL" == true ]]; then
    run "Installing Postfix" pacman -S --needed --noconfirm postfix
fi
ok "System packages installed"

# Rust — prefer the rustup package, fall back to the rustup.rs installer
if ! command -v rustc &>/dev/null; then
    echo -e "  ${DIM}Installing Rust...${NC}"
    if pacman -S --needed --noconfirm rustup >/dev/null 2>&1; then
        run "Setting Rust default toolchain" rustup default stable
    else
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable >/dev/null 2>&1
        source "$HOME/.cargo/env"
    fi
    ok "Rust installed"
else
    ok "Rust already installed: $(rustc --version)"
fi

# Caddy (in the 'extra' repo on Arch — community was merged into extra in 2023)
if ! command -v caddy &>/dev/null; then
    run "Installing Caddy" pacman -S --needed --noconfirm caddy
    ok "Caddy installed"
else
    ok "Caddy already installed"
fi

if [[ "$ENABLE_EMAIL" == true ]]; then
    echo -e "  ${DIM}Configuring Postfix...${NC}"
    postconf -e "myhostname = $DOMAIN"
    postconf -e "mydomain = $DOMAIN"
    postconf -e "myorigin = \$mydomain"
    postconf -e "inet_interfaces = loopback-only"
    postconf -e "inet_protocols = ipv4"
    postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
    postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject"
    systemctl enable --now postfix >/dev/null 2>&1 || true
    ok "Postfix configured"
fi

id "$SERVICE_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/bin/nologin "$SERVICE_USER"
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR" /var/log/caddy
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"

# ── Step 5: build ─────────────────────────────────────────────────────────────
step "[5/6] Building CryptIRC"
echo -e "  ${DIM}First build takes 3-5 minutes. Please wait.${NC}\n"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"
source "$HOME/.cargo/env" 2>/dev/null || true
if ! cargo build --release; then
    die "Build failed (see output above). Common causes: low RAM (need ~1 GB free — add swap) or missing openssl."
fi
[[ -f target/release/cryptirc ]] || die "Build reported success but target/release/cryptirc is missing."
install -m 755 -o root -g root target/release/cryptirc "$INSTALL_DIR/cryptirc"
ok "CryptIRC built and installed"

# ── Step 6: configure TLS + service ───────────────────────────────────────────
step "[6/6] Configuring services"

[[ -f /etc/caddy/Caddyfile ]] && cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)" \
    && warn "Existing Caddyfile backed up to /etc/caddy/Caddyfile.bak.*"

if [[ "$SELF_SIGNED" == true ]]; then
    mkdir -p "$SS_DIR"
    # (Re)generate the cert if there isn't one, OR an existing one doesn't cover this
    # address (e.g. re-running the installer after the server's IP changed).
    if [[ ! -f "$SS_DIR/cert.pem" ]] || ! openssl x509 -in "$SS_DIR/cert.pem" -noout -text 2>/dev/null | grep -qF "$HOSTADDR"; then
        if is_ip "$HOSTADDR"; then SAN="IP:$HOSTADDR"; else SAN="DNS:$HOSTADDR"; fi
        run "Generating self-signed certificate" openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$SS_DIR/key.pem" -out "$SS_DIR/cert.pem" -days 3650 \
            -subj "/CN=$HOSTADDR" -addext "subjectAltName=$SAN"
    fi
    chown caddy:caddy "$SS_DIR/key.pem" "$SS_DIR/cert.pem" 2>/dev/null || true
    chmod 640 "$SS_DIR/key.pem"; chmod 644 "$SS_DIR/cert.pem"

    cat > /etc/caddy/Caddyfile <<CADDY
{
    admin off
}

http://$URL_HOST {
    redir https://$URL_HOST{uri}
}

https://$URL_HOST {
    tls $SS_DIR/cert.pem $SS_DIR/key.pem
    reverse_proxy localhost:9001 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
    encode zstd gzip
    header {
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
else
    cat > /etc/caddy/Caddyfile <<CADDY
{
    email $EMAIL
    admin off
}

$URL_HOST {
    reverse_proxy localhost:9001 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
    encode zstd gzip
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
fi

if ! caddy validate --config /etc/caddy/Caddyfile >"$RUN_LOG" 2>&1; then
    cat "$RUN_LOG" >&2
    die "Caddy config is invalid (see above)."
fi
ok "Caddy configured"

CRYPTIRC_REG_VALUE="closed"; [[ "$ENABLE_EMAIL" == true ]] && CRYPTIRC_REG_VALUE="open"
HSTS_VALUE="on";            [[ "$SELF_SIGNED" == true ]] && HSTS_VALUE="off"
FROM_EMAIL="${EMAIL:-noreply@localhost}"

cat > /etc/systemd/system/cryptirc.service <<UNIT
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
Environment="CRYPTIRC_BASE_URL=https://$URL_HOST"
Environment=CRYPTIRC_BASE_PATH=/
Environment=CRYPTIRC_PORT=9001
Environment="CRYPTIRC_FROM_EMAIL=$FROM_EMAIL"
Environment=CRYPTIRC_REGISTRATION=${CRYPTIRC_REG_VALUE}
Environment="CRYPTIRC_REG_CODE=$REG_CODE"
Environment=CRYPTIRC_HSTS=${HSTS_VALUE}
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
chmod 640 /etc/systemd/system/cryptirc.service

systemctl daemon-reload
systemctl enable --now cryptirc >/dev/null 2>&1 || true
systemctl reload-or-restart caddy  >/dev/null 2>&1 || true
ok "Services started"

sleep 3
if systemctl is-active --quiet cryptirc; then
    ok "CryptIRC is running"
else
    warn "CryptIRC isn't active yet. Check:  journalctl -u cryptirc -n 50 --no-pager"
fi

# ── Firewall (ufw → firewalld → iptables) ─────────────────────────────────────
echo ""
if command -v ufw &>/dev/null; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ok "Opened ports 80 and 443 (ufw)"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-service=http  >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "Opened ports 80 and 443 (firewalld)"
elif command -v iptables &>/dev/null; then
    iptables -C INPUT -p tcp --dport 80  -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 80  -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    ok "Opened ports 80 and 443 (iptables)"
    warn "iptables rules aren't persistent — install iptables and enable a save service to keep them."
fi

# ── First user (interactive only) ─────────────────────────────────────────────
if [[ "$INTERACTIVE" == true ]]; then
    echo ""
    echo -e "${BOLD}Create your first user (admin)${NC}\n"
    read -rp "  Would you like to create a user now? (y/N): " CREATE_USER
    if [[ "$CREATE_USER" =~ ^[Yy] ]]; then
        read -rp  "  Username (3-32 chars, letters/numbers/_): " NEW_USER
        read -rp  "  Email [${NEW_USER:-user}@${DOMAIN}]: " NEW_EMAIL
        read -rsp "  Password (min 10 chars): " NEW_PASS; echo ""
        NEW_EMAIL="${NEW_EMAIL:-${NEW_USER}@${DOMAIN}}"
        if [[ -z "$NEW_USER" || -z "$NEW_PASS" ]]; then
            warn "Skipped — username and password are required."
        elif [[ ${#NEW_PASS} -lt 10 ]]; then
            warn "Skipped — password must be at least 10 characters."
        else
            if CRYPTIRC_NEW_PASS="$NEW_PASS" bash "$REPO_DIR/adduser.sh" "$NEW_USER" "$NEW_EMAIL" 2>"$RUN_LOG"; then
                ok "User '${NEW_USER}' created"
                USER_FILE="$DATA_DIR/users/$(echo "$NEW_USER" | tr '[:upper:]' '[:lower:]').json"
                if [[ -f "$USER_FILE" ]] && CRYPTIRC_USER_FILE="$USER_FILE" python3 - <<'PY' 2>/dev/null
import json, os
p = os.environ['CRYPTIRC_USER_FILE']
with open(p) as f: d = json.load(f)
d['admin'] = True
with open(p, 'w') as f: json.dump(d, f, indent=2)
PY
                then ok "${NEW_USER} is now an admin"
                else warn "Created the user, but couldn't set admin — do it later in Settings ▸ Admin."
                fi
            else
                warn "Couldn't create the user. Try:  sudo CRYPTIRC_NEW_PASS=... bash adduser.sh ${NEW_USER} ${NEW_EMAIL}"
                tail -n 5 "$RUN_LOG" >&2 || true
            fi
        fi
    fi
fi

rm -f "$RUN_LOG" 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}✓ CryptIRC is live!${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  ${BOLD}URL${NC}: ${GREEN}https://${URL_HOST}${NC}"
if [[ "$SELF_SIGNED" == true ]]; then
echo -e "${CYAN}║${NC}  ${YELLOW}Self-signed cert:${NC} your browser shows a one-time warning."
echo -e "${CYAN}║${NC}  ${DIM}Click \"Advanced\" → \"Proceed\" — that's expected & safe.${NC}"
echo -e "${CYAN}║${NC}  Registration: ${GREEN}Invite only${NC}"
echo -e "${CYAN}║${NC}  Add users: ${DIM}sudo CRYPTIRC_NEW_PASS=pw bash adduser.sh <user> <email>${NC}"
elif [[ "$ENABLE_EMAIL" == true ]]; then
echo -e "${CYAN}║${NC}  Registration: ${CYAN}Open${NC} (email verification)"
else
echo -e "${CYAN}║${NC}  Registration: ${GREEN}Invite only${NC}"
echo -e "${CYAN}║${NC}  Add users: ${DIM}sudo CRYPTIRC_NEW_PASS=pw bash adduser.sh <user> <email>${NC}"
fi
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${DIM}status:  systemctl status cryptirc${NC}"
echo -e "${CYAN}║${NC}  ${DIM}logs:    journalctl -u cryptirc -f${NC}"
echo -e "${CYAN}║${NC}  ${DIM}update:  sudo bash deploy/update.sh${NC}"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Help:${NC} ${BOLD}irc.twistednet.org${NC} ${DIM}#dev / #twisted${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
