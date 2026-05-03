#!/usr/bin/env bash
# CryptIRC Deployment Script for Arch Linux
# Usage: sudo bash deploy/deploy-arch.sh [domain] [email]
#
# If run without arguments, enters interactive mode.
# Tested on Arch Linux (rolling release)

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

INSTALL_DIR="/opt/cryptirc"
DATA_DIR="/var/lib/cryptirc"
LOG_DIR="/var/log/cryptirc"
SERVICE_USER="cryptirc"

# ── Check root ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    echo "Usage: sudo bash deploy/deploy-arch.sh"
    exit 1
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}${BOLD}          CryptIRC Installer v0.5 (Arch)              ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${NC}${DIM}          End-to-end encrypted IRC client              ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Get domain and email (interactive or from args) ───────────────────────────
DOMAIN="${1:-}"
EMAIL="${2:-}"

if [[ -z "$DOMAIN" ]]; then
    echo -e "${BOLD}[1/6] Server Information${NC}"
    echo ""

    SERVER_IP=$(curl -s --max-time 5 ip.me 2>/dev/null \
             || curl -s --max-time 5 ifconfig.me 2>/dev/null \
             || curl -s --max-time 5 icanhazip.com 2>/dev/null \
             || echo "unknown")

    echo -e "  Your server's public IP: ${GREEN}${SERVER_IP}${NC}"
    echo ""
    read -p "  Enter your domain name (e.g. irc.mydomain.com): " DOMAIN
    read -p "  Enter your email address: " EMAIL
    echo ""

    if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
        echo -e "${RED}Error: Domain and email are required.${NC}"
        exit 1
    fi

    # ── DNS Check ─────────────────────────────────────────────────────────────
    echo -e "${BOLD}[2/6] Checking DNS...${NC}"
    echo ""

    check_dns() {
        local resolved=""
        if command -v dig &>/dev/null; then
            resolved=$(dig +short A "$DOMAIN" 2>/dev/null | grep -E '^[0-9]' | head -1)
        fi
        if [[ -z "$resolved" ]] && command -v host &>/dev/null; then
            resolved=$(host "$DOMAIN" 2>/dev/null | grep 'has address' | head -1 | awk '{print $NF}')
        fi
        if [[ -z "$resolved" ]]; then
            resolved=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1)
        fi
        echo "$resolved"
    }

    DOMAIN_IP=$(check_dns)

    if [[ "$SERVER_IP" != "unknown" && "$DOMAIN_IP" == "$SERVER_IP" ]]; then
        echo -e "  ${GREEN}✓ DNS is correct!${NC} ${DOMAIN} → ${SERVER_IP}"
    else
        echo -e "  ${RED}✗ ${DOMAIN} does not point to this server.${NC}"
        echo ""
        echo -e "  ${CYAN}╔════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${CYAN}║${NC}  You need to create a DNS ${BOLD}A record${NC}:                ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}                                                    ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  ${BOLD}Name${NC}:  ${DOMAIN}"
        echo -e "  ${CYAN}║${NC}  ${BOLD}Type${NC}:  A"
        echo -e "  ${CYAN}║${NC}  ${BOLD}Value${NC}: ${GREEN}${SERVER_IP}${NC}"
        echo -e "  ${CYAN}║${NC}                                                    ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  Do this in your domain registrar's DNS settings   ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  (GoDaddy, Cloudflare, Namecheap, etc.)            ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}                                                    ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  DNS can take 1-10 minutes to propagate.           ${CYAN}║${NC}"
        echo -e "  ${CYAN}╚════════════════════════════════════════════════════╝${NC}"
        echo ""

        read -p "  Press Enter to wait for DNS, or type 'skip' to continue anyway: " DNS_CHOICE

        if [[ "$DNS_CHOICE" != "skip" ]]; then
            echo ""
            echo -e "  ${DIM}Waiting for DNS to resolve... (checking every 30s, Ctrl+C to cancel)${NC}"
            ATTEMPT=0
            while true; do
                ATTEMPT=$((ATTEMPT + 1))
                DOMAIN_IP=$(check_dns)
                if [[ "$DOMAIN_IP" == "$SERVER_IP" ]]; then
                    echo -e "  ${GREEN}✓ DNS resolved!${NC} ${DOMAIN} → ${SERVER_IP}"
                    break
                fi
                echo -e "  ${DIM}⏳ Attempt ${ATTEMPT} — not yet... (resolved to: ${DOMAIN_IP:-nothing})${NC}"
                sleep 30
            done
        else
            echo -e "  ${YELLOW}⚠ Skipping DNS check. Make sure DNS is configured before visiting the site.${NC}"
        fi
    fi
    echo ""
else
    echo -e "  Domain : ${GREEN}${DOMAIN}${NC}"
    echo -e "  Email  : ${GREEN}${EMAIL}${NC}"
    echo ""
fi

# ── Registration mode ─────────────────────────────────────────────────────────
echo -e "${BOLD}[3/6] Registration Settings${NC}"
echo ""
echo "  How should new users register?"
echo ""
echo -e "  ${BOLD}1)${NC} ${GREEN}Invite only${NC} — you create accounts manually (more secure)"
echo -e "  ${BOLD}2)${NC} ${CYAN}Open registration${NC} — anyone can register with email verification"
echo ""
read -p "  Choose [1/2] (default: 1): " REG_MODE
REG_MODE="${REG_MODE:-1}"

ENABLE_EMAIL=false
REG_CODE=""
if [[ "$REG_MODE" == "2" ]]; then
    ENABLE_EMAIL=true
    echo -e "  ${CYAN}→ Open registration enabled. Postfix will be configured for email.${NC}"
    echo ""
    read -p "  Require a registration code? (y/n, default: n): " WANT_CODE
    if [[ "$WANT_CODE" =~ ^[Yy] ]]; then
        read -p "  Enter the registration code: " REG_CODE
        if [[ -n "$REG_CODE" ]]; then
            echo -e "  ${CYAN}→ Registration code set. Users must enter '${REG_CODE}' to register.${NC}"
        fi
    fi
else
    echo -e "  ${GREEN}→ Invite only. Use adduser.sh to create accounts.${NC}"
fi
echo ""

# ── Install system dependencies ───────────────────────────────────────────────
echo -e "${BOLD}[4/6] Installing dependencies...${NC}"
echo ""

echo -e "  ${DIM}Syncing package database...${NC}"
pacman -Sy --noconfirm >/dev/null 2>&1

echo -e "  ${DIM}Installing system packages...${NC}"
pacman -S --needed --noconfirm \
    base-devel curl git openssl python python-pip \
    bind-tools ffmpeg >/dev/null 2>&1

# Install argon2 for adduser.sh
pip install argon2-cffi --quiet --break-system-packages 2>/dev/null \
    || pip install argon2-cffi --quiet 2>/dev/null || true

if [[ "$ENABLE_EMAIL" == "true" ]]; then
    echo -e "  ${DIM}Installing Postfix for email...${NC}"
    pacman -S --needed --noconfirm postfix >/dev/null 2>&1
fi

echo -e "  ${GREEN}✓ System packages installed${NC}"

# ── Rust ──────────────────────────────────────────────────────────────────────
echo -e "  ${DIM}Installing Rust...${NC}"
if ! command -v rustc &>/dev/null; then
    # Prefer the pacman package, fall back to rustup
    if pacman -S --needed --noconfirm rustup >/dev/null 2>&1; then
        rustup default stable >/dev/null 2>&1
    else
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --default-toolchain stable >/dev/null 2>&1
        source "$HOME/.cargo/env"
    fi
    echo -e "  ${GREEN}✓ Rust installed${NC}"
else
    echo -e "  ${GREEN}✓ Rust already installed: $(rustc --version)${NC}"
fi

# ── Caddy ─────────────────────────────────────────────────────────────────────
echo -e "  ${DIM}Installing Caddy...${NC}"
if ! command -v caddy &>/dev/null; then
    # caddy is in the community repo on Arch
    pacman -S --needed --noconfirm caddy >/dev/null 2>&1
    echo -e "  ${GREEN}✓ Caddy installed${NC}"
else
    echo -e "  ${GREEN}✓ Caddy already installed${NC}"
fi

# ── Postfix config ────────────────────────────────────────────────────────────
if [[ "$ENABLE_EMAIL" == "true" ]]; then
    echo -e "  ${DIM}Configuring Postfix...${NC}"
    postconf -e "myhostname = $DOMAIN"
    postconf -e "mydomain = $DOMAIN"
    postconf -e "myorigin = \$mydomain"
    postconf -e "inet_interfaces = loopback-only"
    postconf -e "inet_protocols = ipv4"
    postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
    postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject"
    systemctl enable --now postfix >/dev/null 2>&1
    echo -e "  ${GREEN}✓ Postfix configured${NC}"
fi

# ── Service user ──────────────────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/bin/nologin "$SERVICE_USER"
fi

# ── Directories ───────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR" /var/log/caddy
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"

echo ""

# ── Build CryptIRC ────────────────────────────────────────────────────────────
echo -e "${BOLD}[5/6] Building CryptIRC...${NC}"
echo -e "  ${DIM}This takes 3-5 minutes on first build. Please wait.${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

cd "$REPO_DIR"
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release 2>&1 | tail -3

cp target/release/cryptirc "$INSTALL_DIR/cryptirc"
chmod 755 "$INSTALL_DIR/cryptirc"
chown root:root "$INSTALL_DIR/cryptirc"
echo ""
echo -e "  ${GREEN}✓ CryptIRC built and installed${NC}"
echo ""

# ── Caddy config ──────────────────────────────────────────────────────────────
echo -e "${BOLD}[6/6] Configuring services...${NC}"
echo ""

if [[ -f /etc/caddy/Caddyfile ]]; then
    cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
    echo -e "  ${YELLOW}⚠ Existing Caddyfile backed up to /etc/caddy/Caddyfile.bak.*${NC}"
fi

cat > /etc/caddy/Caddyfile << CADDY
{
    email $EMAIL
    admin off
}

$DOMAIN {
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

caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1
echo -e "  ${GREEN}✓ Caddy configured${NC}"

# ── Systemd service ───────────────────────────────────────────────────────────
CRYPTIRC_REG_VALUE="closed"
if [[ "$ENABLE_EMAIL" == "true" ]]; then CRYPTIRC_REG_VALUE="open"; fi

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
Environment=CRYPTIRC_BASE_PATH=/
Environment=CRYPTIRC_PORT=9001
Environment=CRYPTIRC_FROM_EMAIL=$EMAIL
Environment=CRYPTIRC_REGISTRATION=${CRYPTIRC_REG_VALUE}
Environment=CRYPTIRC_REG_CODE=$REG_CODE
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

systemctl daemon-reload
systemctl enable --now cryptirc >/dev/null 2>&1
systemctl reload-or-restart caddy >/dev/null 2>&1
echo -e "  ${GREEN}✓ Services started${NC}"

# Wait for CryptIRC to start
sleep 3
if systemctl is-active --quiet cryptirc; then
    echo -e "  ${GREEN}✓ CryptIRC is running${NC}"
else
    echo -e "  ${RED}✗ CryptIRC failed to start. Check: journalctl -u cryptirc -n 50${NC}"
fi

# ── Firewall ──────────────────────────────────────────────────────────────────
echo ""
if command -v ufw &>/dev/null; then
    echo -e "  ${DIM}Opening firewall ports (ufw)...${NC}"
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓ Ports 80 and 443 opened${NC}"
elif command -v firewall-cmd &>/dev/null; then
    echo -e "  ${DIM}Opening firewall ports (firewalld)...${NC}"
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓ Ports 80 and 443 opened${NC}"
elif command -v iptables &>/dev/null; then
    echo -e "  ${DIM}Opening firewall ports (iptables)...${NC}"
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    echo -e "  ${GREEN}✓ Ports 80 and 443 opened${NC}"
    echo -e "  ${YELLOW}⚠ iptables rules are not persistent. Install iptables-persistent or use nftables.${NC}"
fi

# ── Create first user ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Create your first user account${NC}"
echo ""
read -p "  Would you like to create a user now? (y/n): " CREATE_USER

if [[ "$CREATE_USER" =~ ^[Yy] ]]; then
    echo ""
    read -p "  Username (3-32 chars, letters/numbers/_ only): " NEW_USER
    read -p "  Email: " NEW_EMAIL
    read -sp "  Password (min 10 chars): " NEW_PASS
    echo ""

    if [[ -z "$NEW_USER" || -z "$NEW_PASS" ]]; then
        echo -e "  ${RED}Skipped — username and password required.${NC}"
    elif [[ ${#NEW_PASS} -lt 10 ]]; then
        echo -e "  ${RED}Skipped — password must be at least 10 characters.${NC}"
    else
        NEW_EMAIL="${NEW_EMAIL:-${NEW_USER}@${DOMAIN}}"
        cd "$REPO_DIR"
        bash adduser.sh "$NEW_USER" "$NEW_EMAIL" "$NEW_PASS" 2>/dev/null && {
            echo -e "  ${GREEN}✓ User '${NEW_USER}' created!${NC}"
            # Make the first user admin
            USER_FILE="$DATA_DIR/users/$(echo "$NEW_USER" | tr '[:upper:]' '[:lower:]').json"
            if [[ -f "$USER_FILE" ]]; then
                python3 -c "
import json, sys
p = sys.argv[1]
with open(p,'r') as f: d=json.load(f)
d['admin']=True
with open(p,'w') as f: json.dump(d,f,indent=2)
" "$USER_FILE" 2>/dev/null && echo -e "  ${GREEN}✓ ${NEW_USER} is now admin.${NC}"
            fi
        } || echo -e "  ${RED}✗ Failed to create user. Try manually: sudo bash adduser.sh ${NEW_USER} ${NEW_EMAIL} <password>${NC}"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}✓ CryptIRC is live!${NC}                                 ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${BOLD}URL${NC}: ${GREEN}https://${DOMAIN}${NC}"
echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"
if [[ "$ENABLE_EMAIL" == "true" ]]; then
echo -e "${CYAN}║${NC}  Registration: ${CYAN}Open${NC} (email verification)             ${CYAN}║${NC}"
else
echo -e "${CYAN}║${NC}  Registration: ${GREEN}Invite only${NC}                           ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Add users:  ${DIM}sudo bash adduser.sh <user> <email> <pass>${NC} ${CYAN}║${NC}"
fi
echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Useful commands:${NC}                                    ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ${DIM}systemctl status cryptirc${NC}                          ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ${DIM}journalctl -u cryptirc -f${NC}                          ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ${DIM}sudo bash deploy/update.sh${NC}  ${DIM}(update CryptIRC)${NC}     ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ${DIM}sudo bash adduser.sh${NC}        ${DIM}(add a user)${NC}          ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Need help? ${NC}${BOLD}irc.twistednet.org${NC} ${DIM}#dev or #twisted${NC}     ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
