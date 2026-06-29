#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CryptIRC Installer  (Debian 12 / Ubuntu 22.04+)
#
# Usage:
#   sudo bash deploy/deploy.sh                       # interactive (recommended)
#   sudo bash deploy/deploy.sh irc.example.com you@example.com   # domain + free Let's Encrypt TLS
#   sudo bash deploy/deploy.sh 203.0.113.10          # bare IP + self-signed cert (no domain needed)
#
# Pass a DOMAIN as the 1st argument for a non-interactive install (no prompts).
# Pass a bare IP as the 1st argument to install on that IP with a self-signed
# certificate. With no arguments the script walks you through everything.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors / output helpers ───────────────────────────────────────────────────
# Full styling + animation on a real terminal; auto-disabled when output is piped
# to a file/tee or when NO_COLOR is set, so logs stay clean and nothing breaks.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
    GREY='\033[0;90m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'; FANCY=true
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; GREY=''
    BOLD=''; DIM=''; NC=''; FANCY=false
fi
# The spinner hides the cursor — guarantee it comes back on any exit.
[[ "$FANCY" == true ]] && trap 'printf "\033[?25h" 2>/dev/null || true' EXIT

ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
die()  { echo -e "\n  ${RED}✗ Error:${NC} $*\n" >&2; exit 1; }

# A thin horizontal rule, clamped to a sane width.
hr() {
    local w="${COLUMNS:-0}"; [[ "$w" -lt 10 ]] && w=$(tput cols 2>/dev/null || echo 60)
    [[ "$w" -gt 60 ]] && w=60
    printf "${GREY}"; printf '─%.0s' $(seq 1 "$w"); printf "${NC}\n"
}

# A unicode progress bar: progressbar CURRENT TOTAL  (green=done, grey=remaining)
progressbar() {
    local cur="$1" tot="$2" width=22 i filled out=""
    filled=$(( cur * width / tot )); (( filled > width )) && filled=width
    out="${GREEN}"
    for ((i=0; i<width; i++)); do
        (( i == filled )) && out+="${GREY}"
        if (( i < filled )); then out+="█"; else out+="░"; fi
    done
    out+="${NC}"; printf "%b" "$out"
}

# Section header. If the title starts with [N/T] it draws an inline progress bar.
step() {
    local title="$*" n t rest bar
    echo ""
    if [[ "$title" =~ ^\[([0-9]+)/([0-9]+)\]\ (.*)$ ]]; then
        n="${BASH_REMATCH[1]}"; t="${BASH_REMATCH[2]}"; rest="${BASH_REMATCH[3]}"
        bar="$(progressbar "$n" "$t")"
        echo -e "${CYAN}${BOLD}▸ ${rest}${NC}  ${bar} ${DIM}${n}/${t}${NC}"
    else
        echo -e "${CYAN}${BOLD}▸ ${title}${NC}"
    fi
    hr
}

# Big ASCII wordmark shown once at the top.
logo() {
    echo ""
    printf "%b" "${CYAN}${BOLD}"
    cat <<'ART'
   ____                  _   ___ ____   ____
  / ___|_ __ _   _ _ __ | |_|_ _|  _ \ / ___|
 | |   | '__| | | | '_ \| __|| || |_) | |
 | |___| |  | |_| | |_) | |_ | ||  _ <| |___
  \____|_|   \__, | .__/ \__|___|_| \_\____|
             |___/|_|
ART
    printf "%b" "${NC}"
    echo -e "       ${DIM}🔒 End-to-end encrypted IRC client${NC}   ${GREY}v0.6${NC}"
}

# Animated spinner frames for run() (array → locale-safe with multibyte glyphs).
SPIN_FRAMES=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')

INSTALL_DIR="/opt/cryptirc"
DATA_DIR="/var/lib/cryptirc"
LOG_DIR="/var/log/cryptirc"
SERVICE_USER="cryptirc"
SS_DIR="/etc/caddy/selfsigned"          # self-signed cert lives here
RUN_LOG="/tmp/cryptirc-install.log"

# Run a command with an animated spinner; on failure show the last lines and stop.
# Falls back to a plain one-liner when not attached to a terminal.
# Usage: run "Doing the thing" some-command --with args
run() {
  local desc="$1"; shift
  if [[ "$FANCY" != true ]]; then
    echo "  ${desc}..."
    if ! "$@" >"$RUN_LOG" 2>&1; then
      echo "  x ${desc} failed. Last lines:" >&2
      tail -n 15 "$RUN_LOG" >&2
      die "Step failed. Full output: $RUN_LOG"
    fi
    return
  fi
  "$@" >"$RUN_LOG" 2>&1 &
  local pid=$! i=0 n=${#SPIN_FRAMES[@]}
  printf '\033[?25l'
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${CYAN}%s${NC} ${DIM}%s…${NC}\033[K" "${SPIN_FRAMES[i % n]}" "$desc"
    i=$((i+1)); sleep 0.08 || true
  done
  printf '\033[?25h'
  if wait "$pid"; then
    printf "\r  ${GREEN}✓${NC} %s\033[K\n" "$desc"
  else
    printf "\r  ${RED}✗${NC} %s\033[K\n" "$desc" >&2
    tail -n 15 "$RUN_LOG" >&2
    die "Step failed. Full output: $RUN_LOG"
  fi
}

# ── Helpers: address classification ───────────────────────────────────────────
is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ipv6() { [[ "$1" == *:* ]]; }
is_ip()   { is_ipv4 "$1" || is_ipv6 "$1"; }
# Host as it must appear in a URL / Caddy site address (IPv6 needs [brackets]).
url_host() { if is_ipv6 "$1"; then echo "[$1]"; else echo "$1"; fi; }

# ── Must be root ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root:  sudo bash deploy/deploy.sh"

# ── Banner ────────────────────────────────────────────────────────────────────
logo

# Preflight: make sure we're on the right distro family for THIS installer.
command -v apt-get &>/dev/null || die "This is the Debian/Ubuntu installer, but apt-get isn't here. On Arch, run:  sudo bash deploy/deploy-arch.sh"

# ── Step 1: where will this run? (domain vs bare IP / self-signed) ─────────────
DOMAIN="${1:-}"
EMAIL="${2:-}"
INTERACTIVE=true; [[ -n "$DOMAIN" ]] && INTERACTIVE=false
# No controlling terminal (AI assistant, CI, cloud-init, `ssh host '…'` without -t)?
# Don't prompt — an unguarded read would hit EOF and exit 1 silently under set -e.
[[ ! -t 0 ]] && INTERACTIVE=false
SELF_SIGNED=false
HOSTADDR=""

# Best-effort public IP — used as the self-signed default and the DNS hint.
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
    # Non-interactive: a bare IP → self-signed; a domain → Let's Encrypt (email required).
    if is_ip "$DOMAIN"; then
        SELF_SIGNED=true; HOSTADDR="$DOMAIN"
        echo -e "\n  ${CYAN}→ Self-signed mode on ${HOSTADDR}${NC}"
    else
        [[ -n "$EMAIL" ]] || die "Domain install needs an email:  sudo bash deploy/deploy.sh <domain> <email>"
        echo -e "  Domain : ${GREEN}${DOMAIN}${NC}"
        echo -e "  Email  : ${GREEN}${EMAIL}${NC}"
    fi
fi

URL_HOST="$(url_host "$DOMAIN")"

# ── Step 2: DNS check (domain mode only) ──────────────────────────────────────
if [[ "$SELF_SIGNED" == false ]]; then
    step "[2/6] Checking DNS"

    check_dns() {   # resolves A and AAAA, dig → host → getent
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

# ── Step 3: registration & access ─────────────────────────────────────────────
# Each setting is its own question with a sensible default — press Enter to take it.
# Email is OPTIONAL (v0.3.6+): open registration is protected by the built-in
# captcha, so a mail server is only needed for email verification or password
# resets. email_required + captcha_enabled have no env var, so they're seeded into
# admin_settings.json (Step 4). Everything here is also changeable later in the
# Admin panel.
step "[3/6] Registration & access"
REG_OPEN=false           # open sign-up vs invite-only
ENABLE_EMAIL=false       # configure Postfix (email sending) — only if needed
EMAIL_REQUIRED=false     # require email verification to register
CAPTCHA_ENABLED=true     # signup captcha (default on)
REG_CODE=""
SETTINGS_KEPT=false

if [[ -f "$DATA_DIR/admin_settings.json" ]]; then
    # Re-run over an existing install: keep the operator's current settings rather than
    # silently overwriting them. Skip the questions — they'd be ignored anyway, since the
    # app treats admin_settings.json as the source of truth — and say so plainly.
    SETTINGS_KEPT=true
    echo -e "  ${DIM}Existing admin_settings.json found — keeping your current registration / email / captcha settings (change them in Settings → Admin).${NC}"
elif [[ "$INTERACTIVE" == true ]]; then
    read -rp "  Allow open registration (anyone can sign up)? [y/N]: " WANT_OPEN
    if [[ "$WANT_OPEN" =~ ^[Yy] ]]; then
        REG_OPEN=true
        read -rp "  Require a registration code? [y/N]: " WANT_CODE
        if [[ "$WANT_CODE" =~ ^[Yy] ]]; then
            # Loop until a non-blank code is entered — a blank one would silently
            # mean "no gate", the opposite of what they just asked for.
            while [[ -z "$REG_CODE" ]]; do
                read -rp "    Registration code (cannot be blank): " REG_CODE
                [[ -z "$REG_CODE" ]] && echo -e "  ${DIM}A blank code means no gate — type one, or Ctrl-C to abort.${NC}"
            done
        fi
        if [[ "$SELF_SIGNED" == true ]]; then
            # No domain → outbound mail from a bare IP won't deliver reliably, so
            # email verification/resets are off here; the captcha protects sign-up.
            echo -e "  ${DIM}No domain set — sign-up is captcha-protected with no email (verification/resets need a domain).${NC}"
        else
            read -rp "  Require email verification to register? [y/N]: " WANT_REQ_EMAIL
            if [[ "$WANT_REQ_EMAIL" =~ ^[Yy] ]]; then
                EMAIL_REQUIRED=true
                ENABLE_EMAIL=true   # verification can't work without a mail server
                echo -e "  ${CYAN}→ Email required — Postfix will be configured.${NC}"
            else
                read -rp "  Set up email sending (enables password resets)? [y/N]: " WANT_EMAIL
                [[ "$WANT_EMAIL" =~ ^[Yy] ]] && ENABLE_EMAIL=true
            fi
        fi
        read -rp "  Enable the signup captcha? [Y/n]: " WANT_CAPTCHA
        [[ "$WANT_CAPTCHA" =~ ^[Nn] ]] && CAPTCHA_ENABLED=false
        _em="off"; [[ "$ENABLE_EMAIL" == true ]] && _em="optional"; [[ "$EMAIL_REQUIRED" == true ]] && _em="required"
        _cap="on"; [[ "$CAPTCHA_ENABLED" == false ]] && _cap="off"
        echo -e "  ${GREEN}→ Open registration${NC} ${DIM}(code: $([[ -n "$REG_CODE" ]] && echo set || echo none) · email: ${_em} · captcha: ${_cap})${NC}"
    else
        echo -e "  ${GREEN}→ Invite only.${NC} ${DIM}Create accounts with adduser.sh.${NC}"
    fi
else
    echo -e "  ${GREEN}→ Invite only${NC} ${DIM}(default for non-interactive installs; add users with adduser.sh)${NC}"
fi

# ── Step 4: dependencies ──────────────────────────────────────────────────────
step "[4/6] Installing dependencies"
export DEBIAN_FRONTEND=noninteractive
run "Updating package lists" apt-get update -qq
run "Installing system packages" apt-get install -y --no-install-recommends \
    curl ca-certificates git build-essential pkg-config \
    openssl libssl-dev python3 python3-pip dnsutils ffmpeg gnupg \
    debian-keyring debian-archive-keyring apt-transport-https

# argon2 (used by adduser.sh)
pip3 install argon2-cffi --quiet --break-system-packages 2>/dev/null \
    || pip3 install argon2-cffi --quiet 2>/dev/null || true

if [[ "$ENABLE_EMAIL" == true ]]; then
    run "Installing Postfix" apt-get install -y postfix
fi
ok "System packages installed"

# Rust
if ! command -v rustc &>/dev/null; then
    echo -e "  ${DIM}Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable >/dev/null 2>&1
    source "$HOME/.cargo/env"
    ok "Rust installed"
else
    ok "Rust already installed: $(rustc --version)"
fi

# Caddy
if ! command -v caddy &>/dev/null; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    run "Updating package lists for Caddy" apt-get update -qq
    run "Installing Caddy" apt-get install -y caddy
    ok "Caddy installed"
else
    ok "Caddy already installed"
fi

# Postfix config (open registration only)
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
    # `enable --now` is a no-op if postfix's postinst already started it with stale
    # config; reload (or restart) so the new myhostname/myorigin actually take effect.
    systemctl reload postfix >/dev/null 2>&1 || systemctl restart postfix >/dev/null 2>&1 || true
    ok "Postfix configured"
    warn "Heads up: email is sent straight from this server, so messages can land in spam"
    echo -e "    ${DIM}or be rejected until you add DNS — a PTR/reverse-DNS record for this IP, an SPF${NC}"
    echo -e "    ${DIM}record, and DKIM signing. A blacklisted VPS IP may be blocked outright; for${NC}"
    echo -e "    ${DIM}reliable delivery, relay Postfix through a provider (Gmail / SES / SendGrid).${NC}"
fi

# Service user + directories
id "$SERVICE_USER" &>/dev/null || useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR" /var/log/caddy
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"

# Seed admin_settings.json — the authoritative config the Admin panel also edits.
# email_required + captcha_enabled have NO env var, so this is the only way to set
# them at install. Written only on a fresh install; an existing file (e.g. an
# operator's later Admin-panel changes) is never clobbered.
SETTINGS_FILE="$DATA_DIR/admin_settings.json"
if [[ ! -f "$SETTINGS_FILE" ]]; then
    # Write via python3 (already a dependency) so the reg code is correctly JSON-encoded
    # for ANY input — control chars, quotes, unicode — and the file is always valid JSON.
    # An invalid file would make the server silently fall back to open, codeless registration.
    CRYPTIRC_S_OPEN="$REG_OPEN" CRYPTIRC_S_CODE="$REG_CODE" \
    CRYPTIRC_S_EMAILREQ="$EMAIL_REQUIRED" CRYPTIRC_S_CAPTCHA="$CAPTCHA_ENABLED" \
    python3 - "$SETTINGS_FILE" <<'PY'
import json, os, sys
b = lambda v: v == "true"
data = {
    "registration_open": b(os.environ["CRYPTIRC_S_OPEN"]),
    "registration_code": os.environ["CRYPTIRC_S_CODE"],
    "email_required":    b(os.environ["CRYPTIRC_S_EMAILREQ"]),
    "captcha_enabled":   b(os.environ["CRYPTIRC_S_CAPTCHA"]),
}
with open(sys.argv[1], "w") as f:
    json.dump(data, f, indent=2)
PY
    chown "$SERVICE_USER:$SERVICE_USER" "$SETTINGS_FILE"
    chmod 600 "$SETTINGS_FILE"
    ok "Admin settings seeded (registration · email · captcha)"
else
    echo -e "  ${DIM}admin_settings.json exists — keeping current settings.${NC}"
fi

# Caddy runs as the 'caddy' user and writes its access log here; make sure it can.
chown caddy:caddy /var/log/caddy 2>/dev/null || true

# ── Step 5: build ─────────────────────────────────────────────────────────────
step "[5/6] Building CryptIRC"
echo -e "  ${DIM}First build takes 3-5 minutes. Please wait.${NC}\n"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"
source "$HOME/.cargo/env" 2>/dev/null || true
if ! cargo build --release; then
    die "Build failed (see output above). Common causes: low RAM (need ~1 GB free — add swap) or missing libssl-dev."
fi
[[ -f target/release/cryptirc ]] || die "Build reported success but target/release/cryptirc is missing."
install -m 755 -o root -g root target/release/cryptirc "$INSTALL_DIR/cryptirc"
ok "CryptIRC built and installed"

# ── Step 6: configure TLS + service ───────────────────────────────────────────
step "[6/6] Configuring services"

[[ -f /etc/caddy/Caddyfile ]] && cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)" \
    && warn "Existing Caddyfile backed up to /etc/caddy/Caddyfile.bak.*"

if [[ "$SELF_SIGNED" == true ]]; then
    # Generate a self-signed cert (10 yrs) with the right SAN — IP: for an IP,
    # DNS: for a hostname (modern browsers ignore CN, so the SAN is what matters).
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
    reverse_proxy 127.0.0.1:9001 {
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
    reverse_proxy 127.0.0.1:9001 {
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

# systemd unit. For self-signed/IP, HSTS is turned OFF — otherwise the browser
# would refuse the cert-warning click-through and lock everyone out for 2 years.
CRYPTIRC_REG_VALUE="closed"; [[ "$REG_OPEN" == true ]] && CRYPTIRC_REG_VALUE="open"
HSTS_VALUE="on";            [[ "$SELF_SIGNED" == true ]] && HSTS_VALUE="off"
FROM_EMAIL="${EMAIL:-noreply@localhost}"
# Escape the reg code for systemd's Environment="K=v" quoting (admin_settings.json
# is authoritative; this env var is only a fallback, but keep the unit file valid).
REG_CODE_SYSTEMD=$(printf '%s' "$REG_CODE" | sed 's/\\/\\\\/g; s/"/\\"/g')

cat > /etc/systemd/system/cryptirc.service <<UNIT
[Unit]
Description=CryptIRC — Encrypted IRC Client
After=network-online.target caddy.service
Wants=network-online.target
# Crash-loop guard. The correct location in modern systemd is [Unit]; the
# legacy [Service] StartLimitInterval=/StartLimitBurst= spelling is deprecated.
StartLimitIntervalSec=60
StartLimitBurst=5

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
# Files/dirs the service creates default to 0600/0700 (matches the at-rest
# secrets hardening), even if a code path forgets to chmod.
UMask=0077

Environment=CRYPTIRC_DATA=$DATA_DIR
Environment="CRYPTIRC_BASE_URL=https://$URL_HOST"
Environment=CRYPTIRC_BASE_PATH=/
Environment=CRYPTIRC_PORT=9001
Environment="CRYPTIRC_FROM_EMAIL=$FROM_EMAIL"
Environment=CRYPTIRC_REGISTRATION=${CRYPTIRC_REG_VALUE}
Environment="CRYPTIRC_REG_CODE=$REG_CODE_SYSTEMD"
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
# The unit holds the registration code — keep it out of world-readable view.
chmod 640 /etc/systemd/system/cryptirc.service

systemctl daemon-reload
systemctl enable cryptirc >/dev/null 2>&1 || true           # start on boot
# Use `restart`, NOT `enable --now`: `--now` only does a `start`, which is a no-op
# if the unit is already active. Re-running this installer on a live system installs
# the new binary on disk but the old process keeps running the old (now-unlinked)
# inode — so without an explicit restart the update silently never takes effect.
# `restart` starts it on a fresh install and swaps in the new binary on a re-run.
systemctl restart cryptirc >/dev/null 2>&1 || true          # don't abort — the check below reports real status
systemctl enable caddy >/dev/null 2>&1 || true              # persist across reboot (pacman/some setups don't auto-enable)
systemctl reload-or-restart caddy  >/dev/null 2>&1 || true
ok "Services started"

sleep 3
if systemctl is-active --quiet cryptirc; then
    ok "CryptIRC is running"
    SERVICE_OK=true
else
    warn "CryptIRC isn't active yet. Check:  journalctl -u cryptirc -n 50 --no-pager"
    SERVICE_OK=false
fi
if ! systemctl is-active --quiet caddy; then
    warn "Caddy (reverse proxy) isn't active. Check:  journalctl -u caddy -n 50 --no-pager"
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
    warn "iptables rules aren't persistent — install iptables-persistent to keep them across reboots."
fi

# ── First user (interactive only) ─────────────────────────────────────────────
if [[ "$INTERACTIVE" == true ]]; then
    echo ""
    echo -e "${BOLD}Create your first user (admin)${NC}\n"
    read -rp "  Would you like to create a user now? (y/N): " CREATE_USER
    if [[ "$CREATE_USER" =~ ^[Yy] ]]; then
        read -rp  "  Username (3-32 chars; letters, numbers, _ and -): " NEW_USER
        read -rp  "  Email (optional — Enter to skip): " NEW_EMAIL
        read -rsp "  Password (min 10 chars): " NEW_PASS; echo ""
        if [[ -z "$NEW_USER" || -z "$NEW_PASS" ]]; then
            warn "Skipped — username and password are required."
        elif [[ ${#NEW_PASS} -lt 10 ]]; then
            warn "Skipped — password must be at least 10 characters."
        else
            # Pass the password via env (NOT argv) so it never shows in ps / /proc.
            if CRYPTIRC_NEW_PASS="$NEW_PASS" bash "$REPO_DIR/adduser.sh" "$NEW_USER" "$NEW_EMAIL" >"$RUN_LOG" 2>&1; then
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
if [[ "$SERVICE_OK" == true ]]; then
echo -e "${CYAN}║${NC}  ${GREEN}✓ CryptIRC is live!${NC}"
else
echo -e "${CYAN}║${NC}  ${YELLOW}⚠ Installed — but the service isn't running yet.${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Check: journalctl -u cryptirc -n 50 --no-pager${NC}"
fi
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  ${BOLD}URL${NC}: ${GREEN}https://${URL_HOST}${NC}"
if [[ "$SELF_SIGNED" == true ]]; then
echo -e "${CYAN}║${NC}  ${YELLOW}Self-signed cert:${NC} your browser shows a one-time warning."
echo -e "${CYAN}║${NC}  ${DIM}Click \"Advanced\" → \"Proceed\" — that's expected & safe.${NC}"
fi
if [[ "$SETTINGS_KEPT" == true ]]; then
    echo -e "${CYAN}║${NC}  Registration: ${DIM}unchanged (existing settings kept — change in Settings → Admin)${NC}"
elif [[ "$REG_OPEN" == true ]]; then
    _rnote="captcha-protected"; [[ "$CAPTCHA_ENABLED" == false ]] && _rnote="no captcha"
    if [[ "$EMAIL_REQUIRED" == true ]]; then _rdesc="email verification required"
    elif [[ "$ENABLE_EMAIL" == true ]]; then _rdesc="email optional · ${_rnote}"
    else _rdesc="${_rnote}"; fi
    echo -e "${CYAN}║${NC}  Registration: ${CYAN}Open${NC} (${_rdesc})"
    [[ -n "$REG_CODE" ]] && echo -e "${CYAN}║${NC}  ${DIM}Sign-up also requires your registration code.${NC}"
else
echo -e "${CYAN}║${NC}  Registration: ${GREEN}Invite only${NC}"
echo -e "${CYAN}║${NC}  Add users: ${DIM}sudo CRYPTIRC_NEW_PASS=pw bash adduser.sh <user> [email]${NC}"
fi
echo -e "${CYAN}║${NC}"
if [[ "$ENABLE_EMAIL" == true ]]; then
echo -e "${CYAN}║${NC}  ${YELLOW}Email${NC}${DIM} can spam-folder until you set up SPF/DKIM/PTR (see notes above).${NC}"
fi
echo -e "${CYAN}║${NC}  ${DIM}status:  systemctl status cryptirc${NC}"
echo -e "${CYAN}║${NC}  ${DIM}logs:    journalctl -u cryptirc -f${NC}"
echo -e "${CYAN}║${NC}  ${DIM}update:  sudo bash deploy/update.sh${NC}"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Help:${NC} ${BOLD}irc.twistednet.org${NC} ${DIM}#dev / #twisted${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
