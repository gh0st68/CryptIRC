#!/usr/bin/env bash
# CryptIRC update script — backs up data, rebuilds, and hot-swaps the binary
# Usage: sudo bash deploy/update.sh [--no-backup] [--restart-daemon]
#
# By default, creates a timestamped backup of all user data before updating.
# Pass --no-backup to skip the backup step.
#
# irc-core (the always-on IRC connection daemon — see deploy/irc-core.service)
# is intentionally NOT restarted by an ordinary update: that's the whole point
# of the daemon split — routine code-only redeploys of cryptirc.service no
# longer drop anyone's IRC connection. The irc_core binary on disk IS still
# refreshed on every run, so the new code takes effect next time the daemon
# itself restarts. Pass --restart-daemon to also bounce it now (rare — only
# needed when irc_core.rs/ipc*.rs actually changed).

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

INSTALL_DIR="/opt/cryptirc"
DATA_DIR="/var/lib/cryptirc"
BACKUP_DIR="/var/lib/cryptirc-backups"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

SKIP_BACKUP=false
RESTART_DAEMON=false
for arg in "$@"; do
    case "$arg" in
        --no-backup)      SKIP_BACKUP=true ;;
        --restart-daemon) RESTART_DAEMON=true ;;
    esac
done

# Safety net for the window between "we stopped cryptirc" and "we successfully
# started it again" — if the script is interrupted anywhere in that window
# (SSH drop, Ctrl-C, OOM), cryptirc would otherwise be left stopped with
# nothing to bring it back (Restart=on-failure doesn't apply to a service
# that was never (re)started, only one that crashes after starting). On a
# normal successful run this is a no-op: by the time the script exits,
# cryptirc is already active, so the check below sees nothing to do.
CRYPTIRC_STOPPED_BY_US=false
_recover_on_exit() {
    if [[ "$CRYPTIRC_STOPPED_BY_US" == "true" ]] && ! systemctl is-active --quiet cryptirc; then
        echo -e "\n  ${YELLOW}⚠ Script exiting with cryptirc stopped — attempting a best-effort restart so the site isn't left down...${NC}" >&2
        systemctl start cryptirc 2>/dev/null || true
    fi
}
trap _recover_on_exit EXIT

# ── Backup ────────────────────────────────────────────────────────────────────
if [[ "$SKIP_BACKUP" == "false" ]]; then
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/cryptirc-backup-${TIMESTAMP}.tar.gz"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    echo -e "${BOLD}Backing up data...${NC}"
    # The backup bundles Argon2 hashes, vaults and admin_settings (reg code) — create it
    # 0600 (umask), not world-readable. And a FAILED backup must ABORT: it's the only
    # safety net before we swap the binary, so continuing would defeat its whole purpose.
    # --exclude the irc-core IPC socket: it's a live endpoint, not user data, and
    # GNU tar exits 1 (not 0) when it has to skip a socket ("socket ignored"),
    # which this script would otherwise misread as a real backup failure.
    if (umask 0077; tar czf "$BACKUP_FILE" --exclude='irc-core.sock' -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")" 2>/dev/null); then
        BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
        echo -e "  ${GREEN}✓ Backup saved:${NC} $BACKUP_FILE (${BACKUP_SIZE})"
    else
        rm -f "$BACKUP_FILE"
        echo -e "  ${RED}✗ Backup failed — aborting update; nothing was changed.${NC}"
        echo -e "  ${DIM}Check free space (df -h /var/lib) and that /var/lib/cryptirc exists, then retry.${NC}"
        exit 1
    fi

    # Keep only the last 5 backups
    ls -1t "$BACKUP_DIR"/cryptirc-backup-*.tar.gz 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/cryptirc-backup-*.tar.gz 2>/dev/null | wc -l)
    echo -e "  ${DIM}(${BACKUP_COUNT} backups kept, older ones pruned)${NC}"
    echo ""
fi

# ── Pull latest code ──────────────────────────────────────────────────────────
echo -e "${BOLD}Pulling latest code...${NC}"
cd "$REPO_DIR"
git pull --ff-only 2>&1 || {
    echo -e "  ${YELLOW}⚠ git pull failed — building from current code${NC}"
}
echo ""

# ── Build ─────────────────────────────────────────────────────────────────────
echo -e "${BOLD}Building new binary...${NC}"
# This script runs under sudo, where $HOME is root's home — but cargo may have
# been installed by deploy.sh (as root, so /root/.cargo is correct) OR by a
# human dev account via rustup directly (so it lives under that user's home
# instead). rustup's own env script isn't self-locating (it trusts $HOME
# internally, so merely sourcing the right file under the wrong $HOME still
# resolves to the wrong bin dir) and its proxy binaries also need
# RUSTUP_HOME/CARGO_HOME to find the toolchain config — so set all three
# explicitly per candidate rather than sourcing anything.
if ! command -v cargo &>/dev/null; then
    for home in "/root" "$HOME" "${SUDO_USER:+/home/$SUDO_USER}"; do
        if [[ -n "$home" && -x "$home/.cargo/bin/cargo" ]]; then
            export CARGO_HOME="$home/.cargo" RUSTUP_HOME="$home/.rustup" PATH="$home/.cargo/bin:$PATH"
            command -v cargo &>/dev/null && break
        fi
    done
fi
BUILD_LOG=$(mktemp "${TMPDIR:-/tmp}/cryptirc-build.XXXXXX")   # mktemp: unpredictable name, no symlink-follow
if ! cargo build --release 2>&1 | tee "$BUILD_LOG" | tail -5; then
    echo -e "  ${RED}✗ Build failed — the service was NOT touched. First errors:${NC}"
    grep -m3 -E '^error' "$BUILD_LOG" || tail -20 "$BUILD_LOG"
    rm -f "$BUILD_LOG"; exit 1
fi
rm -f "$BUILD_LOG"
# Guard the build-succeeded-but-no-binary case (e.g. an upstream bin rename) BEFORE we
# stop the service — matches deploy.sh. A cp on a missing source would leave it down.
[[ -f target/release/cryptirc ]] || { echo -e "  ${RED}✗ Build reported success but target/release/cryptirc is missing — aborting; service untouched.${NC}"; exit 1; }
# irc_core is only built once the daemon-split has landed on this checkout —
# older commits won't produce it, so its absence isn't fatal (nothing to swap).
HAVE_IRC_CORE=false
[[ -f target/release/irc_core ]] && HAVE_IRC_CORE=true
echo ""

# Does this box already have the irc-core unit installed? Two very different
# cases hang off this:
#   • unit present  → routine split-architecture update (the common path).
#   • unit ABSENT but we just built an irc_core binary → this is a PRE-SPLIT
#     install being updated across the daemon cutover. The new cryptirc binary
#     no longer dials IRC itself; it REQUIRES the daemon. Simply swapping the
#     binary here without installing+starting irc-core.service would leave the
#     web UI up but every user's IRC dead (the web process would spin forever
#     dialing a socket nobody serves). That exact gap is handled by the
#     one-time migration block further down (see "Migrate a pre-split install").
HAVE_IRC_CORE_UNIT=false
systemctl cat irc-core.service &>/dev/null && HAVE_IRC_CORE_UNIT=true

# ── Stop service(s) ──────────────────────────────────────────────────────────
echo -e "${BOLD}Stopping CryptIRC...${NC}"
if systemctl is-active --quiet cryptirc; then
    systemctl stop cryptirc
    CRYPTIRC_STOPPED_BY_US=true
    echo -e "  ${GREEN}✓ CryptIRC stopped${NC}"
else
    echo -e "  ${YELLOW}⚠ CryptIRC was not running${NC}"
fi
if [[ "$RESTART_DAEMON" == "true" && "$HAVE_IRC_CORE_UNIT" == "true" ]]; then
    if systemctl is-active --quiet irc-core; then
        systemctl stop irc-core
        echo -e "  ${GREEN}✓ irc-core stopped${NC} ${DIM}(--restart-daemon passed — every connected user's IRC session will drop and reconnect)${NC}"
    else
        echo -e "  ${YELLOW}⚠ irc-core was not running${NC}"
    fi
elif [[ "$HAVE_IRC_CORE_UNIT" == "true" ]]; then
    echo -e "  ${DIM}irc-core left running (pass --restart-daemon to also update/restart it) — no IRC connections will drop${NC}"
fi
echo ""

# ── Swap binary(ies) ─────────────────────────────────────────────────────────
# Atomic write-then-rename, not a plain cp: cryptirc.service was just stopped
# above so its binary is normally free, but irc-core is deliberately LEFT
# RUNNING when --restart-daemon isn't passed — its executable is still
# memory-mapped by the live process, and a plain cp to overwrite it in place
# fails with "Text file busy" (hit this for real on the first production use
# of this script). `mv` just repoints the directory entry to a new inode,
# which the kernel allows even while the old inode is still open/executing.
echo -e "${BOLD}Installing new binary...${NC}"
cp target/release/cryptirc "$INSTALL_DIR/cryptirc.new"
chmod 755 "$INSTALL_DIR/cryptirc.new"
chown root:root "$INSTALL_DIR/cryptirc.new"
mv -f "$INSTALL_DIR/cryptirc.new" "$INSTALL_DIR/cryptirc"
echo -e "  ${GREEN}✓ Binary updated${NC}"
if [[ "$HAVE_IRC_CORE" == "true" ]]; then
    # Refreshed on disk every run regardless of --restart-daemon, so the new
    # code is already in place the next time the daemon itself restarts.
    cp target/release/irc_core "$INSTALL_DIR/irc_core.new"
    chmod 755 "$INSTALL_DIR/irc_core.new"
    chown root:root "$INSTALL_DIR/irc_core.new"
    mv -f "$INSTALL_DIR/irc_core.new" "$INSTALL_DIR/irc_core"
    echo -e "  ${GREEN}✓ irc_core binary updated on disk${NC}"
fi
echo ""

# ── Migrate a pre-split install to the daemon architecture ───────────────────
# The single most important safety step for anyone updating from an OLD build.
# An install created before the irc-core daemon split runs one cryptirc.service
# that dialed IRC directly. The new cryptirc binary does NOT dial IRC anymore —
# it hands every connection to irc-core over a Unix socket. So on such a box we
# must install AND start irc-core.service as part of this update, BEFORE the new
# cryptirc starts, or the web UI comes up with every user's IRC permanently
# dead. Trigger: we built an irc_core binary (new code) but this box has no
# irc-core unit yet. Idempotent — on an already-split box HAVE_IRC_CORE_UNIT is
# true and this whole block is skipped.
MIGRATED_TO_DAEMON=false
if [[ "$HAVE_IRC_CORE" == "true" && "$HAVE_IRC_CORE_UNIT" == "false" ]]; then
    echo -e "${BOLD}Migrating to the irc-core daemon...${NC}"
    echo -e "  ${DIM}This install predates the persistent-connection daemon. Installing"
    echo -e "  irc-core.service so IRC keeps working. Existing IRC sessions drop once"
    echo -e "  during this update, then reconnect — future updates won't drop them.${NC}"

    # Mirror the EXISTING install's data dir, service user/group AND (if set) its
    # custom IPC socket path, instead of assuming defaults — so a box set up with
    # non-standard paths still migrates correctly. INSTALL_DIR is where we just
    # placed the irc_core binary, so the unit's ExecStart uses it directly.
    MIG_DATA=$(systemctl show cryptirc.service -p Environment --value 2>/dev/null | tr ' ' '\n' | grep -m1 '^CRYPTIRC_DATA=' | cut -d= -f2 || true)
    MIG_DATA="${MIG_DATA:-$DATA_DIR}"
    # The web process resolves its socket as CRYPTIRC_IPC_SOCK first, only then
    # $CRYPTIRC_DATA/irc-core.sock (src/main.rs). If the legacy web unit pins a
    # custom socket path, the daemon MUST bind that same path or they'd never
    # meet — so carry it through verbatim (empty → daemon uses the data-dir default).
    MIG_IPC_SOCK=$(systemctl show cryptirc.service -p Environment --value 2>/dev/null | tr ' ' '\n' | grep -m1 '^CRYPTIRC_IPC_SOCK=' | cut -d= -f2 || true)
    # Service user/group: `systemctl show -p User --value` returns the literal
    # "root" (systemd's default) when the unit has no User= line, NOT an empty
    # string — so we can't distinguish "explicitly root" from "unset", and that's
    # fine: mirror whatever the web process actually runs as, INCLUDING root, so
    # the daemon can always write the socket into the data dir and the web
    # process can always open it (same uid). Only if systemd somehow reports
    # nothing do we fall back to the data dir's actual owner (the user that
    # provably can create files there), then to "cryptirc" as a last resort.
    MIG_USER=$(systemctl show cryptirc.service -p User --value 2>/dev/null || true)
    MIG_GROUP=$(systemctl show cryptirc.service -p Group --value 2>/dev/null || true)
    [[ -z "$MIG_USER" ]] && MIG_USER=$(stat -c %U "$MIG_DATA" 2>/dev/null || true)
    [[ -z "$MIG_USER" ]] && MIG_USER=cryptirc
    [[ -z "$MIG_GROUP" ]] && MIG_GROUP=$(stat -c %G "$MIG_DATA" 2>/dev/null || true)
    [[ -z "$MIG_GROUP" ]] && MIG_GROUP="$MIG_USER"
    # Only emit an Environment=CRYPTIRC_IPC_SOCK line when the legacy unit had one.
    MIG_IPC_SOCK_LINE=""
    [[ -n "$MIG_IPC_SOCK" ]] && MIG_IPC_SOCK_LINE="Environment=CRYPTIRC_IPC_SOCK=$MIG_IPC_SOCK"

    cat > /etc/systemd/system/irc-core.service <<UNIT
[Unit]
Description=irc-core — persistent IRC connection daemon for CryptIRC
Documentation=https://github.com/gh0st68/CryptIRC
After=network-online.target
Wants=network-online.target
Before=cryptirc.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=$MIG_USER
Group=$MIG_GROUP
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/irc_core
ExecStop=/bin/kill -s TERM \$MAINPID
TimeoutStopSec=30
KillMode=mixed
Restart=on-failure
RestartSec=5
UMask=0077

Environment=CRYPTIRC_DATA=$MIG_DATA
$MIG_IPC_SOCK_LINE
Environment=RUST_LOG=info

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$MIG_DATA
ProtectHome=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
ProtectClock=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectHostname=true
LimitNOFILE=4096
LimitNPROC=64

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable irc-core >/dev/null 2>&1 || true
    systemctl restart irc-core >/dev/null 2>&1 || true

    # Health-check the SAME socket path the daemon will actually bind: the custom
    # CRYPTIRC_IPC_SOCK if the legacy unit pinned one, else CRYPTIRC_DATA/irc-core.sock.
    # Wait for it to actually appear — proof the daemon bound its listener, not
    # merely that the process forked — before we start the web service.
    MIG_SOCK="${MIG_IPC_SOCK:-${MIG_DATA%/}/irc-core.sock}"
    MIG_HEALTHY=false
    for _ in $(seq 1 10); do
        if systemctl is-active --quiet irc-core && [[ -S "$MIG_SOCK" ]]; then MIG_HEALTHY=true; break; fi
        sleep 1
    done
    if [[ "$MIG_HEALTHY" == "true" ]]; then
        HAVE_IRC_CORE_UNIT=true
        MIGRATED_TO_DAEMON=true
        echo -e "  ${GREEN}✓ irc-core daemon installed, enabled and running${NC}"
    else
        # Don't abort: a running web UI (even with IRC temporarily down) beats
        # leaving the whole site dead. But make the failure impossible to miss —
        # IRC will not work until the daemon comes up.
        echo -e "  ${RED}✗ irc-core was installed but failed to start — check: journalctl -u irc-core -n 50${NC}"
        echo -e "  ${YELLOW}⚠ The site will still load, but IRC connections stay down until the daemon runs.${NC}"
    fi
    echo ""
fi

# ── Start service(s) ─────────────────────────────────────────────────────────
# Skip when we just migrated: the migration block already installed, started and
# health-checked irc-core, so re-running the daemon start here would be a no-op
# that misleadingly reprints "Starting irc-core..." for a box that never had it.
if [[ "$RESTART_DAEMON" == "true" && "$HAVE_IRC_CORE_UNIT" == "true" && "$MIGRATED_TO_DAEMON" == "false" ]]; then
    echo -e "${BOLD}Starting irc-core...${NC}"
    systemctl start irc-core
    # irc-core has no HTTP endpoint, so the functional signal here is its IPC
    # socket actually existing (proof it got far enough to bind its listener,
    # not just that the process forked) — derived the same way the daemon
    # itself derives it, from CRYPTIRC_DATA/CRYPTIRC_IPC_SOCK in its unit.
    IRC_CORE_SOCK=$(systemctl show irc-core.service -p Environment --value | tr ' ' '\n' | grep -m1 '^CRYPTIRC_IPC_SOCK=' | cut -d= -f2 || true)
    if [[ -z "$IRC_CORE_SOCK" ]]; then
        IRC_CORE_DATA=$(systemctl show irc-core.service -p Environment --value | tr ' ' '\n' | grep -m1 '^CRYPTIRC_DATA=' | cut -d= -f2 || true)
        IRC_CORE_SOCK="${IRC_CORE_DATA:-/var/lib/cryptirc}/irc-core.sock"
    fi
    IRC_CORE_HEALTHY=false
    for _ in $(seq 1 10); do
        if systemctl is-active --quiet irc-core && [[ -S "$IRC_CORE_SOCK" ]]; then
            IRC_CORE_HEALTHY=true
            break
        fi
        sleep 1
    done
    if [[ "$IRC_CORE_HEALTHY" == "true" ]]; then
        echo -e "  ${GREEN}✓ irc-core started${NC}"
    else
        # --restart-daemon was explicitly requested (presumably because
        # irc_core.rs/ipc*.rs actually changed) — silently continuing to
        # bring up cryptirc against a dead daemon would report "Update
        # complete!" while every user's IRC connections stay unreconciled.
        echo -e "  ${RED}✗ irc-core failed to start or its IPC socket never appeared — check: journalctl -u irc-core -n 50${NC}"
        echo -e "  ${RED}✗ Aborting — cryptirc was not started against a dead daemon.${NC}"
        exit 1
    fi
    echo ""
fi

echo -e "${BOLD}Starting CryptIRC...${NC}"
systemctl start cryptirc
# `systemctl is-active` only proves the process didn't immediately exit — it
# says nothing about whether it actually bound its port and can serve a
# request. Poll the real HTTP endpoint (extracting port/base-path from the
# unit's own environment, since this script doesn't set them itself) for up
# to 10s before declaring success; a service that starts but panics a few
# seconds later, or binds but deadlocks, is caught here instead of reported
# as healthy.
CRYPTIRC_HEALTH_PORT=$(systemctl show cryptirc.service -p Environment --value | tr ' ' '\n' | grep -m1 '^CRYPTIRC_PORT=' | cut -d= -f2 || true)
CRYPTIRC_HEALTH_PATH=$(systemctl show cryptirc.service -p Environment --value | tr ' ' '\n' | grep -m1 '^CRYPTIRC_BASE_PATH=' | cut -d= -f2 || true)
CRYPTIRC_HEALTHY=false
for _ in $(seq 1 10); do
    if systemctl is-active --quiet cryptirc \
        && curl -sf -o /dev/null --max-time 2 "http://127.0.0.1:${CRYPTIRC_HEALTH_PORT:-9001}${CRYPTIRC_HEALTH_PATH:-/}"; then
        CRYPTIRC_HEALTHY=true
        break
    fi
    sleep 1
done
if [[ "$CRYPTIRC_HEALTHY" == "true" ]]; then
    echo -e "  ${GREEN}✓ CryptIRC restarted successfully${NC}"
else
    echo -e "  ${RED}✗ CryptIRC failed to start or isn't responding — check: journalctl -u cryptirc -n 50${NC}"
    if [[ "$SKIP_BACKUP" == "false" && -f "$BACKUP_FILE" ]]; then
        echo ""
        echo -e "  ${YELLOW}To restore from backup:${NC}"
        echo -e "    sudo systemctl stop cryptirc"
        echo -e "    sudo tar xzf $BACKUP_FILE -C /var/lib"
        echo -e "    sudo systemctl start cryptirc"
    fi
    exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}Update complete!${NC}"
if [[ "$MIGRATED_TO_DAEMON" == "true" ]]; then
    echo -e "  ${DIM}Migrated to the irc-core daemon — this was a one-time reconnect. From now"
    echo -e "  on, routine updates swap only the web binary and won't drop IRC connections.${NC}"
fi
