#!/usr/bin/env bash
# CryptIRC update script — backs up data, rebuilds, and hot-swaps the binary
# Usage: sudo bash deploy/update.sh [--no-backup]
#
# By default, creates a timestamped backup of all user data before updating.
# Pass --no-backup to skip the backup step.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

INSTALL_DIR="/opt/cryptirc"
DATA_DIR="/var/lib/cryptirc"
BACKUP_DIR="/var/lib/cryptirc-backups"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

SKIP_BACKUP=false
if [[ "${1:-}" == "--no-backup" ]]; then SKIP_BACKUP=true; fi

# ── Backup ────────────────────────────────────────────────────────────────────
if [[ "$SKIP_BACKUP" == "false" ]]; then
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/cryptirc-backup-${TIMESTAMP}.tar.gz"
    mkdir -p "$BACKUP_DIR"

    echo -e "${BOLD}Backing up data...${NC}"
    tar czf "$BACKUP_FILE" -C /var/lib cryptirc 2>/dev/null && {
        BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
        echo -e "  ${GREEN}✓ Backup saved:${NC} $BACKUP_FILE (${BACKUP_SIZE})"
    } || {
        echo -e "  ${YELLOW}⚠ Backup failed — continuing anyway${NC}"
    }

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
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release 2>&1 | tail -5
echo ""

# ── Stop service ─────────────────────────────────────────────────────────────
echo -e "${BOLD}Stopping CryptIRC...${NC}"
if systemctl is-active --quiet cryptirc; then
    systemctl stop cryptirc
    echo -e "  ${GREEN}✓ CryptIRC stopped${NC}"
else
    echo -e "  ${YELLOW}⚠ CryptIRC was not running${NC}"
fi
echo ""

# ── Swap binary ──────────────────────────────────────────────────────────────
echo -e "${BOLD}Installing new binary...${NC}"
cp target/release/cryptirc "$INSTALL_DIR/cryptirc"
chmod 755 "$INSTALL_DIR/cryptirc"
chown root:root "$INSTALL_DIR/cryptirc"
echo -e "  ${GREEN}✓ Binary updated${NC}"
echo ""

# ── Start service ────────────────────────────────────────────────────────────
echo -e "${BOLD}Starting CryptIRC...${NC}"
systemctl start cryptirc
sleep 2
if systemctl is-active --quiet cryptirc; then
    echo -e "  ${GREEN}✓ CryptIRC restarted successfully${NC}"
else
    echo -e "  ${RED}✗ CryptIRC failed to start — check: journalctl -u cryptirc -n 50${NC}"
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
