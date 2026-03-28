#!/usr/bin/env bash
# CryptIRC update script — rebuilds and hot-swaps the binary
# Usage: sudo bash deploy/update.sh
# Zero-downtime: systemd restarts the process in <1 second

set -euo pipefail

INSTALL_DIR="/opt/cryptirc"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building new binary..."
cd "$REPO_DIR"
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release 2>&1 | tail -5

echo "Swapping binary..."
# Copy new binary alongside (don't overwrite while running)
cp target/release/cryptirc "$INSTALL_DIR/cryptirc.new"
chmod 755 "$INSTALL_DIR/cryptirc.new"
chown root:root "$INSTALL_DIR/cryptirc.new"
# Atomic rename
mv "$INSTALL_DIR/cryptirc.new" "$INSTALL_DIR/cryptirc"

echo "Restarting CryptIRC..."
systemctl restart cryptirc
sleep 2
systemctl is-active --quiet cryptirc && echo "✓ CryptIRC restarted successfully" || {
    echo "✗ CryptIRC failed to start — check: journalctl -u cryptirc -n 50"
    exit 1
}
