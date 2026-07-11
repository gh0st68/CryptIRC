#!/usr/bin/env bash
# sync-version.sh — Cargo.toml's [package].version is the ONE human-edited
# canonical version for the whole project (web binary, daemon, served JS,
# Electron app, README badge). Everything else derives from it:
#   - the web binary's own version:  env!("CARGO_PKG_VERSION")            (automatic — nothing to sync)
#   - the served app.js version:     substituted at compile time          (automatic — see src/main.rs::render_app_js)
#   - the daemon's CTCP VERSION:     announced over IPC on every Attach   (automatic — see src/ipc.rs::WebVersionCell)
#   - electron/package.json         "version" field                      (THIS SCRIPT)
#   - README.md                     version badge                        (THIS SCRIPT)
#
# Usage:
#   scripts/sync-version.sh check   # (default) exit 1 + report if out of sync; no writes
#   scripts/sync-version.sh fix     # rewrite package.json/README.md to match Cargo.toml
#
# Run `fix` after bumping Cargo.toml's version, then commit all three files together.
# `check` is meant to gate CI / deploy (see deploy/update.sh) so this can never drift
# again silently.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
CARGO_TOML="$REPO_DIR/Cargo.toml"
PACKAGE_JSON="$REPO_DIR/electron/package.json"
PACKAGE_LOCK="$REPO_DIR/electron/package-lock.json"
README="$REPO_DIR/README.md"
MODE="${1:-check}"

if [[ "$MODE" != "check" && "$MODE" != "fix" ]]; then
    echo "Usage: $0 [check|fix]" >&2
    exit 2
fi

CANON_VER=$(grep -m1 '^version[[:space:]]*=' "$CARGO_TOML" | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')
if [[ -z "$CANON_VER" ]]; then
    echo "✗ Could not read [package].version from $CARGO_TOML" >&2
    exit 2
fi

PKG_VER=$(grep -m1 '"version"[[:space:]]*:' "$PACKAGE_JSON" | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
LOCK_VER=$(grep -m1 '"version"[[:space:]]*:' "$PACKAGE_LOCK" | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
README_VER=$(grep -m1 'badge/version-' "$README" | sed -E 's/.*badge\/version-([0-9A-Za-z.+-]+)-[a-z]+.*/\1/')

DRIFT=false
[[ "$PKG_VER" != "$CANON_VER" ]] && DRIFT=true
[[ "$LOCK_VER" != "$CANON_VER" ]] && DRIFT=true
[[ "$README_VER" != "$CANON_VER" ]] && DRIFT=true

if [[ "$MODE" == "check" ]]; then
    if [[ "$DRIFT" == "false" ]]; then
        echo "✓ Electron manifests and README.md badge match Cargo.toml (v$CANON_VER)"
        exit 0
    fi
    echo "✗ Version drift detected — Cargo.toml is v$CANON_VER but:" >&2
    [[ "$PKG_VER" != "$CANON_VER" ]] && echo "    electron/package.json is v${PKG_VER:-<unreadable>}" >&2
    [[ "$LOCK_VER" != "$CANON_VER" ]] && echo "    electron/package-lock.json is v${LOCK_VER:-<unreadable>}" >&2
    [[ "$README_VER" != "$CANON_VER" ]] && echo "    README.md badge is v${README_VER:-<unreadable>}" >&2
    echo "  Fix with: scripts/sync-version.sh fix" >&2
    exit 1
fi

# ── fix mode ──────────────────────────────────────────────────────────────
CHANGED=false
if [[ "$PKG_VER" != "$CANON_VER" || "$LOCK_VER" != "$CANON_VER" ]]; then
    # npm updates package.json plus both application-version entries in the v3
    # lockfile while leaving dependency versions alone.
    (cd "$REPO_DIR/electron" && npm version "$CANON_VER" --no-git-tag-version --allow-same-version >/dev/null)
    echo "  Electron manifests: ${PKG_VER:-<unreadable>}/${LOCK_VER:-<unreadable>} → $CANON_VER"
    CHANGED=true
fi
if [[ "$README_VER" != "$CANON_VER" ]]; then
    sed -i -E "0,/badge\/version-[0-9A-Za-z.+-]+-[a-z]+/s//badge\/version-${CANON_VER}-brightgreen/" "$README"
    echo "  README.md badge: ${README_VER:-<unreadable>} → $CANON_VER"
    CHANGED=true
fi

if [[ "$CHANGED" == "true" ]]; then
    echo "✓ Synced to v$CANON_VER — review the diff and commit."
else
    echo "✓ Already in sync (v$CANON_VER)"
fi
