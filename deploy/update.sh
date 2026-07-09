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
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; WHITE='\033[1;37m'

# ── The flying ghost show 👻 ─────────────────────────────────────────────────
# A ghost flies across the console, then a branded banner. Interactive only (never
# spams a cron/pipe log); skip with --no-ghost or CRYPTIRC_NO_GHOST=1.
_ghost_fly() {
    [[ -t 1 && "$NO_GHOST" != "true" && "${CRYPTIRC_NO_GHOST:-}" != "1" ]] || return 0
    local cols; cols=$(tput cols 2>/dev/null || echo 70); (( cols > 70 )) && cols=70; (( cols < 20 )) && cols=20
    tput civis 2>/dev/null || true
    local trail=". · ∴ ~"
    for ((i=0; i<=cols-4; i+=2)); do
        printf "\r%*s${DIM}${CYAN}%s${NC} ${WHITE}${BOLD}.-.${NC}" "$i" "" "$trail"
        printf "\n%*s      ${WHITE}${BOLD}(o o)${NC}" "$i" ""
        printf "\n%*s      ${WHITE}${BOLD} \\~/ ${NC}" "$i" ""
        sleep 0.018
        printf "\033[2A"   # cursor up 2 lines for the next frame
    done
    printf "\033[2B\r%*s\r" "$cols" ""   # settle + clear
    tput cnorm 2>/dev/null || true
}
_banner() {
    _ghost_fly
    echo -e "${MAGENTA}${BOLD}"
    cat <<'GHOST'
        .-------.
       /  ^   ^  \      C R Y P T I R C
      |    (o)    |     ─────────────────────
      |   \___/   |     encrypted web IRC + irc-core daemon
       \  '''''  /
        `-------'
GHOST
    echo -e "${NC}${CYAN}${BOLD}   developed by gh0st${NC}  ${DIM}·${NC}  ${CYAN}irc.twistednet.org${NC}  ${DIM}#twisted #dev${NC}\n"
}

# ── Progress UI: a step bar for phases + a spinner for long silent ops ────────
_PSTEP=0; _PSTEPS=7
_progress() {   # _progress "Label"
    _PSTEP=$(( _PSTEP + 1 )); (( _PSTEP > _PSTEPS )) && _PSTEPS=$_PSTEP
    local pct=$(( _PSTEP * 100 / _PSTEPS )) filled=$(( _PSTEP * 22 / _PSTEPS )) bar="" i
    for ((i=0; i<22; i++)); do (( i < filled )) && bar+="█" || bar+="░"; done
    echo ""
    printf "${MAGENTA}${BOLD}▕%s▏${NC} ${CYAN}${BOLD}%3d%%${NC}  ${WHITE}${BOLD}%s${NC}\n" "$bar" "$pct" "$1"
}
# _spin "message" cmd args... — run cmd in the background, animate a spinner until it
# finishes (interactive only; falls back to a plain run when piped/cron). Returns cmd's rc.
_spin() {
    local msg="$1"; shift; local rc=0
    # set -e safe: a non-zero exit from the wrapped command must be RETURNED, not abort
    # the script — the caller decides what a given rc means (e.g. tar rc=1 is fine).
    if [[ ! -t 1 ]]; then "$@" || rc=$?; return $rc; fi
    "$@" & local pid=$! frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    # If interrupted mid-spin, kill the backgrounded child (don't orphan a runaway build/tar)
    # and restore the cursor before tearing down. $pid is expanded when the trap FIRES, so it
    # kills the CURRENT child; cleared right after the loop so it never fires with a stale pid.
    trap 'kill "$pid" 2>/dev/null || true; tput cnorm 2>/dev/null || true; exit 130' INT TERM
    tput civis 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}${BOLD}%s${NC} ${DIM}%s${NC}" "${frames:i++%${#frames}:1}" "$msg"
        sleep 0.08
    done
    trap - INT TERM
    wait "$pid" || rc=$?
    tput cnorm 2>/dev/null || true
    printf "\r%*s\r" $(( ${#msg} + 8 )) ""
    return $rc
}

INSTALL_DIR="/opt/cryptirc"
DATA_DIR="/var/lib/cryptirc"
BACKUP_DIR="/var/lib/cryptirc-backups"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

SKIP_BACKUP=false
RESTART_DAEMON=false
NO_GHOST=false
for arg in "$@"; do
    case "$arg" in
        --no-backup)      SKIP_BACKUP=true ;;
        --restart-daemon) RESTART_DAEMON=true ;;
        --no-ghost)       NO_GHOST=true ;;
    esac
done

_banner

# Safety net for the window between "we stopped cryptirc" and "we successfully
# started it again" — if the script is interrupted anywhere in that window
# (SSH drop, Ctrl-C, OOM), cryptirc would otherwise be left stopped with
# nothing to bring it back (Restart=on-failure doesn't apply to a service
# that was never (re)started, only one that crashes after starting). On a
# normal successful run this is a no-op: by the time the script exits,
# cryptirc is already active, so the check below sees nothing to do.
CRYPTIRC_STOPPED_BY_US=false
_recover_on_exit() {
    tput cnorm 2>/dev/null || true   # always restore the cursor — a _spin/_ghost_fly interrupted mid-animation left it hidden
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

    _progress "Backing up your data"
    # The backup bundles Argon2 hashes, vaults and admin_settings (reg code) — create it
    # 0600 (umask), not world-readable. A genuinely FAILED backup must ABORT: it's the
    # only safety net before we swap the binary, so continuing would defeat its purpose.
    #
    # BUT distinguish tar's exit codes — misreading a benign warning as failure made
    # a busy server permanently un-updatable:
    #   0  = clean.
    #   1  = WARNINGS only: a file changed WHILE being read (a live chat log written
    #        during the backup — guaranteed on any active server) or a skipped socket
    #        (the excluded irc-core.sock). The archive is still complete and valid for
    #        every other file, so this MUST NOT abort.
    #   2+ = a real fatal error (out of space, missing path, permission) → abort.
    # We also require the archive to be non-empty (-s) as a floor against a 0-byte/
    # truncated write that somehow still returned 0/1.
    # --exclude the irc-core IPC socket: it's a live endpoint, not user data.
    tar_rc=0
    _spin "Archiving $(basename "$DATA_DIR") …" \
        bash -c 'umask 0077; tar czf "$1" --exclude=irc-core.sock -C "$2" "$3" 2>/dev/null' \
        _ "$BACKUP_FILE" "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")" || tar_rc=$?
    # Verify the archive is actually LISTABLE, not just non-empty — a truncated-but-nonzero
    # gzip (disk filled mid-write, returned rc 1) would pass `-s` yet be useless on restore.
    if [[ ( "$tar_rc" -eq 0 || "$tar_rc" -eq 1 ) && -s "$BACKUP_FILE" ]] && tar tzf "$BACKUP_FILE" >/dev/null 2>&1; then
        BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
        echo -e "  ${GREEN}✓ Backup saved:${NC} $BACKUP_FILE (${BACKUP_SIZE})"
        [[ "$tar_rc" -eq 1 ]] && echo -e "  ${DIM}(some files changed while being read — normal on a live server; the backup is still complete)${NC}"
    else
        rm -f "$BACKUP_FILE"
        echo -e "  ${RED}✗ Backup failed (tar exit ${tar_rc}) — aborting update; nothing was changed.${NC}"
        echo -e "  ${DIM}Check free space (df -h $(dirname "$DATA_DIR")) and that $DATA_DIR exists, then retry.${NC}"
        echo -e "  ${DIM}To update without a backup this once: sudo bash deploy/update.sh --no-backup${NC}"
        exit 1
    fi

    # Keep only the last 5 backups
    ls -1t "$BACKUP_DIR"/cryptirc-backup-*.tar.gz 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/cryptirc-backup-*.tar.gz 2>/dev/null | wc -l)
    echo -e "  ${DIM}(${BACKUP_COUNT} backups kept, older ones pruned)${NC}"
    echo ""
fi

# ── Pull latest code ──────────────────────────────────────────────────────────
_progress "Pulling latest code"
cd "$REPO_DIR"
# Capture HEAD before/after so the summary can state plainly whether the code actually
# ADVANCED — a failed --ff-only (diverged/force-pushed upstream) otherwise silently builds
# the OLD checkout while everything downstream reports success, i.e. a no-op "deploy".
# -c safe.directory: update.sh runs as root over a (often non-root-owned) checkout; without it
# git 2.35.2+ aborts with "dubious ownership" and the pull always fails. Scoped, no global mutation.
_git_before=$(git -c safe.directory="$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')
GIT_PULL_OK=true
git -c safe.directory="$REPO_DIR" pull --ff-only 2>&1 || { GIT_PULL_OK=false; echo -e "  ${YELLOW}⚠ git pull failed — building from the EXISTING checkout; this may NOT be the latest code${NC}"; }
_git_after=$(git -c safe.directory="$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')
echo ""

# ── Build ─────────────────────────────────────────────────────────────────────
# ── Auto-install build dependencies ──────────────────────────────────────────
# Make the box able to BUILD from a cold start: check for the toolchain the release
# build needs (C compiler + make + perl for the vendored OpenSSL, pkg-config) and
# auto-install whatever's missing via this host's package manager. Idempotent + a
# near-instant no-op once the box has built before — but means the script "just works"
# on a fresh host. (Rust itself is handled by the cargo probe just below.)
_progress "Checking build dependencies"
_pkgmgr=""
for _m in apt-get dnf yum pacman zypper apk brew; do command -v "$_m" &>/dev/null && { _pkgmgr="$_m"; break; }; done
_need=()
command -v cc &>/dev/null || command -v gcc &>/dev/null || command -v clang &>/dev/null || _need+=(cc)
command -v make &>/dev/null || _need+=(make)
command -v perl &>/dev/null || _need+=(perl)
command -v pkg-config &>/dev/null || _need+=(pkgconfig)
if (( ${#_need[@]} > 0 )); then
    if [[ -z "$_pkgmgr" ]]; then
        echo -e "  ${RED}✗ Missing build tools (${_need[*]}) and no known package manager found — install them manually.${NC}"; exit 1
    fi
    _pkgs=()
    for _t in "${_need[@]}"; do
        case "${_t}:${_pkgmgr}" in
            cc:apt-get)          _pkgs+=(build-essential) ;;
            cc:pacman)           _pkgs+=(base-devel) ;;
            cc:apk)              _pkgs+=(build-base) ;;
            cc:*)                _pkgs+=(gcc) ;;
            make:pacman)         _pkgs+=(base-devel) ;;
            make:apk)            _pkgs+=(build-base) ;;
            make:*)              _pkgs+=(make) ;;
            perl:*)              _pkgs+=(perl) ;;
            pkgconfig:pacman)    _pkgs+=(pkgconf) ;;
            pkgconfig:apt-get)   _pkgs+=(pkg-config) ;;
            pkgconfig:*)         _pkgs+=(pkgconfig) ;;
        esac
    done
    # shellcheck disable=SC2207  # package names never contain whitespace
    _pkgs=($(printf '%s\n' "${_pkgs[@]}" | sort -u))
    echo -e "  ${YELLOW}Auto-installing missing deps (${_need[*]}) via ${_pkgmgr}: ${_pkgs[*]}${NC}"
    _ok=false
    case "$_pkgmgr" in
        apt-get) apt-get update -qq && apt-get install -y -qq "${_pkgs[@]}" && _ok=true ;;
        dnf|yum) "$_pkgmgr" install -y -q "${_pkgs[@]}" && _ok=true ;;
        pacman)  pacman -Sy --noconfirm --needed "${_pkgs[@]}" && _ok=true ;;
        zypper)  zypper --non-interactive install "${_pkgs[@]}" && _ok=true ;;
        apk)     apk add --no-cache "${_pkgs[@]}" && _ok=true ;;
        brew)    brew install "${_pkgs[@]}" && _ok=true ;;
    esac
    [[ "$_ok" == "true" ]] || { echo -e "  ${RED}✗ Auto-install failed — install ${_need[*]} manually and retry.${NC}"; exit 1; }
fi
echo -e "  ${GREEN}✓ Build toolchain present${NC}"
echo ""

_progress "Building CryptIRC"
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
# Still no cargo? Cold box — install Rust via rustup (minimal profile, into /root/.cargo).
if ! command -v cargo &>/dev/null; then
    echo -e "  ${YELLOW}Rust toolchain not found — installing via rustup...${NC}"
    export CARGO_HOME="/root/.cargo" RUSTUP_HOME="/root/.rustup"
    if command -v curl &>/dev/null; then
        curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
    elif command -v wget &>/dev/null; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
    else
        echo -e "  ${RED}✗ Need curl or wget to install Rust — install one (or Rust) manually.${NC}"; exit 1
    fi
    export PATH="/root/.cargo/bin:$PATH"
    command -v cargo &>/dev/null && echo -e "  ${GREEN}✓ Rust installed${NC}" \
        || { echo -e "  ${RED}✗ Rust install failed — see https://rustup.rs${NC}"; exit 1; }
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

# ── Smart change detection ───────────────────────────────────────────────────
# Hash the freshly-built binaries against what's currently DEPLOYED (compared BEFORE
# the swap below overwrites them) and auto-decide the restart actions, instead of
# relying on the operator to remember flags. Key asymmetry: restarting the WEB never
# drops IRC connections (those live in the daemon, which the web re-attaches to); only
# a DAEMON restart drops them — so the daemon is the single real decision.
WEB_CHANGED=true
DAEMON_CHANGED=true
if [[ -f "$INSTALL_DIR/cryptirc" ]] && cmp -s target/release/cryptirc "$INSTALL_DIR/cryptirc"; then
    WEB_CHANGED=false
fi
# Daemon change = did the daemon's OWN SOURCE change? NOT its binary: the binary embeds
# the repo git-sha via CRYPTIRC_BUILD, so a mere commit (even a web-only one) flips its
# hash and would needlessly prompt a daemon restart. We hash exactly the daemon's CLOSED
# crate:: dependency set (verified: bin/irc_core → ipc_server → {ipc,ipc_framing,
# irc_daemon}; irc_daemon → {ipc,ipc_framing,ircproto}) + the Cargo manifests. This
# ignores the sha and catches both committed AND uncommitted daemon changes. ⚠ If a NEW
# module ever becomes a daemon dependency, ADD IT to DAEMON_SRC below.
DAEMON_SRC=(src/bin/irc_core.rs src/ipc_server.rs src/irc_daemon.rs src/ipc.rs src/ipc_framing.rs src/ircproto.rs Cargo.lock)
# Every listed daemon source MUST exist. If a refactor renamed/moved one (e.g. ipc.rs →
# ipc/mod.rs), cat-ing the missing path would SILENTLY drop it from the hash, and a later
# real change inside the moved code would then hash identically → the daemon runs OLD code
# forever, defeating the entire split. Hard-fail so the operator updates DAEMON_SRC instead
# of deploying blind detection. (This is why the hash below no longer swallows stderr.)
for _f in "${DAEMON_SRC[@]}"; do
    [[ -f "$REPO_DIR/$_f" ]] || { echo -e "  ${RED}✗ Daemon-change detector: source '${_f}' is missing — a refactor likely moved it. Update DAEMON_SRC in deploy/update.sh before deploying; refusing to run with incomplete detection.${NC}"; exit 1; }
done
# Hash the daemon sources + Cargo.lock (resolved deps) + Cargo.toml MINUS its version line —
# a version-only bump changes no daemon behavior, so it must not read as "daemon changed" and
# prompt a needless restart. (The [profile.release]/[dependencies] parts that DO affect the
# daemon are still hashed.)
# `|| true` on the grep: if Cargo.toml were ever ALL version-lines, grep -v would emit
# nothing and exit 1 → under pipefail the whole `VAR=$(…)` would abort. Unreachable with a
# real manifest (it always has [package]/name=…), but belt-and-suspenders for a frozen box.
DAEMON_SRC_HASH=$( cd "$REPO_DIR" && { cat "${DAEMON_SRC[@]}"; grep -v '^version[[:space:]]*=' Cargo.toml || true; } | sha256sum | cut -d' ' -f1 )
if [[ "$HAVE_IRC_CORE" == "true" ]]; then
    if [[ -f "$INSTALL_DIR/.irc-core-srchash" ]]; then
        [[ "$(cat "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null)" == "$DAEMON_SRC_HASH" ]] && DAEMON_CHANGED=false
    elif [[ -f "$INSTALL_DIR/irc_core" ]] && cmp -s target/release/irc_core "$INSTALL_DIR/irc_core"; then
        # Bootstrap (no marker yet): the freshly-built daemon binary is byte-identical to
        # what's deployed, so the RUNNING daemon is already current → seed the marker and
        # treat as unchanged. (A one-time point-in-time binary compare is safe — the
        # sha-embedding only matters ACROSS commits, not for "is it the same right now".)
        DAEMON_CHANGED=false
        echo "$DAEMON_SRC_HASH" > "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null || true
    fi
fi
# Web version detection (for the summary): the version pill is Cargo's package version.
NEW_VER=$( grep -m1 '^version[[:space:]]*=' "$REPO_DIR/Cargo.toml" | cut -d'"' -f2 )
OLD_VER=$( cat "$INSTALL_DIR/.version" 2>/dev/null || echo "unknown" )
# Web: restart only if it actually changed (an unchanged web binary needs no restart).
WEB_RESTART=false
[[ "$WEB_CHANGED" == "true" ]] && WEB_RESTART=true
# Recovery: if the web binary reads "unchanged" but the service isn't actually running (a
# previous run swapped the binary then died before a healthy (re)start, or someone stopped
# it), still (re)start it. Otherwise the binary-cmp "unchanged" verdict would skip the very
# restart needed to bring the site back — leaving it down across repeated re-runs.
if [[ "$WEB_RESTART" == "false" ]] && systemctl cat cryptirc.service >/dev/null 2>&1 \
   && ! systemctl is-active --quiet cryptirc; then
    WEB_RESTART=true
    echo -e "  ${YELLOW}⚠ cryptirc binary unchanged, but the service is not active — will (re)start it to recover.${NC}"
fi
# Daemon: resolve the restart decision.
if [[ "$HAVE_IRC_CORE_UNIT" == "true" ]]; then
    if [[ "$DAEMON_CHANGED" == "false" ]]; then
        # Nothing to apply — never drop connections for an unchanged daemon, even if
        # --restart-daemon was explicitly passed.
        [[ "$RESTART_DAEMON" == "true" ]] && \
            echo -e "${DIM}irc-core binary is unchanged — skipping the daemon restart (no connections dropped for nothing).${NC}"
        RESTART_DAEMON=false
    elif [[ "$RESTART_DAEMON" == "true" ]]; then
        : # explicitly forced AND changed → restart to apply (handled by the stop/start blocks)
    elif [[ -t 0 ]]; then
        # Interactive: the daemon changed but no flag — ask, since applying it drops
        # every user's live IRC session.
        echo -e "${YELLOW}⚠ The irc-core daemon binary CHANGED.${NC} Applying it restarts the daemon and drops every user's live IRC session (they auto-reconnect)."
        read -r -p "  Restart the daemon now to apply it? [y/N] " _ans || _ans=""
        case "$_ans" in
            [yY]|[yY][eE][sS]) RESTART_DAEMON=true ;;
            *) RESTART_DAEMON=false ;;
        esac
    else
        # Non-interactive (cron / piped): never surprise-drop connections — defer + warn
        # (a loud line is printed in the summary at the end).
        RESTART_DAEMON=false
    fi
fi
echo ""

# ── Stop service(s) ──────────────────────────────────────────────────────────
_progress "Applying update"
if [[ "$WEB_RESTART" == "true" ]]; then
    if systemctl is-active --quiet cryptirc; then
        systemctl stop cryptirc
        CRYPTIRC_STOPPED_BY_US=true
        echo -e "  ${GREEN}✓ CryptIRC stopped${NC}"
    else
        echo -e "  ${YELLOW}⚠ CryptIRC was not running${NC}"
    fi
else
    echo -e "  ${DIM}cryptirc web binary unchanged — left running (no web restart needed)${NC}"
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

# ── Refresh the irc-core unit on an already-split box ────────────────────────
# The migration block below only WRITES the unit on a PRE-split box. On an
# already-split box, hardening/watchdog changes to deploy/irc-core.service would
# otherwise never reach systemd (the binary swaps but the unit stays stale). Sync
# it here — but ONLY when --restart-daemon is passed, so a new Type=notify +
# WatchdogSec applies to a FRESH process that actually heartbeats: arming a
# watchdog against the already-running OLD binary via daemon-reload could get it
# killed for not sending WATCHDOG=1. And ONLY for a STOCK unit whose
# ExecStart/User/CRYPTIRC_DATA match this repo's — a box with a customized unit is
# left untouched and flagged, never clobbered.
if [[ "$RESTART_DAEMON" == "true" && "$HAVE_IRC_CORE_UNIT" == "true" && -f "$SCRIPT_DIR/irc-core.service" ]]; then
    INST_UNIT=/etc/systemd/system/irc-core.service
    REPO_UNIT="$SCRIPT_DIR/irc-core.service"
    if [[ -f "$INST_UNIT" ]] && ! diff -q "$INST_UNIT" "$REPO_UNIT" >/dev/null 2>&1; then
        _unit_field() { grep -m1 "^$1" "$2" | cut -d= -f2- ; }
        if [[ "$(_unit_field 'ExecStart=' "$INST_UNIT")" == "$(_unit_field 'ExecStart=' "$REPO_UNIT")" \
           && "$(_unit_field 'User=' "$INST_UNIT")" == "$(_unit_field 'User=' "$REPO_UNIT")" \
           && "$(grep -m1 '^Environment=CRYPTIRC_DATA=' "$INST_UNIT")" == "$(grep -m1 '^Environment=CRYPTIRC_DATA=' "$REPO_UNIT")" ]]; then
            cp "$REPO_UNIT" "$INST_UNIT"
            chmod 644 "$INST_UNIT"; chown root:root "$INST_UNIT"
            systemctl daemon-reload
            echo -e "  ${GREEN}✓ irc-core.service refreshed from repo${NC} ${DIM}(watchdog/hardening applied on the restart below)${NC}"
        else
            echo -e "  ${YELLOW}⚠ Installed irc-core.service has custom paths/user — NOT auto-refreshed.${NC}"
            echo -e "  ${YELLOW}  The daemon restarts with the NEW binary but your OLD unit — if that unit is${NC}"
            echo -e "  ${YELLOW}  Type=simple / lacks WatchdogSec, the never-die watchdog will NOT be active.${NC}"
            echo -e "  ${DIM}Reconcile it against deploy/irc-core.service (Type=notify + WatchdogSec + StartLimitIntervalSec=0) for full protection.${NC}"
        fi
    fi
fi

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
    # Service user/group: mirror whatever the web process actually runs as (INCLUDING root)
    # so the daemon can write the socket into the data dir and the web process can open it
    # (same uid). NOTE: `systemctl show -p User --value` MAY return empty (not the literal
    # "root") when the unit has no User= line — so we fall back to the data dir's actual
    # owner. The resolved account MUST exist or the generated unit won't start, so the final
    # guard drops to root (always present, always able to create the socket).
    MIG_USER=$(systemctl show cryptirc.service -p User --value 2>/dev/null || true)
    MIG_GROUP=$(systemctl show cryptirc.service -p Group --value 2>/dev/null || true)
    [[ -z "$MIG_USER" ]] && MIG_USER=$(stat -c %U "$MIG_DATA" 2>/dev/null || true)
    [[ -z "$MIG_USER" ]] && MIG_USER=cryptirc
    id -u "$MIG_USER" >/dev/null 2>&1 || { MIG_USER=root; MIG_GROUP=root; }   # non-existent user → unit won't start; root always works
    [[ -z "$MIG_GROUP" ]] && MIG_GROUP=$(stat -c %G "$MIG_DATA" 2>/dev/null || true)
    [[ -z "$MIG_GROUP" ]] && MIG_GROUP="$MIG_USER"
    getent group "$MIG_GROUP" >/dev/null 2>&1 || MIG_GROUP="$MIG_USER"       # fall back to the (now-valid) user name as group
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
# NEVER latch into a permanent 'failed' state: =0 disables the rate limiter so systemd
# retries forever (a manual 'systemctl stop' still stops it). See deploy/irc-core.service.
StartLimitIntervalSec=0

[Service]
# Type=notify + WatchdogSec: the freshly-started NEW binary drives the systemd watchdog —
# the only backstop for a hung-but-alive daemon. Safe here because this is a brand-new
# process (started below), not the already-running old one.
Type=notify
NotifyAccess=main
WatchdogSec=60
User=$MIG_USER
Group=$MIG_GROUP
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/irc_core
ExecStop=/bin/kill -s TERM \$MAINPID
TimeoutStopSec=30
KillMode=mixed
Restart=always
RestartSec=5
MemoryMax=512M
TasksMax=256
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
LimitNOFILE=16384
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
        # The daemon is Restart=always (StartLimitIntervalSec=0), so systemd keeps retrying it.
        # A total outage helps no one: bring cryptirc up regardless so the web UI stays available
        # — it re-attaches + reconciles automatically once the daemon recovers. Start it EXPLICITLY
        # here (not via the EXIT trap) so the abort path and the trap can't disagree on end state.
        if [[ "$WEB_RESTART" == "true" ]]; then
            echo -e "  ${YELLOW}⚠ Starting cryptirc anyway so the web UI stays up; IRC reconnects once irc-core recovers.${NC}"
            systemctl start cryptirc 2>/dev/null || true
            CRYPTIRC_STOPPED_BY_US=false   # handled here — don't let the EXIT trap double-start it
        fi
        echo -e "  ${RED}✗ irc-core is unhealthy — fix it (journalctl -u irc-core) then: sudo systemctl restart irc-core${NC}"
        exit 1
    fi
    echo ""
fi

if [[ "$WEB_RESTART" == "true" ]]; then
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
CRYPTIRC_HEALTHY=false
for _ in $(seq 1 10); do
    # Probe the ROOT path and accept ANY HTTP status < 500 (200/301/404 all prove the port is
    # bound and serving). The old `-f` false-failed a healthy base-path/reverse-proxy deploy
    # that 404s at "/" — and then recommended a DESTRUCTIVE restore. A dead process is caught
    # by is-active; a hung one by --max-time (curl → 000); a 5xx-ing app stays "unhealthy".
    _code=$(curl -s -L -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${CRYPTIRC_HEALTH_PORT:-9001}/" 2>/dev/null || true)
    [[ "$_code" =~ ^[0-9]{3}$ ]] || _code=000
    if systemctl is-active --quiet cryptirc && (( 10#$_code >= 100 && 10#$_code < 500 )); then
        CRYPTIRC_HEALTHY=true
        break
    fi
    sleep 1
done
if [[ "$CRYPTIRC_HEALTHY" == "true" ]]; then
    echo -e "  ${GREEN}✓ CryptIRC restarted successfully${NC}"
elif systemctl is-active --quiet cryptirc; then
    # systemd says it's up but the local HTTP probe didn't confirm (last code: ${_code}) —
    # most likely a custom port/base-path, or a value set via an EnvironmentFile this script
    # can't read. That is NOT a reason to touch data: report up-but-unconfirmed and finish.
    echo -e "  ${YELLOW}⚠ cryptirc is active, but the HTTP probe on :${CRYPTIRC_HEALTH_PORT:-9001} didn't confirm it (code ${_code}).${NC}"
    echo -e "    ${DIM}If you run a custom port/base-path this probe can be wrong. Verify: systemctl status cryptirc · journalctl -u cryptirc -n 50${NC}"
else
    echo -e "  ${RED}✗ CryptIRC failed to start — check: journalctl -u cryptirc -n 50${NC}"
    if [[ "$SKIP_BACKUP" == "false" && -f "$BACKUP_FILE" ]]; then
        echo ""
        echo -e "  ${DIM}The new binary is installed (the previous one was overwritten in place).${NC}"
        echo -e "  ${YELLOW}Only if you know the DATA is corrupt${NC} ${DIM}— this OVERWRITES current data with the pre-update backup:${NC}"
        echo -e "    ${DIM}sudo systemctl stop cryptirc && sudo tar xzf $BACKUP_FILE -C $(dirname "$DATA_DIR") && sudo systemctl start cryptirc${NC}"
    fi
    exit 1
fi
else
    echo -e "  ${DIM}cryptirc left running (unchanged) — it re-attaches to irc-core automatically if the daemon restarted${NC}"
fi

# ── Summary: what actually changed, and what this run did about it ────────────
echo ""
echo -e "${BOLD}Summary${NC}"
if [[ "$OLD_VER" != "unknown" && "$OLD_VER" != "$NEW_VER" ]]; then
    echo -e "  version:         ${CYAN}v${OLD_VER}${NC} → ${CYAN}${BOLD}v${NEW_VER}${NC}"
else
    echo -e "  version:         ${CYAN}${BOLD}v${NEW_VER}${NC}"
fi
if [[ "${GIT_PULL_OK:-true}" != "true" ]]; then
    echo -e "  code:            ${YELLOW}git pull FAILED — built from ${_git_after:-?} (may be stale)${NC}"
elif [[ "${_git_before:-}" == "${_git_after:-}" ]]; then
    echo -e "  code:            ${DIM}already up to date (${_git_after:-?})${NC}"
else
    echo -e "  code:            ${GREEN}${_git_before:-?} → ${_git_after:-?}${NC}"
fi
if [[ "$WEB_CHANGED" == "true" ]]; then
    echo -e "  web (cryptirc):  ${GREEN}changed → restarted${NC}"
elif [[ "$WEB_RESTART" == "true" ]]; then
    echo -e "  web (cryptirc):  ${YELLOW}unchanged but was down → restarted${NC}"
else
    echo -e "  web (cryptirc):  ${DIM}unchanged → left running${NC}"
fi
if [[ "$HAVE_IRC_CORE_UNIT" == "true" ]]; then
    if [[ "$DAEMON_CHANGED" != "true" ]]; then
        echo -e "  irc-core daemon: ${DIM}unchanged → left running${NC}"
    elif [[ "$RESTART_DAEMON" == "true" ]]; then
        echo -e "  irc-core daemon: ${GREEN}changed → restarted${NC} ${DIM}(connections dropped, auto-reconnecting)${NC}"
    else
        # Deferred restart: changed but left running — the new daemon code is on disk but
        # the running process still executes the OLD code until it restarts.
        echo -e "  irc-core daemon: ${YELLOW}CHANGED but NOT restarted${NC}"
        echo -e "    ${YELLOW}⚠ The new daemon code is installed but the running daemon is still on the OLD code.${NC}"
        echo -e "    ${YELLOW}  Re-run with --restart-daemon to apply it (this will drop + reconnect IRC sessions).${NC}"
    fi
fi

# ── Persist deploy markers used by the NEXT run's change detection ────────────
# .version → shown as the "from" version next time. .irc-core-srchash → the daemon SOURCE
# hash the RUNNING daemon was built from; written ONLY when we actually (re)started it, so
# a DEFERRED daemon change is correctly still seen as "changed" on the next run.
echo "$NEW_VER" > "$INSTALL_DIR/.version" 2>/dev/null || true
if { [[ "$RESTART_DAEMON" == "true" ]] || [[ "${MIGRATED_TO_DAEMON:-false}" == "true" ]]; } \
   && systemctl is-active --quiet irc-core 2>/dev/null; then
    echo "$DAEMON_SRC_HASH" > "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}${BOLD}✓ Update complete!${NC}"
echo -e "${DIM}   CryptIRC by ${NC}${CYAN}${BOLD}gh0st${NC}${DIM}  ·  irc.twistednet.org  ·  ${NC}${CYAN}#twisted #dev${NC}"
if [[ "$MIGRATED_TO_DAEMON" == "true" ]]; then
    echo -e "  ${DIM}Migrated to the irc-core daemon — this was a one-time reconnect. From now"
    echo -e "  on, routine updates swap only the web binary and won't drop IRC connections.${NC}"
fi
