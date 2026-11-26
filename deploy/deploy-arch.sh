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
#
# Safe to re-run (e.g. after the server's IP changes): settings are kept, every
# config file it replaces is backed up first, and the irc-core daemon (everyone's
# live IRC sessions) is only restarted when its code or unit actually changed.
# CRYPTIRC_NO_PULL=1 builds the checkout exactly as it is (no `git pull`).
# Upgrading an installed version below 0.5.8 backs up users' data first (CRYPTIRC_NO_BACKUP=1
# skips that) and never rolls back automatically once users' data changed (deploy/data-floor.sh).
# Exit status: 0 = live; 1 = failed or rolled back; 4 = the new version failed its health check
# but was kept, because users' data had already changed under it (the message says what to do).
# ─────────────────────────────────────────────────────────────────────────────
# bash only — under sh/dash the `set -o pipefail` below dies with a cryptic "Illegal option".
if [ -z "${BASH_VERSION:-}" ]; then echo "Please run this installer with bash:  sudo bash deploy/deploy-arch.sh" >&2; exit 1; fi
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

DIED=false      # set by die(), so the EXIT handler doesn't add a second, generic error
KEEP_LOG=false  # set when a failure message points at $RUN_LOG, so it's kept for the operator
ERR_LINE=""     # last top-level line that failed (recorded by the ERR trap below)
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
die()  { DIED=true; echo -e "\n  ${RED}✗ Error:${NC} $*\n" >&2; exit 1; }
# restore_cert: while a newly generated self-signed pair is in place but the Caddy config that
# uses it hasn't validated (CERT_STATE=replaced), put back the pair it replaced — or remove the
# new one if there was none. Each file goes back by rename, never half-written.
restore_cert() {
    local f
    [[ "${CERT_STATE:-}" == replaced ]] || return 0
    for f in key.pem cert.pem; do
        if [[ -n "${CERT_PREV_DIR:-}" && -f "$CERT_PREV_DIR/$f" ]]; then
            cp -p "$CERT_PREV_DIR/$f" "$SS_DIR/.$f.restore" && mv -f "$SS_DIR/.$f.restore" "$SS_DIR/$f"
        else
            rm -f "$SS_DIR/$f"
        fi
    done
    CERT_STATE=restored
    return 0
}
# Config files this run replaced, oldest first: "target|backup|uid gid mode" (backup and perms empty:
# the file is new). Until the new services run (the commit right after the restart, below), any way
# out of the run puts every one of them back (on_exit → restore_configs); a Caddy configuration that
# doesn't validate does the same.
CONFIG_TXN=()
# undo_rec "target|backup|perm": put a replaced file back exactly as it was — content, owner, group,
# mode — staged beside it and renamed over it; or remove a file this run created. rc 1 = couldn't.
undo_rec() {
    local target bak perm uid gid mode tmp
    IFS='|' read -r target bak perm <<< "$1"
    [[ -n "$target" ]] || return 0
    if [[ -n "$bak" ]]; then
        [[ -f "$bak" ]] || return 1
        read -r uid gid mode <<< "$perm"
        tmp="$(mktemp "$(dirname "$target")/.$(basename "$target").XXXXXX")" || return 1
        if install -m "${mode:-600}" -o "${uid:-0}" -g "${gid:-0}" "$bak" "$tmp" && mv -f "$tmp" "$target"; then return 0; fi
        rm -f "$tmp"; return 1
    fi
    rm -f "$target"
}
restore_configs() {
    local i
    for (( i = ${#CONFIG_TXN[@]} - 1; i >= 0; i-- )); do
        undo_rec "${CONFIG_TXN[i]}" || echo -e "  ${YELLOW}⚠${NC} Couldn't put ${CONFIG_TXN[i]%%|*} back — its previous version is in $UNIT_BACKUP_DIR or /etc/caddy." >&2
    done
    CONFIG_TXN=()
    return 0
}
# On ANY exit: bring the cursor back (the spinner hides it), drop an empty step log, and —
# if something failed WITHOUT going through die() (say a download pipeline hit a network
# error) — say so plainly instead of stopping without a word.
on_exit() {
    local rc=$?
    # Every step below must run, whatever happens meanwhile: a lost SSH session (writes to its
    # terminal fail with EIO — under errexit the first echo ended the handler — and SIGHUP), a
    # second Ctrl-C or a closed pipe must not cut the clean-up short (as update.sh's handler).
    set +eu
    trap '' INT TERM HUP PIPE
    [[ "$FANCY" == true ]] && printf '\033[?25h' 2>/dev/null
    [[ -n "${PREV_ENV_JSON:-}" ]] && rm -f "$PREV_ENV_JSON"
    [[ -n "${SS_NEW:-}" ]] && rm -rf "$SS_NEW"
    if (( ${#CONFIG_TXN[@]} )); then
        restore_configs
        systemctl daemon-reload >/dev/null 2>&1 || true
        echo -e "  ${DIM}(the config files this run had replaced were put back)${NC}" >&2
    fi
    if [[ "${CERT_STATE:-}" == replaced ]]; then
        restore_cert
        echo -e "  ${DIM}(the previous self-signed certificate was put back)${NC}" >&2
    fi
    # New binaries staged but never swapped in: drop them. Swapped in but the services not
    # restarted yet (stopped in that short window): put the previous ones back, so the files
    # on disk match what is running.
    case "${BIN_STATE:-}" in
        staged)  rm -f "$INSTALL_DIR/.cryptirc.staged" "$INSTALL_DIR/.irc_core.staged" ;;
        swapped) local b; for b in cryptirc irc_core; do
                     [[ -f "$INSTALL_DIR/.$b.prev" ]] && mv -f "$INSTALL_DIR/.$b.prev" "$INSTALL_DIR/$b"
                     rm -f "$INSTALL_DIR/.$b.staged"
                 done
                 rm -f "$INSTALL_DIR/.irc_core.ondisk-srchash"
                 echo -e "  ${DIM}(the previously installed binaries were put back)${NC}" >&2 ;;
    esac
    # This run stopped cryptirc (for the 0.5.8 data-floor checks) and didn't get to start it again:
    # start it — on the binary and unit now on disk (the previous ones, when they were put back
    # above) — so an interrupted run never leaves the site down (systemd won't restart a unit that
    # was stopped on purpose).
    if [[ "${WEB_STOPPED:-}" == true ]]; then
        systemctl daemon-reload >/dev/null 2>&1
        systemctl reset-failed cryptirc >/dev/null 2>&1
        systemctl start cryptirc >/dev/null 2>&1
        WEB_STOPPED=false
        echo -e "  ${DIM}(cryptirc, which this run had stopped, was started again: $(systemctl is-active cryptirc 2>/dev/null))${NC}" >&2
    fi
    # The step log is kept only when an error message refers to it (or nothing explained the exit).
    if [[ -n "${RUN_LOG:-}" && -f "$RUN_LOG" ]] \
       && [[ $rc -eq 0 || ! -s "$RUN_LOG" || ( "$DIED" == true && "$KEEP_LOG" != true ) ]]; then rm -f "$RUN_LOG"; fi
    if [[ $rc -ne 0 && "$DIED" != true ]]; then
        if [[ $rc -eq 130 ]]; then
            echo -e "\n  ${YELLOW}Interrupted.${NC} Re-run whenever you're ready — re-running is safe.\n" >&2
        else
            echo -e "\n  ${RED}✗ The installer stopped unexpectedly${ERR_LINE:+ at line $ERR_LINE} (exit $rc).${NC}" >&2
            [[ -n "${RUN_LOG:-}" && -s "$RUN_LOG" ]] && echo -e "  ${DIM}Output of the last step: $RUN_LOG${NC}" >&2
            echo -e "  ${DIM}Fix the cause shown above (often a temporary network error) and re-run — re-running is safe.${NC}\n" >&2
        fi
    fi
}
trap on_exit EXIT
trap 'ERR_LINE=$LINENO' ERR

# A thin horizontal rule, clamped to a sane width.
hr() {
    local w="${COLUMNS:-0}"; [[ "$w" -lt 10 ]] && w=$(tput cols 2>/dev/null || echo 60)
    [[ "$w" -gt 60 ]] && w=60
    printf "${GREY}"; printf '─%.0s' $(seq 1 "$w"); printf "${NC}\n"
}

# A unicode progress bar: progressbar CURRENT TOTAL  (green=done, grey=remaining)
progressbar() {
    local cur="$1" tot="$2" width=22 i filled out=""
    filled=$(( cur * width / tot )); (( filled > width )) && filled=$width
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
    echo -e "       ${DIM}🔒 End-to-end encrypted IRC client${NC}   ${GREY}v${VERSION:-?} · Arch${NC}"
}

# Animated spinner frames for run() (array → locale-safe with multibyte glyphs).
SPIN_FRAMES=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')

INSTALL_DIR="/opt/cryptirc"
DATA_DIR="/var/lib/cryptirc"
LOG_DIR="/var/log/cryptirc"
SERVICE_USER="cryptirc"
SS_DIR="/etc/caddy/selfsigned"          # self-signed cert lives here
CONF_DIR="/etc/cryptirc"                # root-only (0700): the env file below + backups of replaced units
ENV_FILE="$CONF_DIR/cryptirc.env"       # fallback registration code — 0600, NOT in the unit (`systemctl show` would reveal it)
UNIT_BACKUP_DIR="$CONF_DIR/backups"
RUN_LOG=""                              # per-step output — a private mktemp file, created once we know we're root
RUN_HINT=""                             # optional extra advice run() prints when a step fails

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
      KEEP_LOG=true; die "Step failed. Full output: $RUN_LOG${RUN_HINT:+\n  $RUN_HINT}"
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
    KEEP_LOG=true; die "Step failed. Full output: $RUN_LOG${RUN_HINT:+\n  $RUN_HINT}"
  fi
}

# ── Helpers: address classification ───────────────────────────────────────────
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o                                   # each octet must be 0–255 (rejects 999.x etc)
    for o in "${BASH_REMATCH[@]:1:4}"; do (( 10#$o <= 255 )) || return 1; done   # 10# = force base-10 (avoid octal on leading 0)
    return 0
}
# Must be ONLY hex digits + colons (and contain a colon) — so a hostport like "host:8080"
# is not mis-classified as an IPv6 literal and pushed down the self-signed path.
is_ipv6() { [[ "$1" == *:* && "$1" =~ ^[0-9a-fA-F:]+$ ]]; }
is_ip()   { is_ipv4 "$1" || is_ipv6 "$1"; }
# Host as it must appear in a URL / Caddy site address (IPv6 needs [brackets]).
url_host() { if is_ipv6 "$1"; then echo "[$1]"; else echo "$1"; fi; }
# Host-name check: dot-separated labels of letters/digits/hyphens (no leading/trailing
# hyphen) whose last label contains a letter — so "999.1.1.1", "host:8443", "https://x"
# or "a b" never pass. `read -a` (not an unquoted loop) so a stray '*' can't glob-expand.
is_hostname() {
    local h="$1" label; local -a labels
    [[ -n "$h" && ${#h} -le 253 && "$h" != .* && "$h" != *. && "$h" != *..* ]] || return 1
    IFS=. read -ra labels <<< "$h"
    for label in "${labels[@]}"; do [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || return 1; done
    [[ "${labels[-1]}" =~ [A-Za-z] ]]
}
is_domain() { [[ "$1" == *.* ]] && is_hostname "$1"; }   # Let's Encrypt needs a dotted public name
is_email()  { [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; }
# Lower-case, trim whitespace and one trailing dot (DNS root) from a typed host.
clean_host() { local h="${1//[[:space:]]/}"; h="${h,,}"; echo "${h%.}"; }

# ── Must be root ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root:  sudo bash deploy/deploy-arch.sh"
# The usual umask for this run. What must be private is created with an explicit mode (secrets
# 0600, /etc/cryptirc 0700, backups go-rwx …); everything else — /opt/cryptirc, Caddy's conf.d,
# the self-signed certificate's directory — has to be readable by the unprivileged services
# (cryptirc, irc-core, caddy). Under a hardened root umask (077) those came out root-only, and
# neither service could even start.
umask 022
# One deployment at a time: the same lock as deploy/update.sh (/run is root-only), held on fd 9 for
# the life of the run — across the re-exec after a pull too. Two installers, or an installer and an
# update, would otherwise share the .staged/.prev names and interleave swaps and restarts.
DEPLOY_LOCK=/run/cryptirc-update.lock
if command -v flock >/dev/null 2>&1; then
    if ! { [[ "${CRYPTIRC_REEXECED:-}" == 1 ]] && { true >&9; } 2>/dev/null; }; then
        exec 9>>"$DEPLOY_LOCK"
    fi
    flock -n 9 || die "Another deployment is running — deploy/update.sh or this installer (lock: $DEPLOY_LOCK). Let it finish, then re-run."
else
    warn "flock not found — cannot guard against a second installer or update.sh running at the same time."
fi
# Private, unpredictable step log. (A fixed /tmp name let any local user pre-create the
# file — making root's writes fail — and left it world-readable after a failure.)
RUN_LOG="$(mktemp -t cryptirc-install.XXXXXXXX)"
# root's real home. Not plain $HOME: under `sudo -E` that is the invoking user's home, and in
# `env -i` / some cloud-init contexts it is unset, which `set -u` turns into a crash.
ROOT_HOME="$(getent passwd root 2>/dev/null | cut -d: -f6 || true)"; ROOT_HOME="${ROOT_HOME:-/root}"
export HOME="${HOME:-$ROOT_HOME}"

# ── Locate the repo + read the REAL version ───────────────────────────────────
# This script lives in <repo>/deploy/, so the repo is one level up. Read the version
# straight from Cargo.toml (source of truth) instead of a hardcoded string. `|| true`
# keeps the pipeline from tripping `set -e`/`pipefail` if the line is ever absent.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
# Work from / (everything below uses absolute paths): Python puts the current directory first
# on its import path, so an argon2.py / json.py lying in the directory this was started from
# (/tmp, a download folder) would otherwise run as root at the first python3 call. Every
# python3 call below is also isolated (-I, or the cwd dropped from sys.path) for the same reason.
cd /
read_version() { grep -m1 '^version[[:space:]]*=' "$REPO_DIR/Cargo.toml" 2>/dev/null | cut -d'"' -f2 || true; }
VERSION="$(read_version)"; [[ -n "$VERSION" ]] || VERSION="?"

# ── Banner ────────────────────────────────────────────────────────────────────
logo

# Preflight: make sure we're on the right distro family for THIS installer.
command -v pacman &>/dev/null || die "This is the Arch installer, but pacman isn't here. On Debian/Ubuntu, run:  sudo bash deploy/deploy.sh"

# It installs systemd services: fail now, not after a 5-minute build (containers / WSL1).
[[ -d /run/systemd/system ]] || die "This system wasn't booted with systemd, which CryptIRC's services need (irc-core uses its watchdog)."

# ── Get the latest code FIRST, before any question ────────────────────────────
# A fresh install should build CURRENT code, so fast-forward the checkout (best-effort: not
# a git checkout / can't fast-forward → build what's on disk). git runs as the checkout's
# OWNER: a root pull leaves root-owned objects/FETCH_HEAD/work-tree files in someone's clone,
# so their own next pull or edit fails. If the pull changed THIS installer, re-exec the new
# copy, so the new installer (and its dependency list) does the installing — not the old one.
pull_latest() {
    [[ -d "$REPO_DIR/.git" && "${CRYPTIRC_REEXECED:-}" != 1 ]] || return 0
    if [[ "${CRYPTIRC_NO_PULL:-}" == 1 ]]; then echo -e "  ${DIM}CRYPTIRC_NO_PULL=1 — building the checkout as it is.${NC}"; return 0; fi
    command -v git >/dev/null 2>&1 || { warn "git isn't installed — building the checkout as it is."; return 0; }
    local self owner owner_home before after self_before
    local -a as_owner=()
    self="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
    owner="$(stat -c %U "$REPO_DIR/.git" 2>/dev/null || echo root)"
    if [[ "$owner" != root && "$owner" != UNKNOWN ]] && command -v runuser >/dev/null 2>&1; then
        owner_home="$(getent passwd "$owner" | cut -d: -f6 || true)"
        as_owner=(runuser -u "$owner" -- env HOME="${owner_home:-/}")
    fi
    before="$(git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')"
    self_before="$(sha256sum "$self" | cut -d' ' -f1)"
    # No prompts (credentials / ssh host keys) and a time limit: never hang an unattended run.
    if "${as_owner[@]}" env GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="ssh -o BatchMode=yes" \
         timeout 120 git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" pull --ff-only >"$RUN_LOG" 2>&1; then
        after="$(git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')"
        if [[ "$before" == "$after" ]]; then ok "Code is up to date ($after)"; else ok "Pulled the latest code ($before → $after)"; fi
        if [[ "$(sha256sum "$self" | cut -d' ' -f1)" != "$self_before" ]]; then
            echo -e "  ${CYAN}↻ The installer itself was updated — restarting with the new version…${NC}"
            rm -f "$RUN_LOG"
            exec env CRYPTIRC_REEXECED=1 CRYPTIRC_NO_GHOST=1 bash "$self" "$@"
        fi
    else
        warn "git pull couldn't fast-forward — building the checkout as it is (may not be the newest):"
        tail -n 3 "$RUN_LOG" | sed 's/^/      /' >&2 || true
    fi
}
pull_latest "$@"
_v="$(read_version)"; [[ -n "$_v" ]] && VERSION="$_v"

# The 0.5.8 data floor (deploy/data-floor.sh, shared with update.sh): when this run upgrades an
# installed version below 0.5.8 (or of unknown version) to 0.5.8 or later, users' data is backed up
# first, and a new build that fails its health check is NOT rolled back once users' data changed
# under it — see "The 0.5.8 data floor" further down.
[[ -f "$SCRIPT_DIR/data-floor.sh" ]] || die "deploy/data-floor.sh is missing from this checkout — it is incomplete."
# shellcheck source=deploy/data-floor.sh disable=SC1091
source "$SCRIPT_DIR/data-floor.sh"
[[ -f "$SCRIPT_DIR/unit-env.sh" ]] || die "deploy/unit-env.sh is missing from this checkout — it is incomplete."
# shellcheck source=deploy/unit-env.sh disable=SC1091
source "$SCRIPT_DIR/unit-env.sh"
PREV_VER=""; FLOOR_ON=false; FLOOR_SNAP=""; WEB_WITHHELD=false
WEB_STOPPED=false   # this run stopped cryptirc and hasn't started it again (on_exit then does)
if [[ -f "$INSTALL_DIR/cryptirc" ]]; then
    PREV_VER="$(head -c 64 "$INSTALL_DIR/.version" 2>/dev/null | tr -d '[:space:]' || true)"; [[ -n "$PREV_VER" ]] || PREV_VER=unknown
    if _floor_crossed "$PREV_VER" "$VERSION"; then FLOOR_ON=true; fi
fi
PREV_NAME="v$PREV_VER"; [[ "$PREV_VER" == unknown ]] && PREV_NAME="the installed version (unknown)"
# The data dir the INSTALLED service really uses — its unit, a drop-in or an EnvironmentFile may point
# it away from /var/lib/cryptirc — resolved exactly as update.sh does (deploy/unit-env.sh). Everything
# below uses THAT directory: the registration settings, the backup and the data-floor checks, the
# units this run writes, the irc-core socket and the first account.
DATA_DIR_DEFAULT="$DATA_DIR"
WEB_IPC_SOCK=""     # the cryptirc service's own CRYPTIRC_IPC_SOCK: the units this run writes keep it
if systemctl cat cryptirc.service >/dev/null 2>&1; then
    _rc=0; _v="$(_unit_data_dir cryptirc)" || _rc=$?
    case "$_rc" in
        0) DATA_DIR="$_v" ;;
        3) die "CRYPTIRC_DATA is set in an EnvironmentFile of cryptirc.service that is not root-owned, is group/world-writable, or sits (or is a symlink) in a directory others can write — or a wildcard EnvironmentFile reads a directory others can add files to ($(_unit_envfiles cryptirc | xargs)) — its value can't be trusted, so this run can't tell where users' data is. Make it a root-owned file others can't write (chown root: FILE; chmod go-w FILE) in a directory only root can write, then re-run. Nothing was changed." ;;
        5) die "cryptirc.service has EnvironmentFile=$(_envfile_glob_unsupported cryptirc) — a wildcard in a directory part, which this installer doesn't follow (only the file name may have one, e.g. /etc/cryptirc/env.d/*.env), so it can't tell where users' data is. Name the directory itself, then re-run. Nothing was changed." ;;
        *) die "The cryptirc service's data directory resolves to $_v, which is not a usable absolute path. Nothing was changed." ;;
    esac
    # The RUNNING service must be using that directory (same check as update.sh): if its settings
    # were changed without a restart, or something sets it that isn't read here, the backup, the
    # data checks and every file below would land in the wrong one.
    _pid="$(systemctl show -p MainPID --value cryptirc 2>/dev/null || true)"
    if systemctl is-active --quiet cryptirc && [[ "$_pid" =~ ^[1-9][0-9]*$ ]]; then
        _rc=0; _live="$(_live_data_dir "$_pid")" || _rc=$?
        if (( _rc == 0 )) && ! _same_dir "$_live" "$DATA_DIR"; then
            die "The running cryptirc uses the data directory $(printf '%q' "$_live"), but its unit's settings now resolve to $(printf '%q' "$DATA_DIR") — this run would work on the wrong one. If the settings were changed on purpose (the data moved), restart it first so it runs with them: sudo systemctl daemon-reload && sudo systemctl restart cryptirc. Otherwise fix them (systemctl cat cryptirc). Nothing was changed."
        fi
    fi
    _rc=0; WEB_IPC_SOCK="$(_unit_env cryptirc CRYPTIRC_IPC_SOCK)" || _rc=$?
    (( _rc == 5 )) && die "cryptirc.service has EnvironmentFile=$(_envfile_glob_unsupported cryptirc) — a wildcard in a directory part, which this installer doesn't follow (only the file name may have one). Name the directory itself, then re-run. Nothing was changed."
    (( _rc == 3 )) && die "CRYPTIRC_IPC_SOCK is set in an EnvironmentFile of cryptirc.service that can't be trusted — not root-owned, writable by others, or in a directory others can write ($(_unit_envfiles cryptirc | xargs)): make it a root-owned file others can't write, in a directory only root can write, then re-run. Nothing was changed."
    (( _rc == 0 )) || WEB_IPC_SOCK=""
    if [[ -n "$WEB_IPC_SOCK" ]] && ! _sane_path "$WEB_IPC_SOCK"; then
        die "CRYPTIRC_IPC_SOCK in the cryptirc service's settings is not a usable absolute path: $(printf '%q' "$WEB_IPC_SOCK"). Nothing was changed."
    fi
    [[ "$DATA_DIR" != "$DATA_DIR_DEFAULT" ]] && echo -e "  ${DIM}The installed service keeps its data in ${DATA_DIR} (its settings say so) — this run keeps it there.${NC}"
fi
# This run makes the data dir the service account's (owner, mode 750): never a system directory.
system_dir() {
    case "$1" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib|/var/log|/var/tmp|/etc/*|/usr/*|/boot/*|/proc/*|/sys/*|/dev/*|"$INSTALL_DIR"|"$LOG_DIR"|"$CONF_DIR") return 0 ;;
    esac
    return 1
}
system_dir "$DATA_DIR" && die "The cryptirc service's data directory is $(printf '%q' "$DATA_DIR") — a system directory this run would hand to the service account. Point CRYPTIRC_DATA at a directory of its own (e.g. /var/lib/cryptirc), then re-run. Nothing was changed."
# …and nobody but root can swap it for something else before the chown/chmod below (which follow a
# symlink): the directory holding it — or, while it doesn't exist yet, the nearest one above that does —
# is root-owned and writable by nobody else, and so is every directory above (deploy/unit-env.sh's
# _dir_closed). A symlinked data dir is followed only to a directory held the same way, and that isn't a
# system directory either. DATA_DIR_REAL is what gets created, owned and chmod-ed.
# (The directory holding it is checked as written AND as it resolves — every component of its
# real path: through a symlinked ancestor, the real parent may be one someone else can write.)
_dd_parent="$(dirname -- "$DATA_DIR")"
while [[ ! -e "$_dd_parent" && ! -L "$_dd_parent" && "$_dd_parent" != / ]]; do _dd_parent="$(dirname -- "$_dd_parent")"; done
_dd_real="$(readlink -e -- "$_dd_parent" 2>/dev/null || true)"
{ [[ -n "$_dd_real" ]] && _dir_closed "$_dd_parent" && _dir_closed "$_dd_real"; } || die "The data directory $(printf '%q' "$DATA_DIR") is in $(printf '%q' "$_dd_parent")$([[ -n "$_dd_real" && "$_dd_real" != "$_dd_parent" ]] && printf ' (really %q)' "$_dd_real"), which someone other than root can write to (or which is a link to nothing): the service account could swap the data directory for a link to a system directory before this run hands it over (chown/chmod). Keep the data under directories only root can write (e.g. /var/lib/cryptirc or /srv/cryptirc), then re-run. Nothing was changed."
DATA_DIR_REAL="$DATA_DIR"
if [[ -e "$DATA_DIR" || -L "$DATA_DIR" ]]; then
    DATA_DIR_REAL="$(readlink -e -- "$DATA_DIR" 2>/dev/null || true)"
    [[ -n "$DATA_DIR_REAL" && -d "$DATA_DIR_REAL" ]] || die "The data directory $(printf '%q' "$DATA_DIR") is not a directory (or is a link to nothing). Nothing was changed."
    if [[ "$DATA_DIR_REAL" != "$DATA_DIR" ]]; then
        { _dir_closed "$(dirname -- "$DATA_DIR_REAL")" && ! system_dir "$DATA_DIR_REAL"; } \
            || die "The data directory $(printf '%q' "$DATA_DIR") is a link to $(printf '%q' "$DATA_DIR_REAL"): a system directory, or one in a directory someone other than root can write to. Point it (or CRYPTIRC_DATA) at a directory of its own under directories only root can write, then re-run. Nothing was changed."
    fi
fi

# ── Step 1: where will this run? (domain vs bare IP / self-signed) ─────────────
DOMAIN="$(clean_host "${1:-}")"
EMAIL="${2:-}"
INTERACTIVE=true; [[ -n "$DOMAIN" ]] && INTERACTIVE=false
# No controlling terminal (AI assistant, CI, cloud-init, `ssh host '…'` without -t)?
# Don't prompt — an unguarded read would hit EOF and exit 1 silently under set -e.
[[ ! -t 0 ]] && INTERACTIVE=false
SELF_SIGNED=false
HOSTADDR=""
HOSTADDR2=""

# Best-effort public IPv4 / IPv6 — detected separately (over a v4-only and a
# v6-only connection, respectively) so a dual-stack box gets BOTH, not
# whichever one the OS/resolver happened to prefer for a family-agnostic
# hostname. Used as the self-signed default(s) and the DNS hint(s). Only a
# well-formed address is accepted (never an HTML error / rate-limit page).
detect_public_ip() {   # detect_public_ip -4|-6
    local fam="$1" ip="" url
    for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
        ip="$(curl -fsS "$fam" --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "$fam" == -4 ]] && is_ipv4 "$ip"; then echo "$ip"; return 0; fi
        if [[ "$fam" == -6 ]] && is_ipv6 "$ip"; then echo "$ip"; return 0; fi
    done
    return 0
}
SERVER_IPV4=""; SERVER_IPV6=""
if [[ -n "$DOMAIN" ]] && is_ip "$DOMAIN"; then
    :   # bare-IP install: the address was given, so don't ask third-party services for one
else
    if command -v curl &>/dev/null; then      # (pacman itself depends on curl)
        SERVER_IPV4=$(detect_public_ip -4)
        SERVER_IPV6=$(detect_public_ip -6)
    fi
fi
# Legacy single-value var (kept for the non-interactive bare-IP path below) —
# prefer v4 since that's what most networks/clients still expect by default.
SERVER_IP="${SERVER_IPV4:-$SERVER_IPV6}"

if [[ -z "$DOMAIN" && "$INTERACTIVE" == false ]]; then
    die "No domain or IP was given, and there's no terminal to ask on. Run one of:
    sudo bash deploy/deploy-arch.sh <domain> <email>    # Let's Encrypt certificate
    sudo bash deploy/deploy-arch.sh ${SERVER_IP:-<server-ip>}    # self-signed, served on that IP${SERVER_IP:+ (detected)}
  …or run it from an interactive terminal (e.g. ssh -t) to be asked."
fi

if [[ "$INTERACTIVE" == true ]]; then
    step "[1/6] Server address"
    [[ -n "$SERVER_IPV4" ]] && echo -e "  Detected public IPv4: ${GREEN}${SERVER_IPV4}${NC}"
    [[ -n "$SERVER_IPV6" ]] && echo -e "  Detected public IPv6: ${GREEN}${SERVER_IPV6}${NC}"
    [[ -n "${SERVER_IPV4}${SERVER_IPV6}" ]] && echo ""
    echo -e "  ${DIM}A domain gives you a free, browser-trusted Let's Encrypt certificate."
    echo -e "  No domain? Just press Enter to serve on your IP with a self-signed cert —"
    echo -e "  it works fine; browsers only show a one-time \"proceed anyway\" warning.${NC}\n"
    read -rp "  Domain name (or press Enter to use the IP): " DOMAIN
    DOMAIN="$(clean_host "$DOMAIN")"
    if [[ -n "$DOMAIN" ]] && is_ip "$DOMAIN"; then
        # An IP isn't a domain: Let's Encrypt can't issue for it (and HSTS would lock browsers
        # out of a self-signed cert) — serve that IP in self-signed mode instead.
        echo -e "  ${DIM}That's an IP address, not a domain — serving it with a self-signed certificate.${NC}"
        SELF_SIGNED=true; HOSTADDR="$DOMAIN"
        echo -e "\n  ${CYAN}→ Self-signed mode:${NC} https://$(url_host "$HOSTADDR")  ${DIM}(no domain, no email needed)${NC}"
    elif [[ -z "$DOMAIN" ]]; then
        SELF_SIGNED=true
        if [[ -n "$SERVER_IPV4" && -n "$SERVER_IPV6" ]]; then
            echo -e "\n  Which address should CryptIRC serve on?"
            echo -e "    1) IPv4 — ${SERVER_IPV4} ${DIM}(default)${NC}"
            echo -e "    2) IPv6 — ${SERVER_IPV6}"
            echo -e "    3) Both"
            read -rp "  Choice [1]: " IP_CHOICE
            case "${IP_CHOICE:-1}" in
                2) HOSTADDR="$SERVER_IPV6" ;;
                3) HOSTADDR="$SERVER_IPV4"; HOSTADDR2="$SERVER_IPV6" ;;
                *) HOSTADDR="$SERVER_IPV4" ;;
            esac
        else
            read -rp "  Address to serve on [${SERVER_IP:-type an IP/hostname}]: " HOSTADDR
            HOSTADDR="$(clean_host "${HOSTADDR:-$SERVER_IP}")"
        fi
        [[ -n "$HOSTADDR" ]] || die "No address provided."
        is_ip "$HOSTADDR" || is_hostname "$HOSTADDR" \
            || die "'$HOSTADDR' isn't an IP address or a host name (leave off any http:// and :port)."
        DOMAIN="$HOSTADDR"
        if [[ -n "$HOSTADDR2" ]]; then
            echo -e "\n  ${CYAN}→ Self-signed mode:${NC} https://$(url_host "$HOSTADDR")  and  https://$(url_host "$HOSTADDR2")  ${DIM}(no domain, no email needed)${NC}"
        else
            echo -e "\n  ${CYAN}→ Self-signed mode:${NC} https://$(url_host "$HOSTADDR")  ${DIM}(no domain, no email needed)${NC}"
        fi
    else
        is_domain "$DOMAIN" || die "'$DOMAIN' doesn't look like a domain name (e.g. chat.example.com — no http:// and no :port)."
        read -rp "  Your email (for Let's Encrypt renewal notices): " EMAIL
        [[ -n "$EMAIL" ]] || die "An email is required for a Let's Encrypt domain."
        is_email "$EMAIL" || die "'$EMAIL' doesn't look like an email address."
    fi
else
    # Non-interactive: a bare IP → self-signed; a domain → Let's Encrypt (email required).
    if is_ip "$DOMAIN"; then
        SELF_SIGNED=true; HOSTADDR="$DOMAIN"
        echo -e "\n  ${CYAN}→ Self-signed mode on ${HOSTADDR}${NC}"
    elif is_domain "$DOMAIN"; then
        [[ -n "$EMAIL" ]] || die "Domain install needs an email:  sudo bash deploy/deploy-arch.sh <domain> <email>"
        is_email "$EMAIL" || die "'$EMAIL' doesn't look like an email address."
        echo -e "  Domain : ${GREEN}${DOMAIN}${NC}"
        echo -e "  Email  : ${GREEN}${EMAIL}${NC}"
    else
        die "'$DOMAIN' is neither an IP address nor a domain name (leave off any http:// and :port)."
    fi
fi

URL_HOST="$(url_host "$DOMAIN")"
URL_HOST2=""; [[ -n "$HOSTADDR2" ]] && URL_HOST2="$(url_host "$HOSTADDR2")"

# ── Step 2: DNS check (domain mode only) ──────────────────────────────────────
if [[ "$SELF_SIGNED" == false ]]; then
    step "[2/6] Checking DNS"

    resolve_dns() {   # resolve_dns A|AAAA <domain> — dig → host → getent, family-aware
        local rtype="$1" dom="$2" r=""
        if command -v dig &>/dev/null; then
            # `|| true`: a no-match `grep` exits 1 (a domain with an A record but no AAAA is
            # normal). Called via $(…), where bash doesn't inherit errexit, this can't abort
            # the installer today — the `|| true` keeps it safe if it's ever called directly.
            r=$(dig +short "$rtype" "$dom" 2>/dev/null | grep -E '^[0-9a-fA-F.:]+$' | head -1 || true)
        fi
        if [[ -z "$r" ]] && command -v host &>/dev/null; then
            if [[ "$rtype" == "AAAA" ]]; then
                r=$(host -t AAAA "$dom" 2>/dev/null | grep -E 'has IPv6 address' | head -1 | awk '{print $NF}' || true)
            else
                r=$(host -t A "$dom" 2>/dev/null | grep -E 'has address' | head -1 | awk '{print $NF}' || true)
            fi
        fi
        if [[ -z "$r" ]]; then
            # getent doesn't distinguish families in its output — only trust it
            # for whichever family its result actually looks like.
            local g; g=$(getent hosts "$dom" 2>/dev/null | awk '{print $1}' | head -1 || true)
            [[ "$rtype" == "AAAA" ]] && is_ipv6 "$g" && r="$g"
            [[ "$rtype" == "A" ]] && is_ipv4 "$g" && r="$g"
        fi
        echo "$r"
    }

    DOMAIN_A=$(resolve_dns A "$DOMAIN")
    DOMAIN_AAAA=$(resolve_dns AAAA "$DOMAIN")
    MATCH_V4=false; MATCH_V6=false
    [[ -n "$SERVER_IPV4" && "$DOMAIN_A" == "$SERVER_IPV4" ]] && MATCH_V4=true
    [[ -n "$SERVER_IPV6" && "$DOMAIN_AAAA" == "$SERVER_IPV6" ]] && MATCH_V6=true

    if [[ "$MATCH_V4" == true || "$MATCH_V6" == true ]]; then
        [[ "$MATCH_V4" == true ]] && ok "DNS points here (A):    ${DOMAIN} → ${SERVER_IPV4}"
        [[ "$MATCH_V6" == true ]] && ok "DNS points here (AAAA): ${DOMAIN} → ${SERVER_IPV6}"
    else
        warn "${DOMAIN} doesn't appear to resolve to this server."
        echo -e "  ${DIM}If you use Cloudflare's proxy or IPv6-only DNS this check can be wrong — that's fine.${NC}"
        if [[ -n "$SERVER_IPV4" ]]; then
            echo -e "  ${DIM}Create an A record:     ${DOMAIN} → ${SERVER_IPV4}${NC}"
        fi
        if [[ -n "$SERVER_IPV6" ]]; then
            echo -e "  ${DIM}Create an AAAA record:  ${DOMAIN} → ${SERVER_IPV6}${NC}"
        fi
        [[ -z "${SERVER_IPV4}${SERVER_IPV6}" ]] && echo -e "  ${DIM}Create an A or AAAA record pointing to this server.${NC}"
        if [[ "$INTERACTIVE" == true && -z "${SERVER_IPV4}${SERVER_IPV6}" ]]; then
            # Nothing to compare against — waiting could never succeed, so don't offer it.
            warn "This server's public IP couldn't be detected, so DNS can't be checked here — continuing."
        elif [[ "$INTERACTIVE" == true ]]; then
            echo ""
            read -rp "  Press Enter to wait for DNS (up to ~10 min), or type 'skip' to continue now: " DNS_CHOICE
            if [[ "$DNS_CHOICE" != skip ]]; then
                for ((i=1; i<=20; i++)); do
                    DOMAIN_A=$(resolve_dns A "$DOMAIN"); DOMAIN_AAAA=$(resolve_dns AAAA "$DOMAIN")
                    MATCH_V4=false; MATCH_V6=false
                    [[ -n "$SERVER_IPV4" && "$DOMAIN_A" == "$SERVER_IPV4" ]] && MATCH_V4=true
                    [[ -n "$SERVER_IPV6" && "$DOMAIN_AAAA" == "$SERVER_IPV6" ]] && MATCH_V6=true
                    if [[ "$MATCH_V4" == true || "$MATCH_V6" == true ]]; then
                        ok "DNS resolved! ${DOMAIN} → ${DOMAIN_A:-$DOMAIN_AAAA}"; break
                    fi
                    echo -e "  ${DIM}waiting… (${i}/20, currently: ${DOMAIN_A:-${DOMAIN_AAAA:-nothing}})${NC}"
                    sleep 30
                done
                [[ "$MATCH_V4" == true || "$MATCH_V6" == true ]] || warn "Still not matching — continuing. Let's Encrypt will keep retrying once DNS is correct."
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

# ── Preflight: is something else already on ports 80/443? ─────────────────────
# Caddy needs both. With nginx/apache already there it can't bind, and the install used to
# "succeed" with a dead proxy. Check before the long build; `ss` may be missing on a minimal
# box, in which case this runs again right after the system packages are installed.
WEB_PORTS_CHECKED=false
check_web_ports() {
    [[ "$WEB_PORTS_CHECKED" == false ]] && command -v ss >/dev/null 2>&1 || return 0
    WEB_PORTS_CHECKED=true
    local pid comm unit holders="" units="" known=true
    for pid in $(ss -Hltnp '( sport = :80 or sport = :443 )' 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
        comm="$(cat "/proc/$pid/comm" 2>/dev/null || echo "pid $pid")"
        [[ "$comm" == caddy ]] && continue
        unit="$(sed -n 's#^.*/\([^/]*\.service\)$#\1#p' "/proc/$pid/cgroup" 2>/dev/null | head -1 || true)"
        holders+=" ${unit:-$comm}"
        case "$unit" in nginx.service|apache2.service|httpd.service|lighttpd.service) units+=" $unit" ;; *) known=false ;; esac
    done
    holders="$(echo "$holders" | tr ' ' '\n' | sort -u | xargs)"; units="$(echo "$units" | tr ' ' '\n' | sort -u | xargs)"
    [[ -n "$holders" ]] || return 0
    warn "Ports 80/443 are already in use by: ${BOLD}${holders}${NC}"
    echo -e "  ${DIM}Caddy (which serves CryptIRC over HTTPS and gets its certificate) needs both ports.${NC}"
    if [[ "$INTERACTIVE" == true && "$known" == true && -n "$units" ]]; then
        read -rp "  Stop and disable ${units} so Caddy can take over? [y/N]: " _free
        if [[ "$_free" =~ ^[Yy] ]]; then
            # shellcheck disable=SC2086
            systemctl disable --now $units >/dev/null 2>&1 || true
            WEB_PORTS_CHECKED=false; sleep 1
            if [[ -z "$(ss -Hltn '( sport = :80 or sport = :443 )' 2>/dev/null)" ]]; then ok "Ports 80/443 are free now"; WEB_PORTS_CHECKED=true; return 0; fi
            die "Ports 80/443 are still busy:  $(ss -Hltnp '( sport = :80 or sport = :443 )' 2>/dev/null | head -2)"
        fi
    fi
    die "Free ports 80 and 443 first${units:+ (e.g.  sudo systemctl disable --now ${units})}, then re-run.
  (To keep an existing web server in front instead, see INSTALL.md for a manual install.)"
}
check_web_ports

# ── Step 4: dependencies ──────────────────────────────────────────────────────
step "[4/6] Installing dependencies"
# Full system upgrade — `pacman -Sy` alone is an unsupported partial upgrade on
# rolling Arch (a later `pacman -S` would link against not-yet-installed libs). On a
# personal machine that's a big step (kernel included), so ask first when we can.
if [[ "$INTERACTIVE" == true ]]; then
    echo -e "  ${DIM}Arch is rolling-release: installing packages needs a full system upgrade (pacman -Syu) first.${NC}"
    read -rp "  Run the full system upgrade now? [Y/n]: " WANT_UPGRADE
    [[ "$WANT_UPGRADE" =~ ^[Nn] ]] && die "Cancelled — nothing was changed. CryptIRC can't be installed without a full upgrade (partial upgrades are unsupported on Arch). Run 'sudo pacman -Syu' yourself, then re-run."
fi
# Refresh the keyring FIRST: on a box that hasn't been upgraded in a while, packages are
# signed by keys its old keyring doesn't know yet, and -Syu dies on "unknown trust".
RUN_HINT="Signature / keyring errors? Try:  sudo pacman-key --init && sudo pacman-key --populate archlinux  — then re-run."
run "Refreshing the Arch Linux keyring" pacman -Sy --needed --noconfirm archlinux-keyring
run "Updating system (pacman -Syu)" pacman -Su --noconfirm
RUN_HINT=""
# perl-image-exiftool: uploads of GIF/WebP/AVIF/HEIC/HEIF/TIFF are metadata-stripped with
# exiftool, and fail CLOSED ("exiftool unavailable") without it. (It installs into
# /usr/bin/vendor_perl, which the cryptirc unit below puts on the service PATH.)
run "Installing system packages" pacman -S --needed --noconfirm \
    base-devel curl git openssl python bind-tools ffmpeg perl-image-exiftool iproute2
# The kernel package was upgraded under the running kernel → its modules are gone until a reboot.
if compgen -G "/usr/lib/modules/*/vmlinuz" >/dev/null && [[ ! -d "/usr/lib/modules/$(uname -r)" ]]; then
    warn "The kernel was upgraded — reboot when convenient (CryptIRC doesn't need it to install)."
fi
check_web_ports

# argon2 (used by adduser.sh to hash the admin/user passwords) — from pacman, not
# `pip --break-system-packages`: pip's copy is invisible to pacman (python-argon2-cffi then
# refuses to install over it) and is orphaned by the next Python minor upgrade.
if python3 -c 'import sys; sys.path[:] = [p for p in sys.path if p not in ("", ".")]; import argon2' 2>/dev/null; then
    _a2="$(python3 -c 'import sys; sys.path[:] = [p for p in sys.path if p not in ("", ".")]; import argon2; print(argon2.__file__)' 2>/dev/null || true)"
    if [[ -n "$_a2" ]] && ! pacman -Qo "$_a2" >/dev/null 2>&1; then
        warn "Python argon2 here was installed with pip, not pacman — a future Python upgrade can orphan it."
        echo -e "  ${DIM}To switch: sudo pip uninstall --break-system-packages argon2-cffi argon2-cffi-bindings && sudo pacman -S python-argon2-cffi${NC}"
    fi
else
    run "Installing python-argon2-cffi" pacman -S --needed --noconfirm python-argon2-cffi
fi
# Verify it's actually importable NOW — otherwise the failure is invisible until the
# operator first runs adduser.sh (which does `from argon2 import PasswordHasher`) and
# can't create a single account. Warn loudly rather than discover it later. (Same import path
# as adduser.sh: the cwd is dropped first, so nothing in the current directory is imported.)
if ! python3 -c 'import sys; sys.path[:] = [p for p in sys.path if p not in ("", ".")]; import argon2' 2>/dev/null; then
    warn "Python 'argon2-cffi' is not importable — creating accounts (adduser.sh) will FAIL until it's installed."
    echo -e "  ${DIM}Fix: sudo pacman -S python-argon2-cffi${NC}"
fi

if [[ "$ENABLE_EMAIL" == true ]]; then
    run "Installing Postfix" pacman -S --needed --noconfirm postfix
fi
ok "System packages installed"

# Rust — root's OWN toolchain, preferring Arch's rustup package. root's ~/.cargo/bin isn't on
# sudo's secure_path, so put it on PATH first. The usual Arch setup — the rustup package with
# a default toolchain for a login user only — leaves /usr/bin/rustc as a proxy that refuses to
# run for root; that gets `rustup default stable` for root instead of failing later with a
# misleading build error. Everything is pinned to root's home (no root-owned files in a user's).
ROOT_CARGO_HOME="$ROOT_HOME/.cargo"; ROOT_RUSTUP_HOME="$ROOT_HOME/.rustup"
use_root_rustup() {
    [[ -x "$ROOT_CARGO_HOME/bin/cargo" ]] || return 0
    export CARGO_HOME="$ROOT_CARGO_HOME" RUSTUP_HOME="$ROOT_RUSTUP_HOME"
    case ":$PATH:" in *":$ROOT_CARGO_HOME/bin:"*) ;; *) export PATH="$ROOT_CARGO_HOME/bin:$PATH" ;; esac
}
rust_works() { rustc --version >/dev/null 2>&1 && cargo --version >/dev/null 2>&1; }
use_root_rustup
if rust_works; then
    ok "Rust already installed: $(rustc --version)"
else
    command -v rustup &>/dev/null || echo -e "  ${DIM}Installing Rust (rustup)...${NC}"
    if ! command -v rustup &>/dev/null && ! pacman -S --needed --noconfirm rustup >"$RUN_LOG" 2>&1; then
        _rustup_init="$(mktemp)"
        curl --proto '=https' --tlsv1.2 -sSf -o "$_rustup_init" https://sh.rustup.rs \
            || die "Couldn't install the rustup package or download https://sh.rustup.rs (network?). Re-run once it's reachable."
        run "Installing Rust (rustup, stable toolchain)" env HOME="$ROOT_HOME" CARGO_HOME="$ROOT_CARGO_HOME" RUSTUP_HOME="$ROOT_RUSTUP_HOME" \
            sh "$_rustup_init" -y --profile minimal --default-toolchain stable
        rm -f "$_rustup_init"
        use_root_rustup
    fi
    if ! rust_works; then
        export RUSTUP_HOME="$ROOT_RUSTUP_HOME" CARGO_HOME="$ROOT_CARGO_HOME"
        run "Installing the Rust stable toolchain for root (rustup default stable)" rustup default stable
        use_root_rustup
    fi
    rust_works || die "rustc/cargo still won't run for root. Try:  sudo rustup default stable"
    ok "Rust ready: $(rustc --version)"
fi

# Caddy (in the 'extra' repo on Arch — community was merged into extra in 2023)
if ! command -v caddy &>/dev/null; then
    run "Installing Caddy" pacman -S --needed --noconfirm caddy
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
    # The address families Postfix may use. IPv4 everywhere it works (as before); but an
    # IPv6-only server (an IPv6 default route and no IPv4 one) limited to ipv4 could never
    # deliver a single verification or reset mail. inet_protocols also decides what Postfix
    # LISTENS on, and CryptIRC always hands mail to 127.0.0.1:25 — so IPv4 stays enabled
    # there too ("all": with loopback-only that is 127.0.0.1 and ::1), and outgoing mail
    # tries IPv6 first.
    PF_PROTOCOLS=ipv4
    if [[ -z "$(ip -4 route show default 2>/dev/null || true)" && -n "$(ip -6 route show default 2>/dev/null || true)" ]]; then
        PF_PROTOCOLS=all
        postconf -e "smtp_address_preference = ipv6"
        echo -e "  ${DIM}No IPv4 route on this server — Postfix will send over IPv6.${NC}"
    fi
    postconf -e "inet_protocols = $PF_PROTOCOLS"
    postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
    postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject"
    systemctl enable postfix >/dev/null 2>&1 || true
    # Restart (a plain `enable --now` is a no-op if the package already started it with its
    # stock config) and CHECK it came up — a bad setting used to be reported as configured.
    systemctl restart postfix >/dev/null 2>&1 || true
    _pf_ok=false
    for _ in 1 2 3 4 5; do postfix status >/dev/null 2>&1 && { _pf_ok=true; break; }; sleep 1; done
    if [[ "$_pf_ok" == true ]]; then
        ok "Postfix configured"
    else
        warn "Postfix did NOT start with these settings — verification/reset emails won't send."
        echo -e "    ${DIM}Check:  sudo postfix check  ·  journalctl -u postfix -n 30 --no-pager${NC}"
    fi
    warn "Heads up: email is sent straight from this server, so messages can land in spam"
    echo -e "    ${DIM}or be rejected until you add DNS — a PTR/reverse-DNS record for this IP, an SPF${NC}"
    echo -e "    ${DIM}record, and DKIM signing. A blacklisted VPS IP may be blocked outright; for${NC}"
    echo -e "    ${DIM}reliable delivery, relay Postfix through a provider (Gmail / SES / SendGrid).${NC}"
fi

# Service user + directories
id "$SERVICE_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/bin/nologin "$SERVICE_USER"
mkdir -p "$INSTALL_DIR" "$DATA_DIR_REAL" "$LOG_DIR" /var/log/caddy
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR_REAL" "$LOG_DIR"
chmod 750 "$DATA_DIR_REAL" "$LOG_DIR"
# The services run from here (WorkingDirectory, ExecStart) and never write here (ProtectSystem=strict):
# root:root 0755 — an earlier run under a umask of 077 left it root-only 0700, and an install made by an
# older procedure may have given it to the service account, which could then swap the binaries root
# starts. deploy/unit-env.sh's _secure_install_dir makes the directory, the binaries, the markers and
# .rollback root's — nothing else, never recursively, never through a link; the data and socket
# directories stay the service's wherever they are. The binaries themselves are installed root:root
# 0755 (stage_bin).
_sid_dirs=("$DATA_DIR_REAL"); _sid_warns=(); _sid_svc_refuse=""
while IFS= read -r _sid_l; do
    case "$_sid_l" in
        "DIR "*) _sid_dirs+=("${_sid_l#DIR }") ;; "WARN "*) _sid_warns+=("${_sid_l#WARN }") ;;
        "REFUSE "*) _sid_svc_refuse="${_sid_l#REFUSE }" ;;
    esac
done < <(_sid_service_dirs "$INSTALL_DIR" "$DATA_DIR" "$WEB_IPC_SOCK")
if (( ${#_sid_warns[@]} )); then for _sid_l in "${_sid_warns[@]}"; do warn "$_sid_l"; done; fi
[[ -z "$_sid_svc_refuse" ]] || die "$_sid_svc_refuse"
_sid_rc=0; _sid_out=$(_secure_install_dir "$INSTALL_DIR" "$SERVICE_USER" "${_sid_dirs[@]}") || _sid_rc=$?
_sid_summary "$_sid_out"
[[ -n "$SID_FIXED" ]] && warn "${INSTALL_DIR}: ${SID_FIXED}"
[[ -n "$SID_OTHER" ]] && warn "${INSTALL_DIR}: ${SID_OTHER}"
(( _sid_rc == 0 )) || die "${SID_REFUSE:-the install directory could not be handed to root.}"
chmod go+rx "$INSTALL_DIR"

# Seed admin_settings.json — the authoritative config the Admin panel also edits.
# email_required + captcha_enabled have NO env var, so this is the only way to set
# them at install. Written only on a fresh install; an existing file (e.g. an
# operator's later Admin-panel changes) is never clobbered.
SETTINGS_FILE="$DATA_DIR/admin_settings.json"
if [[ ! -f "$SETTINGS_FILE" ]]; then
    # Write via python3 (already a dependency) so the reg code is correctly JSON-encoded
    # for ANY input — control chars, quotes, unicode — and the file is always valid JSON.
    # An invalid file would make the server silently fall back to open, codeless registration.
    # The data dir belongs to the service account, so nothing here may follow a name in it:
    # the file is created O_CREAT|O_EXCL|O_NOFOLLOW relative to a descriptor for the data dir
    # (never through a symlink, e.g. a dangling one to a system file) and gets its owner and
    # mode with fchown/fchmod on the open descriptor, 0600 from the start (it holds the code).
    _seed_rc=0
    _seed_out="$(CRYPTIRC_S_OPEN="$REG_OPEN" CRYPTIRC_S_CODE="$REG_CODE" \
    CRYPTIRC_S_EMAILREQ="$EMAIL_REQUIRED" CRYPTIRC_S_CAPTCHA="$CAPTCHA_ENABLED" \
    python3 -I - "$DATA_DIR" "$(id -u "$SERVICE_USER")" "$(id -g "$SERVICE_USER")" <<'PY'
import errno, json, os, stat, sys
data_dir, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
b = lambda v: v == "true"
data = json.dumps({
    "registration_open": b(os.environ["CRYPTIRC_S_OPEN"]),
    "registration_code": os.environ["CRYPTIRC_S_CODE"],
    "email_required":    b(os.environ["CRYPTIRC_S_EMAILREQ"]),
    "captcha_enabled":   b(os.environ["CRYPTIRC_S_CAPTCHA"]),
}, indent=2).encode()
NAME = "admin_settings.json"
dfd = os.open(data_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
note = "created"
try:
    fd = os.open(NAME, flags, 0o600, dir_fd=dfd)
except FileExistsError:
    st = os.lstat(NAME, dir_fd=dfd)
    if not stat.S_ISLNK(st.st_mode):
        print("exists")                 # appeared meanwhile (the server wrote it): keep it
        sys.exit(0)
    # A symlink to nowhere (the existence test above found no file behind it) is not
    # settings anything wrote: remove the link itself (unlink never follows) and create
    # the real file in its place.
    os.unlink(NAME, dir_fd=dfd)
    fd = os.open(NAME, flags, 0o600, dir_fd=dfd)
    note = "replaced-symlink"
try:
    os.fchown(fd, uid, gid)             # before fchmod: chown may clear mode bits
    os.fchmod(fd, 0o600)
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]
    os.fsync(fd)
finally:
    os.close(fd)
print(note)
PY
)" || _seed_rc=$?
    if [[ $_seed_rc -ne 0 ]]; then
        warn "Couldn't create $SETTINGS_FILE — registration falls back to the service settings (closed unless set there)."
    elif [[ "$_seed_out" == exists ]]; then
        echo -e "  ${DIM}admin_settings.json exists — keeping current settings.${NC}"
    else
        [[ "$_seed_out" == replaced-symlink ]] && warn "$SETTINGS_FILE was a symlink to a file that doesn't exist — replaced it with a real settings file (the link was not followed)."
        ok "Admin settings seeded (registration · email · captcha)"
    fi
else
    echo -e "  ${DIM}admin_settings.json exists — keeping current settings.${NC}"
fi

# Caddy runs as the 'caddy' user and writes its access log here; make sure it can.
chown caddy:caddy /var/log/caddy 2>/dev/null || true

# IPv6 literals in canonical compressed form (python3 is installed now), so the Caddy site
# address, default_sni and the certificate SAN all match what browsers actually send.
canon_ipv6() { python3 -I -c 'import ipaddress,sys; print(ipaddress.IPv6Address(sys.argv[1]).compressed)' "$1" 2>/dev/null || echo "$1"; }
if [[ "$SELF_SIGNED" == true ]]; then
    is_ipv6 "$HOSTADDR"  && HOSTADDR="$(canon_ipv6 "$HOSTADDR")"
    [[ -n "$HOSTADDR2" ]] && is_ipv6 "$HOSTADDR2" && HOSTADDR2="$(canon_ipv6 "$HOSTADDR2")"
    DOMAIN="$HOSTADDR"
    URL_HOST="$(url_host "$DOMAIN")"
    URL_HOST2=""; [[ -n "$HOSTADDR2" ]] && URL_HOST2="$(url_host "$HOSTADDR2")"
fi

# ── Step 5: build ─────────────────────────────────────────────────────────────
step "[5/6] Building CryptIRC"
echo -e "  ${DIM}The first build can take several minutes, especially with low memory.${NC}\n"
cd "$REPO_DIR"       # SCRIPT_DIR/REPO_DIR were resolved up top (the latest code was pulled there too)
if ! bash "$SCRIPT_DIR/build-release.sh"; then
    die "Build failed (see output above). Check that openssl is installed. If the compiler ran out of memory, add swap or build on a machine with more RAM."
fi
[[ -f target/release/cryptirc ]] || die "Build reported success but target/release/cryptirc is missing."

# Has the irc-core daemon's CODE changed since the running daemon was built? Decided BEFORE
# the new binary is installed. Same marker + formula as deploy/update.sh: a hash of the
# daemon's own sources + Cargo.lock + Cargo.toml minus its version line (the binary itself
# embeds the git sha, so a binary compare would flag every commit). The source list is
# read from update.sh so the two can never drift; the copy below is only a fallback.
HAVE_IRC_CORE=false; [[ -f target/release/irc_core ]] && HAVE_IRC_CORE=true
DAEMON_SRC=(src/bin/irc_core.rs src/ipc_server.rs src/irc_daemon.rs src/ipc.rs src/ipc_framing.rs src/ircproto.rs Cargo.lock)
_ds_line="$(grep -m1 -E '^DAEMON_SRC=\([A-Za-z0-9_./ -]+\)$' "$SCRIPT_DIR/update.sh" 2>/dev/null || true)"
[[ -n "$_ds_line" ]] && eval "$_ds_line"
DAEMON_SRC_HASH=""
_ds_ok=true; for _f in "${DAEMON_SRC[@]}"; do [[ -f "$REPO_DIR/$_f" ]] || _ds_ok=false; done
if [[ "$_ds_ok" == true ]]; then
    DAEMON_SRC_HASH=$( cd "$REPO_DIR" && { cat "${DAEMON_SRC[@]}"; grep -v '^version[[:space:]]*=' Cargo.toml || true; } | sha256sum | cut -d' ' -f1 )
fi
# Is the RUNNING irc-core executing the irc_core file on disk now? (yes | no | down | unknown)
# A daemon started before an earlier run replaced that file still runs the old, deleted
# inode — same check as update.sh.
daemon_runs_ondisk() {
    local pid run_id disk_id
    systemctl is-active --quiet irc-core 2>/dev/null || { echo down; return 0; }
    pid="$(systemctl show -p MainPID --value irc-core 2>/dev/null || true)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || { echo unknown; return 0; }
    run_id="$(stat -L -c '%d:%i' "/proc/$pid/exe" 2>/dev/null || true)"
    disk_id="$(stat -L -c '%d:%i' "$INSTALL_DIR/irc_core" 2>/dev/null || true)"
    if [[ -z "$run_id" || -z "$disk_id" ]]; then echo unknown
    elif [[ "$run_id" == "$disk_id" ]]; then echo yes
    # Another inode with the same bytes is the same daemon: the install-dir hand-back
    # (_secure_install_dir) replaces a binary that wasn't root's by a root-owned copy.
    elif cmp -s "/proc/$pid/exe" "$INSTALL_DIR/irc_core" 2>/dev/null; then echo yes
    else echo no
    fi
}
# What the irc_core file ON DISK was built from — same record and format as update.sh
# ("<source hash> <sha256 of the file>"). After a deferred daemon change .irc-core-srchash is
# stale on purpose; once the daemon has restarted onto the file anyway (a reboot), this says
# what it runs, so a re-run doesn't restart it (dropping everyone's IRC) for nothing.
ondisk_srchash() {
    local rec h s
    rec="$(cat "$INSTALL_DIR/.irc_core.ondisk-srchash" 2>/dev/null)" || return 1
    h="${rec%% *}"; s="${rec#* }"
    [[ "$h" =~ ^[0-9a-f]{64}$ && "$s" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$(sha256sum "$INSTALL_DIR/irc_core" 2>/dev/null | cut -d' ' -f1)" == "$s" ]] || return 1
    printf '%s' "$h"
}
record_ondisk_srchash() {
    local s
    [[ -n "$DAEMON_SRC_HASH" ]] || { rm -f "$INSTALL_DIR/.irc_core.ondisk-srchash"; return 0; }
    s="$(sha256sum "$INSTALL_DIR/irc_core" 2>/dev/null | cut -d' ' -f1)"
    [[ -n "$s" ]] && { echo "$DAEMON_SRC_HASH $s" > "$INSTALL_DIR/.irc_core.ondisk-srchash" 2>/dev/null || true; }
    return 0
}
DAEMON_CHANGED=true
if [[ "$HAVE_IRC_CORE" == true ]]; then
    if [[ -n "$DAEMON_SRC_HASH" && -f "$INSTALL_DIR/.irc-core-srchash" ]]; then
        if [[ "$(cat "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null)" == "$DAEMON_SRC_HASH" ]]; then
            DAEMON_CHANGED=false
        elif [[ "$(ondisk_srchash || true)" == "$DAEMON_SRC_HASH" && "$(daemon_runs_ondisk)" == yes ]]; then
            DAEMON_CHANGED=false     # a deferred change, applied since by a daemon restart
        fi
    elif [[ -f "$INSTALL_DIR/irc_core" ]] && cmp -s target/release/irc_core "$INSTALL_DIR/irc_core"; then
        # No marker yet, but the very same binary is installed — current only if the running
        # daemon (if any) really executes that file.
        case "$(daemon_runs_ondisk)" in yes|down) DAEMON_CHANGED=false ;; esac
    fi
fi

# Stage the new binaries NEXT TO the live ones; they are swapped in by rename(2) only just
# before the services restart (atomic, needs no free space), with the previous ones kept
# until the new version is verified. Copying straight over the live files left a truncated
# binary behind on a full disk, or a new web binary next to an old daemon.
BIN_STATE=""          # "" → staged → swapped → restarted (see on_exit and the swap below)
stage_bin() {   # stage_bin <built file> <name>
    local dst="$INSTALL_DIR/.$2.staged"
    rm -f "$dst"
    if ! install -m 755 -o root -g root "$1" "$dst" || ! cmp -s "$1" "$dst"; then
        rm -f "$INSTALL_DIR/.cryptirc.staged" "$INSTALL_DIR/.irc_core.staged"
        die "Couldn't copy the new $2 binary into $INSTALL_DIR (disk full?). Nothing was replaced — the installed version is untouched."
    fi
}
stage_bin target/release/cryptirc cryptirc
BIN_STATE=staged
ok "CryptIRC built"

# irc_core (the always-on IRC connection daemon). On a modern checkout the web
# binary NO LONGER dials IRC itself — it hands every connection to this daemon
# over a Unix socket, so without it the site would come up but ALL IRC would be
# dead. This deploy script ships FROM the same checkout as the source, so if
# src/bin/irc_core.rs exists then a successful `cargo build --release` MUST have
# produced the binary; its absence means a broken/partial build, and installing
# only the web half would silently strand every IRC connection. Abort loudly in
# that case. (A genuinely old pre-split checkout has no src/bin/irc_core.rs, and
# there cryptirc.service alone really is standalone — so we allow that path.)
if [[ "$HAVE_IRC_CORE" == true ]]; then
    stage_bin target/release/irc_core irc_core
    ok "irc-core daemon built"
elif [[ -f "$REPO_DIR/src/bin/irc_core.rs" || -f src/bin/irc_core.rs ]]; then
    die "Build succeeded but the irc-core daemon binary (target/release/irc_core) is missing.
  This checkout expects the daemon — installing only the web binary would leave the
  site up but every IRC connection dead. Aborting. Re-run 'bash deploy/build-release.sh' and
  check for a build error specific to the irc_core binary."
fi
# Building as root leaves a root-owned target/ (and possibly Cargo.lock / .git files) in the
# checkout. Hand them back to the checkout's owner (after the installs above), so their own
# `cargo build` / `git pull` keeps working. A user can't create root-owned files, so every
# root-owned file in their checkout is ours. -h: never follow a symlink out of the checkout.
_repo_owner="$(stat -c %U:%G "$REPO_DIR" 2>/dev/null || echo root:root)"
if [[ "$_repo_owner" != root:* && "$_repo_owner" != UNKNOWN:* ]]; then
    chown -hR "$_repo_owner" target 2>/dev/null || true
    find "$REPO_DIR" -xdev -user root -exec chown -h "$_repo_owner" {} + 2>/dev/null || true
fi

# ── Step 6: configure TLS + service ───────────────────────────────────────────
step "[6/6] Configuring services"
BACKUPS=()

# ── Across the 0.5.8 data floor: back up users' data first ──
# Upgrading an installed version below 0.5.8 migrates users' data as they unlock, one way. Same
# archive, place and rotation as update.sh (/var/lib/cryptirc-backups, root-only, last 5 kept),
# made before anything is configured or replaced; a failed backup stops the run here.
# CRYPTIRC_NO_BACKUP=1 skips it (as update.sh --no-backup).
BACKUP_DIR=/var/lib/cryptirc-backups
if [[ "$FLOOR_ON" == true && "${CRYPTIRC_NO_BACKUP:-}" != 1 && -d "$DATA_DIR" ]]; then
    _data_real="$(readlink -f -- "$DATA_DIR" 2>/dev/null || true)"
    [[ -n "$_data_real" && -d "$_data_real" ]] || die "Couldn't resolve the data directory $DATA_DIR for the backup — nothing was changed."
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    _bk="$BACKUP_DIR/cryptirc-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    _bk_rc=0
    # A user's directory moved to another disk behind a symlink is archived with what it holds — as the
    # service account, never into a device, FIFO, socket, /proc, /sys or /dev (deploy/data-floor.sh's
    # _backup_data); an archive that still has a symlink member is refused (a link restores no data).
    _bk_msgs="$(mktemp)"
    _backup_data "$_data_real" "$_bk" "$_bk_msgs" || _bk_rc=$?
    _bk_why="$(sed 's/^/    /' "$_bk_msgs")"; rm -f "$_bk_msgs"
    # tar 1 = a file changed while being read (a live log): the archive is still complete.
    if (( _bk_rc > 1 )) || [[ ! -s "$_bk" ]] || ! tar tzf "$_bk" >/dev/null 2>&1 \
       || tar tzvf "$_bk" 2>/dev/null | awk 'substr($1, 1, 1) == "l" { found = 1 } END { exit !found }'; then
        rm -f "$_bk"
        # (Names from the data dir are in $_bk_why: printed as they are, never through die's echo -e.)
        [[ -n "$_bk_why" ]] && printf '%s\n' "$_bk_why" >&2
        die "Backing up $DATA_DIR before the 0.5.8 upgrade failed (exit $_bk_rc${_bk_why:+; see above}) — nothing was changed.
  Check free space (df -h $BACKUP_DIR), or skip the backup this once: CRYPTIRC_NO_BACKUP=1"
    fi
    # shellcheck disable=SC2012  # backup names are fixed-format timestamps
    ls -1t "$BACKUP_DIR"/cryptirc-backup-*.tar.gz 2>/dev/null | tail -n +6 | xargs -r rm -f 2>/dev/null || true
    ok "Upgrading ${PREV_NAME} to v${VERSION} (past 0.5.8): users' data backed up to $_bk"
    [[ -n "$_bk_why" ]] && printf '%s\n' "$_bk_why"
fi

# What the INSTALLED web service is configured with right now — before anything below
# rewrites its unit or env file: its Environment= lines (unit + drop-ins, via systemctl show)
# and its EnvironmentFile=s, but only ones that are root-owned and not group/world-writable.
# Never the running process's /proc/<pid>/environ: that belongs to the unprivileged service
# account, which can rewrite it. Used to keep the current registration fallback for
# settings admin_settings.json doesn't hold, and to recognise the previous install's site.
PREV_ENV_JSON="$(mktemp)"
python3 -I - "$PREV_ENV_JSON" <<'PY' || echo '{}' > "$PREV_ENV_JSON"
import glob, json, os, shlex, stat, subprocess, sys

def sysd(*args):
    try:
        return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return ""

def protected_dirs(path):
    """Every directory on the way to `path` — as written, and as it resolves — is root-owned and
    not writable by group/others (sticky dirs allowed): nobody else can re-point or swap it."""
    for d in (os.path.dirname(os.path.abspath(path)), os.path.dirname(os.path.realpath(path))):
        while True:
            try:
                st = os.stat(d)
            except OSError:
                return False
            if st.st_uid != 0 or (st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX):
                return False
            if d == "/":
                break
            d = os.path.dirname(d)
    return True

def dir_closed(d):
    """Nobody but root can add an entry to `d` (root-owned, not group/world-writable, sticky or
    not) and the directories above it are protected — as deploy/unit-env.sh's _dir_closed."""
    try:
        st = os.stat(d)
    except OSError:
        return False
    if st.st_uid != 0 or st.st_mode & 0o022:
        return False
    return protected_dirs(os.path.join(d, "x"))

def entry_paths(entry):
    """The files one EnvironmentFile= entry makes systemd read, as deploy/unit-env.sh expands
    them (glob(3): matches sorted byte-wise, no dot-files; a wildcard in the file name only, its
    directory — or the nearest existing component above, symlinks resolved — closed). None = a
    wildcard this installer can't trust (a directory part, an open directory, a dangling link)."""
    if not any(c in entry for c in "*?["):
        return [entry]
    d = os.path.dirname(entry)
    if any(c in d for c in "*?["):
        return None
    while not os.path.lexists(d) and d != "/":
        d = os.path.dirname(d)
    if not os.path.exists(d) or not dir_closed(os.path.realpath(d)) or not protected_dirs(os.path.join(d, "x")):
        return None
    return sorted((m for m in glob.glob(entry) if not os.path.basename(m).startswith(".")), key=os.fsencode)

def read_file(path, trusted_only):
    """Text of a regular file, read through ONE descriptor that was checked with fstat (so it
    can't be swapped between the check and the read; O_NONBLOCK: a FIFO can't hang root).
    trusted_only: only a root-owned file that group/others can't write, and a symlink only
    where nobody but root can re-point it. Returns (text, ok); text None = missing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, True
    except OSError:
        return None, False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 1 << 20:
            return None, False
        if trusted_only:
            if st.st_uid != 0 or st.st_mode & 0o022:
                return None, False
            lst = os.lstat(path)
            if stat.S_ISLNK(lst.st_mode):
                if not protected_dirs(path):
                    return None, False
            elif (lst.st_ino, lst.st_dev) != (st.st_ino, st.st_dev):
                return None, False
        with os.fdopen(fd, "rb") as f:
            fd = -1
            return f.read().decode("utf-8", "replace"), True
    except OSError:
        return None, False
    finally:
        if fd >= 0:
            os.close(fd)

def envfile(path, env):
    """systemd EnvironmentFile syntax: KEY=VALUE, "..." with backslash escapes, '...', #/; comments.
    Only a trusted file (see read_file) is read; returns False otherwise."""
    text, ok = read_file(path, True)
    if not ok:
        return False
    if text is None:
        return True
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;" or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v, out, i = v[1:-1], [], 0
            while i < len(v):
                if v[i] == "\\" and i + 1 < len(v):
                    i += 1
                out.append(v[i])
                i += 1
            v = "".join(out)
        elif len(v) >= 2 and v[0] == v[-1] == "'":
            v = v[1:-1]
        env[k] = v
    return True

WANT = ("CRYPTIRC_REGISTRATION", "CRYPTIRC_REG_CODE", "CRYPTIRC_BASE_URL")
res = {"service": False, "env": {}}
if sysd("cat", "cryptirc.service").strip():
    res["service"] = True
    env = {}
    try:
        toks = shlex.split(sysd("show", "-p", "Environment", "--value", "cryptirc"))
    except ValueError:
        # Output this can't parse: what the service runs with is unknown, so the registration
        # fallback fails CLOSED (as for an untrusted file below) instead of reading as "none set".
        toks = []
        res["untrusted"] = "the cryptirc unit's Environment= lines (systemctl show could not be parsed)"
    for t in toks:
        if "=" in t:
            k, v = t.split("=", 1)
            env[k] = v
    for line in sysd("show", "-p", "EnvironmentFiles", "--value", "cryptirc").splitlines():
        entry = line.split(" (ignore_errors=")[0].strip().lstrip("-")
        if not entry:
            continue
        paths = entry_paths(entry)
        if paths is None:                       # a wildcard whose files can't be trusted: fail CLOSED
            res["untrusted"] = entry
            continue
        for path in paths:
            if not envfile(path, env):          # EnvironmentFile= overrides Environment=, as in systemd
                # Not root-owned / writable by others / a re-pointable symlink: its values can't be
                # trusted. If it sets any registration setting — or can't even be read safely — the
                # fallback fails CLOSED instead (see below).
                text, ok = read_file(path, False)
                if not ok or any(line.strip().startswith(w) for line in (text or "").splitlines() for w in WANT):
                    res["untrusted"] = path
    if res.get("untrusted"):
        env.pop("CRYPTIRC_REGISTRATION", None); env.pop("CRYPTIRC_REG_CODE", None)
    res["env"] = {k: env[k] for k in WANT if k in env}
with open(sys.argv[1], "w") as f:
    json.dump(res, f)
PY
chmod 600 "$PREV_ENV_JSON"
PREV_BASE_URL="$(python3 -I -c 'import json, sys
try:
    print(json.load(open(sys.argv[1])).get("env", {}).get("CRYPTIRC_BASE_URL", ""))
except Exception:
    print("")' "$PREV_ENV_JSON" 2>/dev/null || true)"

# put_file NEW DEST MODE BACKUP_PREFIX [keep] — install NEW as DEST only if the content differs,
# first saving the old DEST as BACKUP_PREFIX.<timestamp> (root-only). Sets PUT_CHANGED, PUT_BACKUP,
# PUT_PREV_PERM ("uid gid mode" of the file replaced; empty: there was none) and PUT_REC (the
# record undo_rec takes), and adds the record to CONFIG_TXN.
# - The new content is staged beside the destination and renamed over it: a full disk or an
#   interruption never leaves a half-written or missing config.
# - A symlinked DEST is written through to the file it points at (as before) — the link stays —
#   and everything is decided on THAT file: its owner/mode, never the link's own 0777.
# - A 5th argument "keep" keeps an existing file's owner, group and mode for the new content (an
#   operator's root:caddy 0640 Caddyfile with a DNS-provider token in it stays 0640; nothing is
#   ever widened). Without it, the given MODE and root:root apply (the installer's own files).
# Plain command (not an `if` condition), so `set -e` still guards every step.
put_file() {
    local new="$1" dest="$2" mode="$3" prefix="$4" keep="${5:-}" owner=root group=root target tmp
    PUT_CHANGED=false; PUT_BACKUP=""; PUT_PREV_PERM=""; PUT_REC=""
    target="$dest"
    if [[ -L "$dest" ]]; then
        target="$(readlink -f -- "$dest" 2>/dev/null || true)"
        [[ -n "$target" && -d "$(dirname "$target")" ]] || die "$dest is a symlink to nowhere usable — fix or remove it, then re-run."
    fi
    [[ -e "$target" && ! -f "$target" ]] && die "$target is not a regular file — refusing to replace it."
    if [[ -f "$target" ]] && cmp -s "$new" "$target"; then rm -f "$new"; return 0; fi
    if [[ -f "$target" ]]; then
        PUT_PREV_PERM="$(stat -c '%u %g %a' "$target")"
        [[ "$keep" == keep* ]] && read -r owner group mode <<< "$PUT_PREV_PERM"
        PUT_BACKUP="$prefix.$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$(dirname "$PUT_BACKUP")"
        cp -p "$target" "$PUT_BACKUP"; chmod go-rwx "$PUT_BACKUP"
        BACKUPS+=("$PUT_BACKUP")
    fi
    tmp="$(mktemp "$(dirname "$target")/.$(basename "$target").XXXXXX")" \
        || die "Couldn't create a file next to $target (disk full? read-only?) — it was left as it was."
    if ! { install -m "$mode" -o "$owner" -g "$group" "$new" "$tmp" && mv -f "$tmp" "$target"; }; then
        rm -f "$tmp" "$new"
        die "Couldn't write $target (disk full?) — it was left as it was."
    fi
    rm -f "$new"
    PUT_REC="$target|$PUT_BACKUP|$PUT_PREV_PERM"
    CONFIG_TXN+=("$PUT_REC")
    PUT_CHANGED=true
}
mkdir -p "$CONF_DIR" "$UNIT_BACKUP_DIR"; chmod 700 "$CONF_DIR" "$UNIT_BACKUP_DIR"

# The address(es) the EXISTING self-signed certificate was made for, read before it may be
# regenerated below. The installers only ever made it for the address(es) they served, so a
# CryptIRC site in the main Caddyfile listing exactly those is the previous install's own
# (e.g. one that served both IPv4 and IPv6, re-run for one of them).
PREV_SS_ADDRS=()
if [[ -f "$SS_DIR/cert.pem" ]]; then
    while IFS= read -r _a; do [[ -n "$_a" ]] && PREV_SS_ADDRS+=("$_a"); done < <(
        openssl x509 -in "$SS_DIR/cert.pem" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' \
            | sed -n -E 's/^[[:space:]]*(IP Address|DNS):[[:space:]]*([^[:space:]]+)[[:space:]]*$/\2/p' || true)
fi
CERT_CHANGED=false
CERT_STATE=""       # "replaced": a new pair is in place, and the Caddy config using it hasn't validated yet
CERT_PREV_DIR=""    # root-only copy of the pair it replaced (none = there was no pair before)
SS_NEW=""           # private directory the new pair is generated in
if [[ "$SELF_SIGNED" == true ]]; then
    # Generate a self-signed cert (10 yrs) with the right SAN — IP: for an IP,
    # DNS: for a hostname (modern browsers ignore CN, so the SAN is what matters).
    mkdir -p "$SS_DIR"
    chmod go+rx "$SS_DIR"      # caddy reads the pair through it (a umask-077 run made it 0700)
    # (Re)generate the cert if there isn't one, OR an existing one doesn't cover
    # every address we're serving on (e.g. re-running the installer after the
    # server's IP changed, or after adding a second IP family via "Both"), or it
    # expires within 30 days. EXACT SAN match via openssl -checkip/-checkhost — the
    # old substring grep kept a 203.0.113.10 cert for 203.0.113.1 and never matched
    # OpenSSL's expanded IPv6 notation (so it re-keyed on every "Both" re-run).
    cert_covers() {
        local out
        if is_ip "$1"; then out="$(openssl x509 -in "$SS_DIR/cert.pem" -noout -checkip "$1" 2>/dev/null || true)"
        else out="$(openssl x509 -in "$SS_DIR/cert.pem" -noout -checkhost "$1" 2>/dev/null || true)"; fi
        [[ "$out" == *" does match certificate"* ]]
    }
    NEED_CERT=false
    if [[ ! -f "$SS_DIR/cert.pem" || ! -f "$SS_DIR/key.pem" ]]; then
        NEED_CERT=true
    else
        cert_covers "$HOSTADDR" || NEED_CERT=true
        [[ -n "$HOSTADDR2" ]] && { cert_covers "$HOSTADDR2" || NEED_CERT=true; }
        openssl x509 -in "$SS_DIR/cert.pem" -noout -checkend 2592000 >/dev/null 2>&1 || NEED_CERT=true
    fi
    if [[ "$NEED_CERT" == true ]]; then
        if is_ip "$HOSTADDR"; then SAN="IP:$HOSTADDR"; else SAN="DNS:$HOSTADDR"; fi
        if [[ -n "$HOSTADDR2" ]]; then
            if is_ip "$HOSTADDR2"; then SAN="${SAN},IP:$HOSTADDR2"; else SAN="${SAN},DNS:$HOSTADDR2"; fi
        fi
        # Made in a private directory next to the live pair and renamed into place, so the live
        # key and certificate are never half-written. The pair they replace is kept (root-only,
        # with the other backups) and is put back if the Caddy configuration below doesn't
        # validate or the run stops before that (see restore_cert): Caddy, and every desktop app
        # that pinned that certificate, keep the identity they know.
        SS_NEW="$(mktemp -d "$SS_DIR/.new.XXXXXXXX")"
        run "Generating self-signed certificate" openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$SS_NEW/key.pem" -out "$SS_NEW/cert.pem" -days 3650 \
            -subj "/CN=$HOSTADDR" -addext "subjectAltName=$SAN"
        chown caddy:caddy "$SS_NEW/key.pem" "$SS_NEW/cert.pem" 2>/dev/null || true
        chmod 640 "$SS_NEW/key.pem"; chmod 644 "$SS_NEW/cert.pem"
        if [[ -f "$SS_DIR/key.pem" || -f "$SS_DIR/cert.pem" ]]; then
            CERT_PREV_DIR="$(mktemp -d "$UNIT_BACKUP_DIR/selfsigned.$(date +%Y%m%d-%H%M%S).XXXX")"
            for _f in key.pem cert.pem; do
                [[ -f "$SS_DIR/$_f" ]] && cp -p "$SS_DIR/$_f" "$CERT_PREV_DIR/$_f"
            done
            BACKUPS+=("$CERT_PREV_DIR/ (the previous self-signed key and certificate)")
        fi
        CERT_STATE=replaced
        mv -f "$SS_NEW/key.pem" "$SS_DIR/key.pem"
        mv -f "$SS_NEW/cert.pem" "$SS_DIR/cert.pem"
        rmdir "$SS_NEW" 2>/dev/null || true; SS_NEW=""
        CERT_CHANGED=true
    fi
    chown caddy:caddy "$SS_DIR/key.pem" "$SS_DIR/cert.pem" 2>/dev/null || true
    chmod 640 "$SS_DIR/key.pem"; chmod 644 "$SS_DIR/cert.pem"
fi

# ── Caddy configuration ──
# CryptIRC's site lives in its own file, /etc/caddy/conf.d/cryptirc.caddy. The main
# Caddyfile is either fully managed here (fresh box, the package's stock welcome page,
# or a file only an earlier CryptIRC installer wrote) or — when it serves OTHER sites — kept
# as it is, with only the import line (and, in IP mode, default_sni) added. Other sites are
# never dropped. Every file replaced is backed up first, and nothing is touched unless it
# validates.
CADDY_MAIN=/etc/caddy/Caddyfile
CADDY_CONFD=/etc/caddy/conf.d
CADDY_SITE="$CADDY_CONFD/cryptirc.caddy"
CADDY_MARK="# Managed by the CryptIRC installer"
CADDY_TAG="# cryptirc-installer"     # marks each line added to a Caddyfile we don't own
mkdir -p "$CADDY_CONFD"
chmod go+rx "$CADDY_CONFD"     # caddy (an unprivileged user) lists and reads it (a umask-077 run made it 0700)

# The name SNI-less clients get a certificate for. Browsers send no SNI for https://<IP>,
# and behind NAT (AWS/GCP/Azure/Oracle, home port-forwards) Caddy can't pick the cert by the
# box's local address, so without this every handshake to the public IP failed.
SNI_ADDR="$HOSTADDR"

# "managed" | "merge": can the main Caddyfile be (re)written wholesale? Only if EVERY
# top-level block in it is one an installer wrote (or the package's welcome page):
#   - CryptIRC's own site: nothing but the installers' directives (a reverse_proxy to
#     127.0.0.1:9001, encode, the header lines installers wrote, our log file, our tls) AND
#     serving ONLY this install's addresses — the one(s) being installed, the previous
#     install's CRYPTIRC_BASE_URL, or the address(es) its self-signed certificate was made for.
#     A site that also lists an address of the operator's own (an alias), or carries a header
#     the operator added, is theirs: it is kept;
#   - its http→https redirect: `redir https://{host}{uri}` for http:// of those addresses;
#   - the package's welcome page, `:80` (Debian) or `http://` (Arch) { root * /usr/share/caddy; file_server };
#   - global options limited to admin / email / default_sni, and our conf.d import.
# Anything else — another site (even a bare redirect, or one that also proxies :9001), a
# snippet, another import — means the operator serves other things from this file: it is
# KEPT ("merge"), and only gets tagged lines added. That also applies to a file an earlier
# run of this installer generated (the header mark is not trusted): a site added to it
# later survives.
caddy_main_mode() {
    [[ -f "$CADDY_MAIN" ]] || { echo managed; return 0; }
    # This install's addresses: the one(s) being installed, the previous install's URL, and
    # what the previous self-signed certificate covered.
    python3 -I - "$CADDY_MAIN" "$DOMAIN" "${HOSTADDR2:-}" "$PREV_BASE_URL" "${PREV_SS_ADDRS[@]}" <<'PY' 2>/dev/null || echo merge
import ipaddress, sys

def host_of(a):
    """Comparable host of a site address / URL: no scheme, port, brackets, path or case."""
    a = a.strip().rstrip(",").lower()
    rest = a.split("://", 1)[1] if "://" in a else a
    rest = rest.split("/", 1)[0]
    if rest.startswith("["):
        h = rest[1:rest.find("]")] if "]" in rest else rest[1:]
    elif rest.count(":") >= 2:
        h = rest                                    # a bare IPv6 literal
    else:
        h = rest.rsplit(":", 1)[0] if ":" in rest else rest
    h = h.rstrip(".")
    try:
        h = ipaddress.ip_address(h).compressed
    except ValueError:
        pass
    return h

def lex(text):
    toks, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            toks.append("\n"); i += 1
        elif c in " \t\r":
            i += 1
        elif c == "#":                              # a comment runs to the end of the line
            while i < n and text[i] != "\n":
                i += 1
        elif c in "\"`":                             # quoted token (kept with its quote mark)
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if c == "\"" and text[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(text[j]); j += 1
            if j >= n:
                raise ValueError("unterminated quote")
            toks.append(c + "".join(buf)); i = j + 1
        else:
            j = i
            while j < n and text[j] not in " \t\r\n":
                j += 1
            t = text[i:j]
            if t.startswith("<<"):
                raise ValueError("heredoc")         # not something an installer wrote
            toks.append(t); i = j
    return toks

def parse(toks):
    pos = 0
    def block(top):
        nonlocal pos
        out, cur = [], []
        while pos < len(toks):
            t = toks[pos]; pos += 1
            if t == "\n":
                if cur:
                    out.append((cur, None)); cur = []
            elif t == "{":
                out.append((cur, block(False))); cur = []
            elif t == "}":
                if top:
                    raise ValueError("unbalanced }")
                if cur:
                    out.append((cur, None))
                return out
            else:
                cur.append(t)
        if not top:
            raise ValueError("unclosed {")
        if cur:
            out.append((cur, None))
        return out
    return block(True)

uq = lambda t: t[1:] if t[:1] in ("\"", "`") else t
UPSTREAMS = {"127.0.0.1:9001", "localhost:9001", "127.0.0.1:9000", "localhost:9000"}
INSTALLER_HEADERS = (["Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"],
                     ["X-Robots-Tag", "noindex, nofollow"], ["-Server"])
INSTALLER_HEADER_LINES = (["header", "@static", "Cache-Control", "public, max-age=3600"],    # deploy/Caddyfile,
                          ["header", "@static", "Cache-Control", "public, max-age=3600, stale-while-revalidate=86400"],
                          ["header", "@sw", "Cache-Control", "public, max-age=0"])          # March 2026 installers

def proxy_site(kids):
    """Only the directives the installers ever wrote, including a reverse_proxy to CryptIRC."""
    proxied = False
    for toks, sub in kids:
        d = uq(toks[0])
        if d == "reverse_proxy":
            if len(toks) != 2 or uq(toks[1]) not in UPSTREAMS:
                return False
            if any(uq(t[0]) not in ("header_up", "health_uri", "health_interval", "health_timeout") or s
                   for t, s in (sub or [])):
                return False
            proxied = True
        elif d == "encode":
            if sub:
                return False
        elif d == "header":
            # Only the header lines installers ever wrote; anything else is the operator's.
            if len(toks) == 1:
                if not sub or any(s or [uq(x) for x in t] not in INSTALLER_HEADERS for t, s in sub):
                    return False
            elif sub or [uq(x) for x in toks] not in INSTALLER_HEADER_LINES:
                return False
        elif d.startswith("@"):
            if len(toks) != 1 or not sub or any(uq(t[0]) != "path" or s for t, s in sub):
                return False
        elif d == "log":
            if len(toks) != 1:
                return False
            for t, s in (sub or []):
                k = uq(t[0])
                if k == "output":
                    if [uq(x) for x in t[1:]] != ["file", "/var/log/caddy/cryptirc.log"]:
                        return False
                    if any(uq(t3[0]) not in ("roll_size", "roll_keep", "roll_keep_for") or s3 for t3, s3 in (s or [])):
                        return False
                elif k != "format":
                    return False
        elif d == "tls":
            args = [uq(x) for x in toks[1:]]
            if sub or not (args == ["/etc/caddy/selfsigned/cert.pem", "/etc/caddy/selfsigned/key.pem"]
                           or args == ["internal"] or (len(args) == 1 and "@" in args[0])):
                return False
        else:
            return False
    return proxied

def main():
    path, known = sys.argv[1], {host_of(h) for h in sys.argv[2:] if h}
    known.discard("")
    tree = parse(lex(open(path, encoding="utf-8", errors="replace").read()))
    sites, redirects = [], []
    for toks, kids in tree:
        if kids is None:                            # a top-level line: only our conf.d import
            if [uq(t) for t in toks] not in (["import", "/etc/caddy/conf.d/*"], ["import", "/etc/caddy/conf.d/cryptirc.caddy"]):
                return "merge"
        elif not toks:                              # global options
            if any(uq(t[0]) not in ("admin", "email", "default_sni") or s for t, s in kids):
                return "merge"
        elif toks[0].startswith("("):               # a snippet
            return "merge"
        elif [uq(t) for t in toks] in ([":80"], ["http://"]) and kids and all(
                ([uq(x) for x in t], s) in ((["root", "*", "/usr/share/caddy"], None), (["file_server"], None))
                for t, s in kids):
            continue                                # the package's welcome page
        elif proxy_site(kids):
            sites.append([uq(t) for t in toks])
        else:
            redirects.append(([uq(t) for t in toks], kids))
    ours = set(known)
    for addrs in sites:
        hosts = {host_of(a) for a in addrs}
        if not hosts <= known:
            return "merge"                          # CryptIRC on (also) an address that isn't this install's
    for addrs, kids in redirects:
        if len(kids) != 1 or kids[0][1] is not None:
            return "merge"
        r = [uq(t) for t in kids[0][0]]
        if r[0] != "redir" or len(r) not in (2, 3) or (len(r) == 3 and r[2] not in ("permanent", "301", "302", "307", "308")):
            return "merge"
        if not all(a.rstrip(",").lower().startswith("http://") and host_of(a) in ours for a in addrs if a.rstrip(",")):
            return "merge"
        if r[1] != "https://{host}{uri}" and not (r[1].startswith("https://") and r[1].endswith("{uri}")
                                                  and host_of(r[1][:-len("{uri}")]) in ours):
            return "merge"
    return "managed"

try:
    print(main())
except Exception:
    print("merge")
PY
}

# The client address Caddy passes on. {client_ip} (Caddy 2.7+) is the TCP peer — like {remote_host} —
# unless the operator lists a CDN / load balancer in Caddy's global `servers { trusted_proxies … }`
# (in the main Caddyfile, which is then kept as theirs): then it is the real client from the
# CDN's headers, and CryptIRC rate-limits per user instead of per CDN address. Older Caddy
# doesn't know {client_ip}: {remote_host} there (see INSTALL.md, "Client IP addresses").
# But by default Caddy takes that client from the LEFT of X-Forwarded-For — the part the client
# writes itself (a CDN appends the address it saw) — so with trusted_proxies alone anyone could
# name a new address for every login try. {client_ip} is used only when Caddy's servers either trust
# no proxy, or read from the right (trusted_proxies_strict, Caddy 2.8+), or take the client from
# headers other than X-Forwarded-For (client_ip_headers, e.g. Cloudflare's CF-Connecting-IP).
# caddy_proxy_trust: safe | unsafe | unknown, from the main Caddyfile as Caddy reads it.
caddy_proxy_trust() {
    local json
    json="$(caddy adapt --config "$CADDY_MAIN" --adapter caddyfile 2>/dev/null)" || { echo unknown; return 0; }
    printf '%s' "$json" | python3 -I -c '
import json, sys
try:
    cfg = json.load(sys.stdin)
    servers = (((cfg.get("apps") or {}).get("http") or {}).get("servers") or {})
    for s in servers.values():
        if not s.get("trusted_proxies") or s.get("trusted_proxies_strict"):
            continue
        if "x-forwarded-for" in [str(h).lower() for h in (s.get("client_ip_headers") or ["X-Forwarded-For"])]:
            print("unsafe"); sys.exit(0)
    print("safe")
except Exception:
    print("unknown")
' 2>/dev/null || echo unknown
    return 0
}
CADDY_MODE="$(caddy_main_mode)"
CADDY_CLIENT='{remote_host}'
_cv="$(caddy version 2>/dev/null | grep -oE '^v?[0-9]+\.[0-9]+' | head -1 || true)"; _cv="${_cv#v}"
if [[ "$_cv" =~ ^([0-9]+)\.([0-9]+)$ ]] && (( BASH_REMATCH[1] > 2 || ( BASH_REMATCH[1] == 2 && BASH_REMATCH[2] >= 7 ) )); then
    CADDY_CLIENT='{client_ip}'
    # (A main Caddyfile this run regenerates has no servers options: nothing to check.)
    if [[ "$CADDY_MODE" == merge ]]; then
        case "$(caddy_proxy_trust)" in
            safe) ;;
            unsafe)
                CADDY_CLIENT='{remote_host}'
                warn "Your Caddy trusts proxies (trusted_proxies) but takes the client from the LEFT of X-Forwarded-For — the part a client writes itself — so anyone could name a new address for each login try."
                echo -e "  ${DIM}CryptIRC's site passes the connecting address ({remote_host}) until $CADDY_MAIN's servers options add trusted_proxies_strict (Caddy 2.8+) or client_ip_headers with your CDN's own header (Cloudflare: CF-Connecting-IP). See INSTALL.md, \"Client IP addresses behind a proxy\".${NC}" ;;
            *)
                CADDY_CLIENT='{remote_host}'
                echo -e "  ${DIM}(Couldn't read Caddy's proxy settings from $CADDY_MAIN — CryptIRC's site passes the connecting address, {remote_host}.)${NC}" ;;
        esac
    fi
fi
# Shared body of CryptIRC's HTTPS site. $1 = "hsts" adds the HSTS header (domain mode
# only — on a self-signed cert it would lock browsers out of the click-through).
caddy_site_body() {
    cat <<CADDY
    reverse_proxy 127.0.0.1:9001 {
        header_up Host {host}
        header_up X-Real-IP $CADDY_CLIENT
        header_up X-Forwarded-For $CADDY_CLIENT
        header_up X-Forwarded-Proto {scheme}
    }
    encode zstd gzip
    header {
CADDY
    [[ "${1:-}" == hsts ]] && echo '        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
    cat <<'CADDY'
        X-Robots-Tag "noindex, nofollow"
        -Server
    }
    log {
        output file /var/log/caddy/cryptirc.log {
            roll_size 10mb
            roll_keep 5
        }
        # Keep one-time secrets out of the access log: email-verify / password-reset
        # tokens and paste passwords travel in the query string (and the Referer of a
        # page opened from such a link would repeat them).
        format filter {
            request>uri query {
                replace token REDACTED
                replace password REDACTED
            }
            request>headers>Referer delete
        }
    }
CADDY
}

_site="$(mktemp)"
{
    echo "$CADDY_MARK ($(basename "${BASH_SOURCE[0]}")): CryptIRC's own site, regenerated on"
    echo "# every installer run (the previous version is kept as /etc/caddy/cryptirc.caddy.bak.<time>)."
    echo ""
    if [[ "$SELF_SIGNED" == true ]]; then
        # Caddyfile site addresses: space-separated so ONE block handles both
        # families when "Both" was chosen — Caddy matches any listed address.
        HTTP_HOSTS="http://$URL_HOST"; HTTPS_HOSTS="https://$URL_HOST"
        if [[ -n "$URL_HOST2" ]]; then
            HTTP_HOSTS="$HTTP_HOSTS http://$URL_HOST2"
            HTTPS_HOSTS="$HTTPS_HOSTS https://$URL_HOST2"
        fi
        echo "$HTTP_HOSTS {"
        echo "    redir https://{host}{uri}"
        echo "}"
        echo ""
        echo "$HTTPS_HOSTS {"
        echo "    tls $SS_DIR/cert.pem $SS_DIR/key.pem"
        caddy_site_body
        echo "}"
    else
        echo "$URL_HOST {"
        echo "    tls $EMAIL"
        caddy_site_body hsts
        echo "}"
    fi
} > "$_site"

_main="$(mktemp)"
if [[ "$CADDY_MODE" == managed ]]; then
    {
        echo "$CADDY_MARK ($(basename "${BASH_SOURCE[0]}")) — regenerated on every installer run;"
        echo "# the previous version is kept as /etc/caddy/Caddyfile.bak.<time>."
        echo "# CryptIRC's site is in $CADDY_SITE. Put OTHER sites in their own"
        echo "# $CADDY_CONFD/<name>.caddy file: they're imported below and survive re-runs."
        echo "{"
        echo "    # Admin API on a caddy-only unix socket, not TCP :2019 (where any local user could"
        echo "    # rewrite the config). This is what \`systemctl reload caddy\` talks to."
        echo "    admin \"unix//run/caddy/admin.socket\""
        if [[ "$SELF_SIGNED" == true ]]; then
            echo "    # Browsers send no SNI to https://<IP>; behind NAT Caddy can't choose the cert by"
            echo "    # the local address, so name the one SNI-less clients get."
            echo "    default_sni $SNI_ADDR $CADDY_TAG"
        fi
        echo "}"
        echo ""
        echo "import $CADDY_CONFD/*"
    } > "$_main"
else
    # The operator's own Caddyfile: drop what an earlier run added (tagged lines), then add
    # back only what's needed. Their sites, options and comments are left exactly as they are.
    grep -vF "$CADDY_TAG" "$CADDY_MAIN" > "$_main" || true
    if grep -qF "$CADDY_MARK" "$CADDY_MAIN"; then
        # A file this installer generated, with sites added to it since: it is no longer
        # regenerated (that would drop them). Its own untagged default_sni (written by
        # earlier versions) is ours to update.
        sed -i -E '/^[[:space:]]*default_sni[[:space:]]/d' "$_main"
        warn "$CADDY_MAIN now also serves sites of its own — it is kept as it is (only CryptIRC's tagged lines are updated)."
        echo -e "  ${DIM}Tip: move those sites into their own files in $CADDY_CONFD/ — they are imported, and the installer then manages $CADDY_MAIN again.${NC}"
    fi
    if [[ "$SELF_SIGNED" == true ]]; then
        if grep -Eq '^[[:space:]]*default_sni[[:space:]]' "$_main"; then
            grep -Eq "^[[:space:]]*default_sni[[:space:]]+${SNI_ADDR//./\\.}([[:space:]]|$)" "$_main" \
                || warn "Your Caddyfile sets its own default_sni — clients that send no SNI (bare-IP URLs behind NAT) get that site's certificate."
        elif [[ "$(sed -e 's/#.*$//' -e '/^[[:space:]]*$/d' "$_main" | head -1 | tr -d '[:space:]')" == "{" ]]; then
            awk -v add="    default_sni $SNI_ADDR $CADDY_TAG" '
                !done { l = $0; sub(/#.*$/, "", l); gsub(/[ \t]/, "", l); if (l == "{") { print; print add; done = 1; next } }
                { print }' "$_main" > "$_main.n" && mv "$_main.n" "$_main"
        else
            { printf '{ %s\n    default_sni %s %s\n} %s\n\n' "$CADDY_TAG" "$SNI_ADDR" "$CADDY_TAG" "$CADDY_TAG"; cat "$_main"; } > "$_main.n" && mv "$_main.n" "$_main"
        fi
    fi
    if ! grep -Eq '^[[:space:]]*import[[:space:]]+/etc/caddy/conf\.d/(\*|cryptirc\.caddy)([[:space:]]|$)' "$_main"; then
        printf '\nimport %s %s\n' "$CADDY_SITE" "$CADDY_TAG" >> "$_main"
    fi
fi
# Normalize indentation (Caddy otherwise warns "input is not formatted") — whitespace only.
caddy fmt --overwrite "$_site" >/dev/null 2>&1 || true
[[ "$CADDY_MODE" == managed ]] && { caddy fmt --overwrite "$_main" >/dev/null 2>&1 || true; }

# Install both, validate the result, and put the old files back if it doesn't validate.
put_file "$_site" "$CADDY_SITE" 644 /etc/caddy/cryptirc.caddy.bak
_site_changed=$PUT_CHANGED
# The main Caddyfile keeps its owner/group/mode (it may be the operator's, with secrets in it).
put_file "$_main" "$CADDY_MAIN" 644 /etc/caddy/Caddyfile.bak keep
_main_changed=$PUT_CHANGED
if ! caddy validate --config "$CADDY_MAIN" --adapter caddyfile >"$RUN_LOG" 2>&1; then
    grep -v '"level":"info"' "$RUN_LOG" | tail -n 15 >&2 || true
    # (Only the two Caddy files are in CONFIG_TXN at this point: they go back as they were.)
    restore_configs
    _cert_note=""; [[ "$CERT_STATE" == replaced ]] && _cert_note=" (and the self-signed certificate)"
    restore_cert
    die "The Caddy configuration didn't validate (see above) — your previous Caddy files${_cert_note} were put back.
  If it says a site is defined more than once, $CADDY_MAIN already serves that address:
  remove that block (other sites stay) and re-run."
fi
# (The new self-signed pair stays CERT_STATE=replaced — put back by any exit, like the config files
# that use it — until the commit below, after the services are restarted on them.)
CADDY_CHANGED=false
[[ "$_site_changed" == true || "$_main_changed" == true || "$CERT_CHANGED" == true ]] && CADDY_CHANGED=true
# Debian's caddy package has no /run/caddy (Arch's creates it via tmpfiles.d), so give the
# unit a RuntimeDirectory for the admin socket — only when we manage the main Caddyfile.
if [[ "$CADDY_MODE" == managed && ! -f /usr/lib/tmpfiles.d/caddy.conf && ! -f /lib/tmpfiles.d/caddy.conf ]]; then
    mkdir -p /etc/systemd/system/caddy.service.d
    _dropin="$(mktemp)"
    printf '%s\n' "# Added by the CryptIRC installer: /run/caddy holds Caddy's admin socket (see /etc/caddy/Caddyfile)." \
        '[Service]' 'RuntimeDirectory=caddy' > "$_dropin"
    put_file "$_dropin" /etc/systemd/system/caddy.service.d/cryptirc-admin-socket.conf 644 "$UNIT_BACKUP_DIR/caddy-cryptirc-admin-socket.conf"
    [[ "$PUT_CHANGED" == true ]] && { systemctl daemon-reload; CADDY_CHANGED=true; }
fi
if [[ "$CADDY_MODE" == merge ]]; then
    ok "Caddy configured — your existing Caddyfile was kept; CryptIRC's site was added via $CADDY_SITE"
else
    ok "Caddy configured"
fi

# ── systemd units ──
# irc-core unit — the always-on IRC connection daemon. Installed from the annotated
# deploy/irc-core.service (same paths/user as this script) — VERBATIM for /var/lib/cryptirc, so a
# fresh Debian or Arch install gets the identical, fully hardened unit and update.sh — which
# compares against that file — sees a stock unit it can refresh; for a data dir (or socket) the
# installed service keeps elsewhere, with those paths in it. Like update.sh, only a STOCK unit (one
# a CryptIRC release or installer wrote) is replaced: one with local changes — a custom socket, a
# moved data dir from update.sh's migration, the operator's own limits — is kept as it is.
# Enabled and started BEFORE cryptirc.service further down (cryptirc.service has
# After=irc-core.service).
IRC_CORE_UNIT_CHANGED=false
IRC_CORE_UNIT_CUSTOM=false
IRC_CORE_UNIT_BAK=""      # the unit this run replaced (empty: none, or unchanged) — for a rollback
IRC_CORE_UNIT_REC=""
if [[ "$HAVE_IRC_CORE" == true ]]; then
    [[ -f "$SCRIPT_DIR/irc-core.service" ]] || die "deploy/irc-core.service is missing from this checkout."
    # The web's own socket goes into the unit where the daemon would otherwise listen elsewhere —
    # nothing in its settings names a socket and the web's isn't <data dir>/irc-core.sock — or where
    # this very file named it (a drop-in or an EnvironmentFile that names it survives anyway).
    _core_sock=""
    if [[ -n "$WEB_IPC_SOCK" && "$WEB_IPC_SOCK" != "${DATA_DIR%/}/irc-core.sock" ]]; then
        _rc=0; _unit_env irc-core.service CRYPTIRC_IPC_SOCK >/dev/null 2>&1 || _rc=$?
        if (( _rc == 1 )) || grep -qsE '^[[:space:]]*Environment=.*CRYPTIRC_IPC_SOCK=' /etc/systemd/system/irc-core.service; then
            _core_sock="$WEB_IPC_SOCK"
        fi
    fi
    _u="$(mktemp)"; _irc_core_unit_subst "$DATA_DIR" "$_core_sock" < "$SCRIPT_DIR/irc-core.service" > "$_u"
    _iu=/etc/systemd/system/irc-core.service
    if [[ -e "$_iu" || -L "$_iu" ]] && [[ "$(_unit_body "$_iu")" != "$(_unit_body "$_u")" ]]; then
        _h="$(_unit_norm_hash < "$_iu" 2>/dev/null || true)"
        _stock="$(_stock_unit_hashes "$DATA_DIR" "$_core_sock"; if [[ -n "$WEB_IPC_SOCK" ]]; then _stock_unit_hashes "$DATA_DIR" "$WEB_IPC_SOCK"; fi)"
        # (an empty / unreadable file hashes to e3b0c4…: never "stock")
        if [[ "$_h" == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
              || $'\n'"$_stock"$'\n' != *$'\n'"$_h"$'\n'* ]]; then
            IRC_CORE_UNIT_CUSTOM=true
        fi
    fi
    if [[ "$IRC_CORE_UNIT_CUSTOM" == true ]]; then
        rm -f "$_u"
        warn "$_iu has local changes (it is not a unit any CryptIRC release or installer wrote) — kept as it is, not replaced."
        echo -e "  ${DIM}Compare it with deploy/irc-core.service yourself (Type=notify + WatchdogSec, StartLimitIntervalSec=0, the hardening).${NC}"
    else
        # A socket outside the data dir needs its directory (on /run, systemd makes it: RuntimeDirectory).
        if [[ -n "$_core_sock" ]]; then
            _sd="$(dirname -- "$_core_sock")"
            if [[ "$_sd/" != "${DATA_DIR%/}/"* && "$_sd" != /run/* && "$_sd" != /var/run/* && ! -d "$_sd" ]]; then
                install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$_sd" || die "Couldn't create the irc-core socket directory $_sd."
            fi
        fi
        put_file "$_u" "$_iu" 644 "$UNIT_BACKUP_DIR/irc-core.service"
        IRC_CORE_UNIT_CHANGED=$PUT_CHANGED; IRC_CORE_UNIT_BAK=$PUT_BACKUP; IRC_CORE_UNIT_REC=$PUT_REC
        # Reload right after writing this unit (not batched with cryptirc's, further
        # down) so an interruption between the two units still leaves systemd's
        # view of THIS one consistent.
        [[ "$IRC_CORE_UNIT_CHANGED" == true ]] && systemctl daemon-reload
        ok "irc-core service unit installed"
    fi
fi

# The registration fallback (used only if admin_settings.json is ever missing) mirrors
# admin_settings.json, so a re-run keeps the CURRENT settings instead of resetting the
# fallback to "closed, no code". The code goes into a root-only EnvironmentFile: any local
# user can read a unit's Environment= lines (`systemctl show`), and systemd would expand
# `%` specifiers in them (50%off → 50<hostname>ff). EnvironmentFile values are literal;
# inside "…" only \ " ` $ need a backslash.
# A setting that admin_settings.json does NOT hold (it only gets one once it is saved in the
# Admin panel; saving e.g. link-preview settings creates the file without them) falls back
# to the environment in the server too (src/main.rs) — so for those the fallback keeps what
# the installed service runs with NOW, instead of turning a closed or code-gated instance
# into open, code-less registration. No previous service at all → closed, no code.
_env="$(mktemp)"
# Lines of the existing env file that are not the installer's own (settings an operator added
# there, e.g. CRYPTIRC_TRUSTED_PROXIES or CRYPTIRC_AI_ALLOW_PRIVATE) are carried over as they are.
_reg_rc=0
_reg_out="$(python3 -I - "$SETTINGS_FILE" "$_env" "$PREV_ENV_JSON" "$ENV_FILE" <<'PY'
import json, os, stat, sys

def read_text(path):
    """A regular file's text, never through a symlink (O_NOFOLLOW) and never blocking on a FIFO."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > 1 << 20:
            raise OSError("not a regular file")
        return f.read().decode("utf-8", "replace")

try:
    prev = json.load(open(sys.argv[3]))
except Exception:
    prev = {}
penv, had_service = prev.get("env", {}), prev.get("service") is True
kept = []
if prev.get("untrusted"):
    # An EnvironmentFile that the service account (or anyone but root) could have written
    # set the registration policy: don't carry it over — fail closed for missing settings.
    had_service, penv = False, {}
    kept.append("NOT the settings in %s (it can't be trusted: not root-owned, writable by others, a symlink others can re-point, or unreadable) — registration closed until set in the Admin panel" % prev["untrusted"])
try:
    # (The data dir belongs to the service account: never read through a link planted there.)
    d = json.loads(read_text(sys.argv[1]))
    if not isinstance(d, dict):
        raise ValueError
    # Same rule as the server: the JSON value counts only when it has the right type.
    if isinstance(d.get("registration_open"), bool):
        reg_open = d["registration_open"]
    elif had_service:
        reg_open = penv.get("CRYPTIRC_REGISTRATION", "open") != "closed"
        kept.append("registration " + ("open" if reg_open else "closed"))
    else:
        reg_open = False
    if isinstance(d.get("registration_code"), str):
        code = d["registration_code"]
    elif had_service:
        code = penv.get("CRYPTIRC_REG_CODE", "")
        kept.append("registration code " + ("set" if code else "none"))
    else:
        code = ""
except Exception:
    reg_open, code = False, ""          # unreadable → fail closed, like the app does
HEADER = [
    "# CryptIRC — written by the installer. Root-only (0600): systemd reads it, local users",
    "# can't (unlike Environment= lines, which `systemctl show` reveals to everyone).",
    "# Fallback only — admin_settings.json (Settings -> Admin) is authoritative.",
]
OWN = "# Your own settings below are kept as they are when the installer runs again:"
own = []
try:
    old = read_text(sys.argv[4]).splitlines()
except FileNotFoundError:
    old = []
for line in old:
    line = line.rstrip("\r")
    t = line.strip()
    if line in HEADER or t == OWN:
        continue
    if "=" in t and t.split("=", 1)[0].strip() == "CRYPTIRC_REG_CODE":
        continue                        # the installer's own setting, written fresh below
    own.append(line)
while own and not own[0].strip():
    own.pop(0)
while own and not own[-1].strip():
    own.pop()
esc = "".join("\\" + c if c in '\\"`$' else c for c in code)
with open(sys.argv[2], "w") as f:
    f.write("\n".join(HEADER) + "\n")
    f.write('CRYPTIRC_REG_CODE="%s"\n' % esc)
    if own:
        f.write("\n" + OWN + "\n" + "\n".join(own) + "\n")
print("open" if reg_open else "closed")
print(", ".join(kept))
PY
)" || _reg_rc=$?
if [[ $_reg_rc -ne 0 ]]; then
    # Couldn't build the env file: keep the current one as it is, and fail closed in the unit.
    warn "Couldn't work out the registration fallback — $ENV_FILE left as it is; the unit's fallback is \"closed\"."
    _reg_out="closed"
    rm -f "$_env"
fi
CRYPTIRC_REG_VALUE="${_reg_out%%$'\n'*}"
[[ "$CRYPTIRC_REG_VALUE" == open ]] || CRYPTIRC_REG_VALUE="closed"
_reg_kept=""; [[ "$_reg_out" == *$'\n'* ]] && _reg_kept="${_reg_out#*$'\n'}"
[[ -n "$_reg_kept" ]] && echo -e "  ${DIM}Not in admin_settings.json, so kept from the current service: ${_reg_kept}${NC}"
ENV_CHANGED=false; ENV_REC=""
if [[ $_reg_rc -eq 0 ]]; then
    put_file "$_env" "$ENV_FILE" 600 "$UNIT_BACKUP_DIR/cryptirc.env"
    ENV_CHANGED=$PUT_CHANGED; ENV_REC=$PUT_REC
fi

# Web unit. For self-signed/IP, HSTS is turned OFF — otherwise the browser
# would refuse the cert-warning click-through and lock everyone out for 2 years.
HSTS_VALUE="on";            [[ "$SELF_SIGNED" == true ]] && HSTS_VALUE="off"
# From: on the server's own domain — matches Postfix's myorigin and the domain's SPF. (The
# Let's Encrypt contact address is usually a gmail/outlook mailbox: mail "from" it sent by
# this VPS fails SPF/DMARC, and it would show the operator's private address to everyone.)
FROM_EMAIL="noreply@localhost"; [[ "$SELF_SIGNED" == false ]] && FROM_EMAIL="noreply@$DOMAIN"
# The data dir as the installed service has it: a re-run never moves the service onto another
# directory. Its CRYPTIRC_IPC_SOCK too, when this very file set it (one from a drop-in or an
# EnvironmentFile survives anyway): never away from the socket its irc-core listens on.
_unit_data_lines="$(_unit_env_line CRYPTIRC_DATA "$DATA_DIR")"
if [[ -n "$WEB_IPC_SOCK" ]] && grep -qsE '^[[:space:]]*Environment=.*CRYPTIRC_IPC_SOCK=' /etc/systemd/system/cryptirc.service; then
    _unit_data_lines+=$'\n'"$(_unit_env_line CRYPTIRC_IPC_SOCK "$WEB_IPC_SOCK")"
fi
_w="$(mktemp)"
cat > "$_w" <<UNIT
[Unit]
Description=CryptIRC — Encrypted IRC Client
After=network-online.target caddy.service irc-core.service
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

# Generated by the installer; a re-run regenerates this file (keeping a backup in
# $UNIT_BACKUP_DIR/). Put your own changes in a drop-in — sudo systemctl edit cryptirc —
# which survives re-runs.
# Secrets (the fallback registration code) live in this root-only file, not here.
EnvironmentFile=-$ENV_FILE
$_unit_data_lines
Environment="CRYPTIRC_BASE_URL=https://$URL_HOST"
Environment=CRYPTIRC_BASE_PATH=/
Environment=CRYPTIRC_PORT=9001
Environment="CRYPTIRC_FROM_EMAIL=$FROM_EMAIL"
Environment=CRYPTIRC_REGISTRATION=${CRYPTIRC_REG_VALUE}
Environment=CRYPTIRC_HSTS=${HSTS_VALUE}
Environment=RUST_LOG=info
# Plain log lines: journald keeps ANSI colour codes as unreadable "blob data".
Environment=NO_COLOR=1
# ffmpeg + exiftool strip upload metadata; Arch installs exiftool in /usr/bin/vendor_perl.
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
$(_unit_rw_line "$DATA_DIR")
ReadWritePaths=$LOG_DIR
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
LimitNOFILE=65536
# Task cap for THIS unit (its cgroup). Not LimitNPROC: RLIMIT_NPROC counts every task of the
# cryptirc UID — irc-core's too — so a burst in one service could starve the other.
TasksMax=512

[Install]
WantedBy=multi-user.target
UNIT
put_file "$_w" /etc/systemd/system/cryptirc.service 644 "$UNIT_BACKUP_DIR/cryptirc.service"
WEB_UNIT_CHANGED=$PUT_CHANGED; WEB_UNIT_REC=$PUT_REC

# ── Swap in the new binaries ──
# rename(2) of the staged copies: atomic, needs no free space, and fine while the old ones
# still run. The previous ones stay hard-linked as .<name>.prev until the new version has
# proved it serves (see below), so a build that doesn't come up is put back.
for _b in irc_core cryptirc; do
    [[ -f "$INSTALL_DIR/.$_b.staged" ]] || continue
    rm -f "$INSTALL_DIR/.$_b.prev"
    if [[ -f "$INSTALL_DIR/$_b" ]] && ! { ln -f "$INSTALL_DIR/$_b" "$INSTALL_DIR/.$_b.prev" 2>/dev/null \
                                          || cp -p "$INSTALL_DIR/$_b" "$INSTALL_DIR/.$_b.prev"; }; then
        rm -f "$INSTALL_DIR/.$_b.prev"
        die "Couldn't keep a copy of the current $INSTALL_DIR/$_b to roll back to (disk full?). Nothing was replaced."
    fi
done
BIN_STATE=swapped     # from here an early exit puts the .prev copies back (see on_exit)
for _b in irc_core cryptirc; do
    [[ -f "$INSTALL_DIR/.$_b.staged" ]] && mv -f "$INSTALL_DIR/.$_b.staged" "$INSTALL_DIR/$_b"
done
[[ "$HAVE_IRC_CORE" == true ]] && record_ondisk_srchash
ok "New binaries installed ${DIM}(the previous ones are kept until the new version is verified)${NC}"

systemctl daemon-reload

# irc-core holds EVERY user's live IRC connection, and the whole point of the daemon split
# is that redeploys don't drop them. So (re)start it only when it isn't running, or when its
# code or unit actually changed — a plain re-run leaves it (and everyone's sessions) alone.
IRC_CORE_ACTION=""
if [[ "$HAVE_IRC_CORE" == true ]]; then
    systemctl enable irc-core >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet irc-core; then
        # Start irc-core FIRST — a cold-started daemon just waits idle for Dial
        # requests, so it's always safe to bring up ahead of the web process.
        systemctl restart irc-core >/dev/null 2>&1 || true
        IRC_CORE_ACTION=started
    elif [[ "$DAEMON_CHANGED" == true || "$IRC_CORE_UNIT_CHANGED" == true ]]; then
        systemctl restart irc-core >/dev/null 2>&1 || true
        IRC_CORE_ACTION=restarted
    else
        IRC_CORE_ACTION=kept
    fi
fi
systemctl enable cryptirc >/dev/null 2>&1 || true           # start on boot
# Use `restart`, NOT `enable --now`: `--now` only does a `start`, which is a no-op
# if the unit is already active. Re-running this installer on a live system installs
# the new binary on disk but the old process keeps running the old (now-unlinked)
# inode — so without an explicit restart the update silently never takes effect.
# `restart` starts it on a fresh install and swaps in the new binary on a re-run.
# (Restarting the WEB never drops IRC: it re-attaches to irc-core.)
systemctl reset-failed cryptirc >/dev/null 2>&1 || true
if [[ "$FLOOR_ON" == true ]]; then
    # Across the 0.5.8 floor: fingerprint users' data while no cryptirc runs, so whatever differs if
    # the new build fails its health check was written by the new version (see the rollback below).
    WEB_STOPPED=true      # until it runs again, any exit starts it (on_exit)
    systemctl stop cryptirc >/dev/null 2>&1 || true
    FLOOR_SNAP="$(_user_data_snapshot "$DATA_DIR")" || FLOOR_SNAP=unknown
fi
systemctl restart cryptirc >/dev/null 2>&1 || true          # don't abort — the check below reports real status
BIN_STATE=restarted
WEB_STOPPED=false
CONFIG_TXN=()         # committed: the services now run on these configs (rollbacks below are explicit)
[[ "$CERT_STATE" == replaced ]] && CERT_STATE=committed    # …and the self-signed pair those configs use
ok "Services started"

# proc_env <pid> <NAME>: NAME in that process's real environment (Environment=,
# EnvironmentFile= and drop-ins alike). rc 1 = not set, rc 2 = unreadable/exiting.
proc_env() {
    local kv any=false
    [[ "$1" =~ ^[1-9][0-9]*$ && -r "/proc/$1/environ" ]] || return 2
    { while IFS= read -r -d '' kv; do
          any=true
          if [[ "$kv" == "$2="* ]]; then printf '%s' "${kv#*=}"; return 0; fi
      done; } < "/proc/$1/environ" 2>/dev/null || return 2
    [[ "$any" == true ]] || return 2
    return 1
}
# pid_is_systemd <pid>: during every (re)start the unit's main PID is first systemd's own forked
# child (systemd-executor on newer systemd), which has not exec'd the service binary yet: its
# environment is systemd's, not the service's, so its port/base path must not be read yet.
pid_is_systemd() {
    local exe
    exe="$(readlink "/proc/$1/exe" 2>/dev/null || true)"; exe="${exe% (deleted)}"
    [[ "${exe##*/}" == systemd || "${exe##*/}" == systemd-executor ]]
}
# url_path <path>: <path> as a client writes it in a request — the characters RFC 3986 allows in
# a path stay as they are (the server matches its base path against the raw request path), every
# other byte is %-encoded, as a browser does. Same as update.sh's _url_path.
url_path() {
    local LC_ALL=C
    local s="$1" out="" c i
    for (( i = 0; i < ${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            [A-Za-z0-9._~!\$\&\'\(\)*+,\;=:@%/-]) out+="$c" ;;
            *) printf -v c '%%%02X' "'$c"; out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}
# irc_core_sock: the IPC socket irc-core binds — its CRYPTIRC_IPC_SOCK, else <its CRYPTIRC_DATA>/
# irc-core.sock — as the running daemon has them (drop-ins and EnvironmentFile= included; only
# used to test for the socket, never written anywhere), else as its unit's root-owned settings set
# them (deploy/unit-env.sh: drop-ins and trusted EnvironmentFiles too), else <the data dir>/irc-core.sock.
irc_core_sock() {
    local pid v rc
    pid="$(systemctl show -p MainPID --value irc-core 2>/dev/null || true)"
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && ! pid_is_systemd "$pid"; then
        rc=0; v="$(proc_env "$pid" CRYPTIRC_IPC_SOCK)" || rc=$?
        if (( rc == 0 )) && [[ -n "$v" ]]; then printf '%s' "$v"; return 0; fi
        if (( rc == 1 )); then
            rc=0; v="$(proc_env "$pid" CRYPTIRC_DATA)" || rc=$?
            if (( rc == 0 )) && [[ -n "$v" ]]; then printf '%s/irc-core.sock' "${v%/}"; return 0; fi
            if (( rc == 1 )); then printf '%s/irc-core.sock' "$DATA_DIR"; return 0; fi
        fi
    fi
    if v="$(_unit_env irc-core.service CRYPTIRC_IPC_SOCK)" && [[ -n "$v" ]]; then printf '%s' "$v"
    elif v="$(_unit_env irc-core.service CRYPTIRC_DATA)" && [[ -n "$v" ]]; then printf '%s/irc-core.sock' "${v%/}"
    else printf '%s/irc-core.sock' "$DATA_DIR"; fi
    return 0
}
# web_healthy <secs>: `is-active` only proves the process didn't exit yet (a crash-looping
# binary reads active between crashes). Healthy = the unit is active and the SAME main PID
# answers HTTP 200 for its index three probes in a row, on the port and base path that
# process really uses. Same rule as deploy/update.sh.
HEALTH_TIMEOUT="${CRYPTIRC_HEALTH_TIMEOUT:-60}"; [[ "$HEALTH_TIMEOUT" =~ ^[0-9]+$ ]] || HEALTH_TIMEOUT=60
WEB_LAST="no answer"
web_healthy() {
    local deadline=$(( SECONDS + $1 )) pid last="" streak=0 n0 n code port path prc
    local -a asis
    n0="$(systemctl show -p NRestarts --value cryptirc 2>/dev/null || true)"; [[ "$n0" =~ ^[0-9]+$ ]] || n0=0
    while (( SECONDS < deadline )); do
        n="$(systemctl show -p NRestarts --value cryptirc 2>/dev/null || true)"; [[ "$n" =~ ^[0-9]+$ ]] || n=$n0
        if (( n - n0 >= 2 )); then WEB_LAST="crash loop (restarted $(( n - n0 ))x)"; return 1; fi
        pid="$(systemctl show -p MainPID --value cryptirc 2>/dev/null || true)"
        if systemctl is-active --quiet cryptirc && [[ "$pid" =~ ^[1-9][0-9]*$ ]] && pid_is_systemd "$pid"; then
            streak=0; last=""; WEB_LAST="service still starting"
        elif systemctl is-active --quiet cryptirc && [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
            port="$(proc_env "$pid" CRYPTIRC_PORT || true)"; [[ "$port" =~ ^[0-9]{1,5}$ ]] || port=9001
            prc=0; path="$(proc_env "$pid" CRYPTIRC_BASE_PATH)" || prc=$?
            (( prc == 1 )) && path=/cryptirc      # unset → the binary's default
            (( prc == 2 )) && path=/              # unreadable → what this installer's unit sets
            while [[ "$path" == */ ]]; do path="${path%/}"; done     # the server trims every trailing '/'
            # Probed as the server mounts it (a drop-in may set any base path, e.g. /irc+chat), in
            # request form (url_path): nothing in the live value — it belongs to the service
            # account — reaches curl as URL syntax. -g: no [] {} globbing; --path-as-is (only when
            # needed: older curl lacks it) keeps a ./ or ../ segment as configured; --noproxy '*':
            # an http_proxy in root's environment must never carry a loopback probe (every probe
            # would fail, and a working build would be rolled back).
            path="$(url_path "$path")"; [[ -z "$path" || "$path" == /* ]] || path="/$path"
            asis=(); [[ "$path/" == */./* || "$path/" == */../* ]] && asis=(--path-as-is)
            code="$(curl -s -g --noproxy '*' ${asis[@]+"${asis[@]}"} -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${port}${path}/" 2>/dev/null || true)"
            WEB_LAST="HTTP ${code:-000} from 127.0.0.1:${port}${path}/"
            if [[ "$code" == 200 ]]; then
                if [[ "$pid" == "$last" ]]; then streak=$(( streak + 1 )); else streak=1; fi
                last=$pid
                (( streak >= 3 )) && return 0
            else
                streak=0; last=""
            fi
        else
            streak=0; last=""; WEB_LAST="service $(systemctl is-active cryptirc 2>/dev/null || true)"
        fi
        sleep 1
    done
    return 1
}
CRYPTIRC_HEALTHY=false
WEB_ROLLED_BACK=false
WEB_BIN_RESTORED=false   # the previous web binary is back on disk (whether or not it then served)
IRC_CORE_FAILED=false
IRC_SOCK_MISMATCH=false  # both run, but the web dials another socket than irc-core listens on
if web_healthy "$HEALTH_TIMEOUT"; then
    CRYPTIRC_HEALTHY=true
elif [[ -f "$INSTALL_DIR/.cryptirc.prev" && "$FLOOR_ON" == true ]] && {
         # The 0.5.8 data floor: decided with the new web stopped, so nothing it writes lands after
         # the check. Changed since it started → it stays (started again), nothing is put back.
         WEB_STOPPED=true
         systemctl stop cryptirc >/dev/null 2>&1 || true
         _datachg="$(_user_data_changed "${FLOOR_SNAP:-unknown}" "$DATA_DIR")"
         [[ -n "$_datachg" ]]; }; then
    WEB_WITHHELD=true
    systemctl reset-failed cryptirc >/dev/null 2>&1 || true
    systemctl start cryptirc >/dev/null 2>&1 || true
    WEB_STOPPED=false
    _what=""
    for _d in $_datachg; do
        case "$_d" in
            e2e)      _what+="${_what:+, }end-to-end keys ($DATA_DIR/e2e/<user>/)" ;;
            networks) _what+="${_what:+, }saved networks ($DATA_DIR/networks/)" ;;
            vaults)   _what+="${_what:+, }vaults ($DATA_DIR/vaults/)" ;;
        esac
    done
    warn "The new CryptIRC build did not come up healthy (${WEB_LAST}) — and it is NOT rolled back automatically:"
    echo -e "    ${YELLOW}v${VERSION} has already changed users' data: ${_what} changed since it started — someone"
    echo -e "    used it (e.g. unlocked their vault, which moves their end-to-end keys to a format ${PREV_NAME} can't"
    echo -e "    read). Putting ${PREV_NAME} back now would make it replace those keys with new ones: those users'"
    echo -e "    encrypted conversations and verified identities would be lost for good.${NC}"
    echo -e "  ${BOLD}What to do:${NC} see why (journalctl -u cryptirc -n 50 --no-pager), fix the cause and re-run this"
    echo -e "  installer, or update to a fixed version (sudo bash deploy/update.sh). Going back anyway: read \"Going"
    echo -e "  back by hand\" in deploy/README.md first; the previous binary is kept as $INSTALL_DIR/.cryptirc.prev${NC}"
    [[ -n "${_bk:-}" ]] && echo -e "  ${DIM}(users' data as it was before this run: ${_bk})${NC}"
elif [[ -f "$INSTALL_DIR/.cryptirc.prev" ]]; then
    # A re-run over a working install: don't leave the site down on a build that won't serve.
    [[ "$FLOOR_ON" == true ]] && echo -e "  ${DIM}(no user's data changed while v${VERSION} ran — safe to put the previous version back)${NC}"
    warn "The new CryptIRC build did not come up healthy (${WEB_LAST}) — putting the previous binary back…"
    mv -f "$INSTALL_DIR/.cryptirc.prev" "$INSTALL_DIR/cryptirc"
    WEB_BIN_RESTORED=true
    # …with the unit and settings file it ran with: this run may have rewritten both, and the
    # previous binary may not even start under the new ones.
    _undone=()
    if [[ "$WEB_UNIT_CHANGED" == true ]]; then
        if undo_rec "$WEB_UNIT_REC"; then _undone+=(cryptirc.service)
        else warn "Couldn't put the previous cryptirc.service back (it is in $UNIT_BACKUP_DIR)."; fi
    fi
    if [[ "$ENV_CHANGED" == true ]]; then
        if undo_rec "$ENV_REC"; then _undone+=("$ENV_FILE")
        else warn "Couldn't put the previous $ENV_FILE back (it is in $UNIT_BACKUP_DIR)."; fi
    fi
    if (( ${#_undone[@]} )); then
        systemctl daemon-reload >/dev/null 2>&1 || true
        ok "Previous ${_undone[*]} put back"
    fi
    systemctl reset-failed cryptirc >/dev/null 2>&1 || true
    systemctl restart cryptirc >/dev/null 2>&1 || true
    WEB_STOPPED=false
    if web_healthy "$HEALTH_TIMEOUT"; then
        CRYPTIRC_HEALTHY=true; WEB_ROLLED_BACK=true
        ok "The previous CryptIRC binary is serving again"
    else
        warn "The previous binary doesn't come up either (${WEB_LAST}) — so it isn't the new build; check the unit and its settings."
    fi
fi
if [[ "$CRYPTIRC_HEALTHY" == "true" && "$WEB_ROLLED_BACK" != true ]]; then
    ok "CryptIRC is running"
    SERVICE_OK=true
elif [[ "$WEB_ROLLED_BACK" == true ]]; then
    echo -e "  ${DIM}Why the new build failed:  journalctl -u cryptirc -n 50 --no-pager${NC}"
    SERVICE_OK=false
elif [[ "$WEB_WITHHELD" == true ]]; then
    SERVICE_OK=false            # (said above)
else
    warn "CryptIRC isn't responding (${WEB_LAST}). Check:  journalctl -u cryptirc -n 50 --no-pager"
    SERVICE_OK=false
fi
if [[ "$HAVE_IRC_CORE" == true ]]; then
    IRC_CORE_OK=false
    for _ in $(seq 1 10); do
        IRC_CORE_SOCK="$(irc_core_sock)"
        systemctl is-active --quiet irc-core && [[ -S "$IRC_CORE_SOCK" ]] && { IRC_CORE_OK=true; break; }
        sleep 1
    done
    # The daemon was (re)started on what this run installed and doesn't come up: put back the
    # previous binary and/or unit — whichever this run replaced (a unit it created is left).
    _undo_bin=false; _undo_unit=false
    if [[ -f "$INSTALL_DIR/.irc_core.prev" ]] && ! cmp -s "$INSTALL_DIR/.irc_core.prev" "$INSTALL_DIR/irc_core"; then _undo_bin=true; fi
    if [[ "$IRC_CORE_UNIT_CHANGED" == true && -n "$IRC_CORE_UNIT_BAK" ]]; then _undo_unit=true; fi
    if [[ "$IRC_CORE_OK" != true && "$IRC_CORE_ACTION" != kept ]] && [[ "$_undo_bin" == true || "$_undo_unit" == true ]]; then
        warn "The new irc-core did not come up — putting the previous version back…"
        if [[ "$_undo_bin" == true ]]; then
            mv -f "$INSTALL_DIR/.irc_core.prev" "$INSTALL_DIR/irc_core"
            rm -f "$INSTALL_DIR/.irc_core.ondisk-srchash"      # (no longer describes the file there)
        fi
        if [[ "$_undo_unit" == true ]]; then
            if undo_rec "$IRC_CORE_UNIT_REC"; then systemctl daemon-reload >/dev/null 2>&1 || true
            else warn "Couldn't put the previous irc-core.service back (it is in $UNIT_BACKUP_DIR)."; fi
        fi
        systemctl reset-failed irc-core >/dev/null 2>&1 || true
        systemctl restart irc-core >/dev/null 2>&1 || true
        for _ in $(seq 1 15); do
            IRC_CORE_SOCK="$(irc_core_sock)"
            systemctl is-active --quiet irc-core && [[ -S "$IRC_CORE_SOCK" ]] && { IRC_CORE_OK=true; break; }
            sleep 1
        done
        if [[ "$IRC_CORE_OK" == true ]]; then
            IRC_CORE_ACTION=rolledback; SERVICE_OK=false
            ok "The previous irc-core is running again ${DIM}(why the new one failed: journalctl -u irc-core -n 50 --no-pager)${NC}"
        fi
    fi
    if [[ "$IRC_CORE_OK" == true && "$IRC_CORE_ACTION" == rolledback ]]; then
        :   # the running daemon is the OLD code: leave the change marker alone
    elif [[ "$IRC_CORE_OK" == true ]]; then
        case "$IRC_CORE_ACTION" in
            kept)      ok "irc-core is running — unchanged, left running ${DIM}(no IRC sessions dropped)${NC}" ;;
            restarted) ok "irc-core restarted with its new code/unit ${DIM}(IRC sessions reconnect by themselves for users whose vault is unlocked, the rest on their next unlock)${NC}" ;;
            *)         ok "irc-core is running" ;;
        esac
        # Persist the update.sh change-detection marker: the source hash the RUNNING daemon
        # was built from — written when we just (re)started it, or when it was left running
        # because it's already current (its marker was missing but the binary matched).
        # ("kept" only ever happens when DAEMON_CHANGED=false, so it is current in every case.)
        [[ -n "$DAEMON_SRC_HASH" ]] && { echo "$DAEMON_SRC_HASH" > "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null || true; }
    else
        # The web may well answer HTTP 200 without the daemon — but then nobody can reach IRC.
        # That is a failed install, not a success: say so, and end non-zero (below).
        IRC_CORE_FAILED=true; SERVICE_OK=false
        warn "irc-core is NOT running (or its socket $IRC_CORE_SOCK never appeared) — the site may load, but no IRC connection can be made."
        echo -e "  ${DIM}Check:  journalctl -u irc-core -n 50 --no-pager${NC}"
    fi
    # The web dials its CRYPTIRC_IPC_SOCK, else <its data dir>/irc-core.sock; the daemon listens on
    # its own. Two different paths pass both checks above, yet no IRC connection can work.
    if [[ "$IRC_CORE_OK" == true && "$CRYPTIRC_HEALTHY" == true ]]; then
        _wsock=""; _wpid="$(systemctl show -p MainPID --value cryptirc 2>/dev/null || true)"
        if [[ "$_wpid" =~ ^[1-9][0-9]*$ ]] && ! pid_is_systemd "$_wpid"; then
            _rc=0; _wsock="$(proc_env "$_wpid" CRYPTIRC_IPC_SOCK)" || _rc=$?
            if (( _rc == 1 )) || [[ -z "$_wsock" ]]; then
                _wsock=""; _wd="$(_live_data_dir "$_wpid")" && _wsock="$_wd/irc-core.sock"
            fi
        fi
        if [[ -n "$_wsock" && "$_wsock" != "$IRC_CORE_SOCK" ]] && ! [[ -e "$_wsock" && "$_wsock" -ef "$IRC_CORE_SOCK" ]]; then
            SERVICE_OK=false; IRC_SOCK_MISMATCH=true
            warn "cryptirc dials irc-core at $(printf '%q' "$_wsock"), but irc-core listens on $(printf '%q' "$IRC_CORE_SOCK") — no IRC connection can be made until both use the same socket (CRYPTIRC_IPC_SOCK / CRYPTIRC_DATA in: systemctl cat cryptirc irc-core)."
        fi
    fi
fi
# .version names the web binary that is INSTALLED now (update.sh shows it as the "from" version, and
# the 0.5.8 data floor of the next run trusts it): only when the new binary stayed in place. When the
# previous one was put back — whether or not it then served — the marker of the previous version stays.
if [[ "$WEB_BIN_RESTORED" != true && "${IRC_CORE_ACTION:-}" != rolledback ]]; then
    echo "$VERSION" > "$INSTALL_DIR/.version" 2>/dev/null || true
fi
# The kept copies of the previous binaries go only once the new ones are verified. (One that
# was put back is gone already.) A daemon that did not come up keeps its previous binary.
[[ "$CRYPTIRC_HEALTHY" == true ]] && rm -f "$INSTALL_DIR/.cryptirc.prev"
if [[ "$HAVE_IRC_CORE" != true || "$IRC_CORE_FAILED" != true ]]; then
    rm -f "$INSTALL_DIR/.irc_core.prev"
elif [[ -f "$INSTALL_DIR/.irc_core.prev" ]]; then
    echo -e "  ${DIM}The previously installed irc_core binary is kept as $INSTALL_DIR/.irc_core.prev${NC}"
fi

# ── Caddy: apply the config, then PROVE it's being served ──
# Reload when possible (no dropped connections for other sites). That fails when the
# RUNNING Caddy has no reachable admin API — e.g. a config with `admin off` from an older
# installer — so fall back to a restart. A "successful" reload is not trusted either:
# a probe through Caddy must see the new config, or we restart and probe again.
caddy_live() {   # 0 = Caddy is serving the CURRENT CryptIRC site
    systemctl is-active --quiet caddy || return 1
    local h body out want got
    if [[ "$SELF_SIGNED" == true ]]; then
        # SNI-less handshake (what a browser does for https://<IP>, NAT'd or not) must get OUR cert…
        want="$(openssl x509 -in "$SS_DIR/cert.pem" -noout -fingerprint -sha256 2>/dev/null || true)"
        got="$(timeout 10 openssl s_client -connect 127.0.0.1:443 -noservername </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
        [[ -n "$want" && "$want" == "$got" ]] || return 1
        # …and every served address must reach the app through it.
        for h in "$URL_HOST" ${URL_HOST2:+"$URL_HOST2"}; do
            body="$(curl -sk --noproxy '*' --max-time 5 -H "Host: $h" https://127.0.0.1/ 2>/dev/null || true)"
            [[ "$body" == *"<title>CryptIRC"* ]] || return 1
        done
        return 0
    fi
    # Domain: the new site's automatic http→https redirect proves the config is loaded (the
    # certificate itself may still be on its way from Let's Encrypt).
    out="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 5 -H "Host: $DOMAIN" http://127.0.0.1/ 2>/dev/null || true)"
    [[ "$out" == "308 https://$DOMAIN/" || "$out" == "301 https://$DOMAIN/" ]] && return 0
    body="$(curl -sk --noproxy '*' --max-time 5 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" 2>/dev/null || true)"
    [[ "$body" == *"<title>CryptIRC"* ]]
}
systemctl enable caddy >/dev/null 2>&1 || true              # persist across reboot (pacman/some setups don't auto-enable)
# `caddy validate` above runs as root (this whole script does) and creates the
# log file it references as a side effect of parsing the config — root:root,
# 0600. The chown of /var/log/caddy itself (done earlier, at directory-creation
# time) doesn't retroactively cover a file created after that. Caddy then
# starts as the unprivileged `caddy` user and can't open its own log file
# ("permission denied") — caught this for real on a fresh box, not by reading
# the code. So, right before the actual restart, root-owned entries under
# /var/log/caddy go to caddy. Not with `chown -R`: caddy owns that directory, so a
# name there may be a hard link it planted to some other root-owned file (where
# fs.protected_hardlinks is off), and chown would hand that file over. Each entry is
# opened without following links and checked on the open descriptor — a regular
# file with exactly one link, or a directory — before fchown on that descriptor.
# Nothing caddy can create is root-owned, so this only ever covers what root made.
give_caddy_logs() {
    id caddy >/dev/null 2>&1 && [[ -d /var/log/caddy ]] || return 0
    python3 -I - /var/log/caddy "$(id -u caddy)" "$(id -g caddy)" <<'PY' || true
import os, stat, sys
top, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
def give(dirfd, name, want_dir):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | (os.O_DIRECTORY if want_dir else 0)
    try:
        fd = os.open(name, flags, dir_fd=dirfd)
    except OSError:
        return                                  # a symlink (ELOOP), a socket, gone meanwhile…
    try:
        st = os.fstat(fd)
        if st.st_uid != 0:
            return
        if want_dir and not stat.S_ISDIR(st.st_mode):
            return
        if not want_dir and not (stat.S_ISREG(st.st_mode) and st.st_nlink == 1):
            if stat.S_ISREG(st.st_mode):
                print("  left as it is (root-owned, %d links): %s" % (st.st_nlink, name), file=sys.stderr)
            return
        os.fchown(fd, uid, gid)
    finally:
        os.close(fd)
# fwalk: directory descriptors all the way, never follows a symlink out of the tree.
for _root, dirs, files, rootfd in os.fwalk(top):
    for d in dirs:
        give(rootfd, d, True)
    for f in files:
        give(rootfd, f, False)
PY
}
give_caddy_logs
if [[ "$CADDY_CHANGED" == true ]] || ! systemctl is-active --quiet caddy; then
    systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
fi
CADDY_OK=false
for _ in $(seq 1 10); do caddy_live && { CADDY_OK=true; break; }; sleep 1; done
if [[ "$CADDY_OK" != true ]]; then
    systemctl restart caddy >/dev/null 2>&1 || true
    for _ in $(seq 1 15); do caddy_live && { CADDY_OK=true; break; }; sleep 1; done
fi
if [[ "$CADDY_OK" == true && "$SELF_SIGNED" == true ]]; then
    ok "Caddy is serving https://${URL_HOST}${URL_HOST2:+ and https://$URL_HOST2}"
elif [[ "$CADDY_OK" == true ]]; then
    ok "Caddy has loaded the site for https://${URL_HOST} ${DIM}(its certificate comes from Let's Encrypt)${NC}"
else
    warn "Caddy is NOT serving the new configuration. Check:  journalctl -u caddy -n 50 --no-pager"
    SERVICE_OK=false
fi

if (( ${#BACKUPS[@]} )); then
    echo -e "  ${DIM}Replaced config files — your previous versions were saved:${NC}"
    for _b in "${BACKUPS[@]}"; do echo -e "    ${DIM}${_b}${NC}"; done
    [[ "$WEB_UNIT_CHANGED" == true || "$IRC_CORE_UNIT_CHANGED" == true || "$ENV_CHANGED" == true ]] && \
        echo -e "  ${DIM}Keep custom unit settings in a drop-in (sudo systemctl edit cryptirc) — those survive re-runs.${NC}"
fi

# ── Firewall ───────────────────────────────────────────────────────────────────
# ufw / firewalld when ACTIVE; otherwise nftables / iptables chains that actually block
# (policy drop or a drop/reject rule) get an accept INSERTED at the top, so a trailing
# reject can't shadow it. iptables-nft's own tables are left to iptables so its tooling
# keeps working. Only ever adds allow rules — it can't lock anyone out.
open_firewall() {
    local -a opened=(); local fam tbl name ipt rules hint_nft=false hint_ipt=false
    # (Listings go through variables, not `| grep -q`: with pipefail, grep quitting early on
    # a big ruleset SIGPIPEs the lister and the whole test reads as "no match".)
    rules="$(ufw status 2>/dev/null || true)"
    if command -v ufw >/dev/null 2>&1 && [[ "$rules" == *"Status: active"* ]]; then
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
        ok "Opened ports 80 and 443 (ufw)"; return 0
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-service=http  >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        ok "Opened ports 80 and 443 (firewalld)"; return 0
    fi
    if command -v nft >/dev/null 2>&1; then
        while read -r fam tbl name; do
            [[ -n "$name" ]] || continue
            [[ ( "$fam" == ip || "$fam" == ip6 ) && "$tbl" == filter && "$name" == INPUT ]] && continue
            rules="$(nft list chain "$fam" "$tbl" "$name" 2>/dev/null || true)"
            [[ "$rules" =~ (^|[[:space:]])(drop|reject)([[:space:]]|\;|$) ]] || continue
            if [[ "$rules" != *cryptirc-web* ]]; then
                nft insert rule "$fam" "$tbl" "$name" tcp dport '{ 80, 443 }' ct state new accept comment '"cryptirc-web"' 2>/dev/null || continue
            fi
            opened+=("nftables $fam $tbl $name"); hint_nft=true
        done < <(nft -j list chains 2>/dev/null | python3 -I -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for o in data.get("nftables", []):
    c = o.get("chain")
    if c and c.get("hook") == "input" and c.get("family") in ("inet", "ip", "ip6"):
        print(c["family"], c["table"], c["name"])
' 2>/dev/null || true)
    fi
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        rules="$("$ipt" -S INPUT 2>/dev/null || true)"
        [[ "$rules" =~ -P\ INPUT\ (DROP|REJECT)|-j\ (DROP|REJECT) ]] || continue
        "$ipt" -C INPUT -p tcp -m multiport --dports 80,443 -m comment --comment cryptirc-web -j ACCEPT 2>/dev/null \
            || "$ipt" -I INPUT 1 -p tcp -m multiport --dports 80,443 -m comment --comment cryptirc-web -j ACCEPT 2>/dev/null \
            || continue
        opened+=("$ipt"); hint_ipt=true
    done
    if (( ${#opened[@]} )); then
        ok "Opened ports 80 and 443 (${opened[*]})"
        warn "Those firewall rules are live now but NOT saved — they're gone after a reboot unless you persist them:"
        [[ "$hint_nft" == true ]] && echo -e "    ${DIM}nftables: add  tcp dport { 80, 443 } accept  to the input chain in /etc/nftables.conf${NC}"
        [[ "$hint_ipt" == true ]] && echo -e "    ${DIM}iptables: save them with your tool (Debian/Ubuntu: iptables-persistent · Arch: iptables-save > /etc/iptables/iptables.rules + enable iptables.service)${NC}"
    else
        ok "No local firewall is blocking ports 80/443 — nothing to open."
    fi
    echo -e "  ${DIM}(A cloud firewall / security group must also allow TCP 80 and 443.)${NC}"
}
echo ""
open_firewall

# ── First user (interactive only) ─────────────────────────────────────────────
# adduser.sh takes the password on stdin (--password-stdin) when it supports it — never
# via argv or sudo's environment, which other local users can read.
ADDUSER_STDIN=false; grep -q -- '--password-stdin' "$REPO_DIR/adduser.sh" 2>/dev/null && ADDUSER_STDIN=true
if [[ "$INTERACTIVE" == true ]]; then
    echo ""
    echo -e "${BOLD}Create your first user (admin)${NC}\n"
    read -rp "  Would you like to create a user now? (y/N): " CREATE_USER
    if [[ "$CREATE_USER" =~ ^[Yy] ]]; then
        # The app's sign-up rules, which adduser.sh enforces: checked here first, so a weak
        # password means "try again" instead of losing the whole step.
        pw_problem() {   # prints why the password won't do; rc 0 = it's acceptable
            printf '%s\n' "$1" | python3 -I -c 'import sys
pw = sys.stdin.buffer.readline().rstrip(b"\n").decode("utf-8", "replace")
n = len(pw.encode("utf-8"))
if n < 10:
    sys.exit("it has fewer than 10 characters")
if n > 1024:
    sys.exit("it is longer than 1024 characters")
if not (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
        and any(c in "0123456789" for c in pw) and any(not c.isalnum() for c in pw)):
    sys.exit("it needs an upper-case letter, a lower-case letter, a digit and a symbol")' 2>&1
        }
        for _try in 1 2 3; do
            read -rp  "  Username (3-32 chars; letters, numbers, _ and -): " NEW_USER
            read -rp  "  Email (optional — Enter to skip): " NEW_EMAIL
            while true; do
                read -rsp "  Password (10+ characters, with upper case, lower case, a digit and a symbol): " NEW_PASS; echo ""
                [[ -n "$NEW_PASS" ]] || break
                if _why="$(pw_problem "$NEW_PASS")"; then
                    read -rsp "  Confirm the password: " _pw2; echo ""
                    [[ "$_pw2" == "$NEW_PASS" ]] && break
                    warn "The two don't match — try again."
                else
                    warn "That password won't do: ${_why}. Try again (or press Enter to skip)."
                fi
            done
            if [[ -z "$NEW_USER" || -z "$NEW_PASS" ]]; then
                warn "Skipped — username and password are required. Later:  sudo bash adduser.sh <user> [email]  then  sudo bash makeadmin.sh <user>"
                break
            fi
            _add_rc=0
            # CRYPTIRC_DATA explicitly, as for makeadmin.sh below: both must use THIS install's data
            # dir, not one inherited from the caller's environment (sudo -E, a CRYPTIRC_DATA=… prefix).
            if [[ "$ADDUSER_STDIN" == true ]]; then
                printf '%s\n' "$NEW_PASS" | CRYPTIRC_DATA="$DATA_DIR" bash "$REPO_DIR/adduser.sh" --password-stdin -- "$NEW_USER" "$NEW_EMAIL" >"$RUN_LOG" 2>&1 || _add_rc=$?
            else
                # Older adduser.sh: env (NOT argv) so it never shows in ps / /proc.
                CRYPTIRC_DATA="$DATA_DIR" CRYPTIRC_NEW_PASS="$NEW_PASS" bash "$REPO_DIR/adduser.sh" "$NEW_USER" "$NEW_EMAIL" >"$RUN_LOG" 2>&1 || _add_rc=$?
            fi
            NEW_PASS=""; _pw2=""
            if [[ $_add_rc -eq 0 ]]; then
                ok "User '${NEW_USER}' created"
                # Hand off to makeadmin.sh rather than rewriting the record inline:
                # it validates the name, writes atomically and preserves owner/mode.
                if CRYPTIRC_DATA="$DATA_DIR" bash "$REPO_DIR/makeadmin.sh" -- "$NEW_USER" >/dev/null 2>&1
                then ok "${NEW_USER} is now an admin"
                else warn "Created the user, but couldn't set admin. Nothing in the app can grant it — run:  sudo CRYPTIRC_DATA=$DATA_DIR bash makeadmin.sh -- ${NEW_USER}"
                fi
                break
            fi
            warn "Couldn't create the user:"
            tail -n 5 "$RUN_LOG" >&2 || true
            if (( _try < 3 )); then
                read -rp "  Try again? [Y/n]: " _again
                if [[ "$_again" =~ ^[Nn] ]]; then
                    warn "Skipped. Later:  sudo bash adduser.sh <user> [email]  then  sudo bash makeadmin.sh <user>"
                    break
                fi
            else
                warn "Giving up for now. Later:  sudo bash adduser.sh <user> [email]  then  sudo bash makeadmin.sh <user>"
            fi
        done
    fi
fi

rm -f "$RUN_LOG" 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
if [[ "$WEB_WITHHELD" == true ]]; then
echo -e "${CYAN}║${NC}  ${YELLOW}⚠ v${VERSION} failed its health check, and was NOT${NC}"
echo -e "${CYAN}║${NC}  ${YELLOW}  rolled back: users' data already changed (above).${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Why: journalctl -u cryptirc -n 50 --no-pager${NC}"
elif [[ "$WEB_ROLLED_BACK" == true || "${IRC_CORE_ACTION:-}" == rolledback ]]; then
[[ "$WEB_ROLLED_BACK" == true ]] && \
echo -e "${CYAN}║${NC}  ${YELLOW}⚠ The new web build didn't serve, so the previous${NC}" && \
echo -e "${CYAN}║${NC}  ${YELLOW}  cryptirc binary was put back and is running.${NC}"
[[ "${IRC_CORE_ACTION:-}" == rolledback ]] && \
echo -e "${CYAN}║${NC}  ${YELLOW}⚠ The new irc-core didn't start, so the previous${NC}" && \
echo -e "${CYAN}║${NC}  ${YELLOW}  irc_core binary was put back and is running.${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Why: journalctl -u cryptirc -u irc-core -n 50 --no-pager${NC}"
elif [[ "$SERVICE_OK" == true ]]; then
echo -e "${CYAN}║${NC}  ${GREEN}✓ CryptIRC v${VERSION:-?} is live!${NC}"
elif [[ "$IRC_SOCK_MISMATCH" == true ]]; then
echo -e "${CYAN}║${NC}  ${YELLOW}⚠ The web app and irc-core both run, but on different${NC}"
echo -e "${CYAN}║${NC}  ${YELLOW}  sockets — nobody can connect to IRC (see above).${NC}"
elif [[ "$IRC_CORE_FAILED" == true && "$CRYPTIRC_HEALTHY" == true ]]; then
echo -e "${CYAN}║${NC}  ${YELLOW}⚠ The web app is up, but the irc-core daemon isn't${NC}"
echo -e "${CYAN}║${NC}  ${YELLOW}  running — nobody can connect to IRC yet.${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Check: journalctl -u irc-core -n 50 --no-pager${NC}"
elif [[ "$CRYPTIRC_HEALTHY" == true ]]; then
echo -e "${CYAN}║${NC}  ${YELLOW}⚠ CryptIRC is running — but Caddy isn't serving it yet.${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Check: journalctl -u caddy -n 50 --no-pager${NC}"
else
echo -e "${CYAN}║${NC}  ${YELLOW}⚠ Installed — but the service isn't running yet.${NC}"
echo -e "${CYAN}║${NC}  ${DIM}Check: journalctl -u cryptirc -n 50 --no-pager${NC}"
fi
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  ${BOLD}URL${NC}: ${GREEN}https://${URL_HOST}${NC}"
[[ -n "$URL_HOST2" ]] && echo -e "${CYAN}║${NC}       ${GREEN}https://${URL_HOST2}${NC}"
# In domain mode, `caddy validate` only checked config SYNTAX — the Let's Encrypt cert is
# issued in the background and needs DNS actually pointing here. Probe the real HTTPS
# endpoint (validating the cert, resolved to localhost) so we never claim "live" while
# every browser would get a TLS error. Non-fatal + informational — issuance is automatic.
if [[ "$SELF_SIGNED" == false ]] && command -v curl >/dev/null 2>&1 \
   && ! curl -s --noproxy '*' --resolve "${DOMAIN}:443:127.0.0.1" -o /dev/null --max-time 6 "https://${DOMAIN}/" 2>/dev/null; then
    echo -e "${CYAN}║${NC}  ${YELLOW}TLS cert not being served yet${NC} ${DIM}— Let's Encrypt issues once DNS points here.${NC}"
    echo -e "${CYAN}║${NC}  ${DIM}First issuance can take ~1 min · watch:  journalctl -u caddy -f${NC}"
fi
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
if [[ "$ADDUSER_STDIN" == true ]]; then
echo -e "${CYAN}║${NC}  Add users: ${DIM}sudo bash adduser.sh <user> [email]${NC}  ${DIM}(asks for the password)${NC}"
else
echo -e "${CYAN}║${NC}  Add users: ${DIM}sudo CRYPTIRC_NEW_PASS=pw bash adduser.sh <user> [email]${NC}"
fi
fi
# Outside the branch on purpose: an open-registration install is exactly where
# somebody signs up in the browser and then has no way into the admin panel.
echo -e "${CYAN}║${NC}  Make admin: ${DIM}sudo bash makeadmin.sh <user>${NC}"

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
# Non-zero when this run did not end with the new version serving: a rollback, a web that never
# answered, or an irc-core that isn't running. (A Caddy that hasn't picked the site up yet is
# reported above but doesn't fail the run: the app itself is verified.) DIED=true: the outcome
# was already explained — the EXIT handler must not add its "stopped unexpectedly" message.
# 4 = the new web failed its health check across the 0.5.8 data floor and was deliberately NOT rolled
# back, because users' data had already changed under it (as update.sh's exit 4).
if [[ "$WEB_WITHHELD" == true ]]; then
    DIED=true
    exit 4
fi
if [[ "$WEB_ROLLED_BACK" == true || "${IRC_CORE_ACTION:-}" == rolledback \
      || "$CRYPTIRC_HEALTHY" != true || "$IRC_CORE_FAILED" == true || "$IRC_SOCK_MISMATCH" == true ]]; then
    DIED=true
    exit 1
fi
