#!/usr/bin/env bash
# CryptIRC update script — backs up data, rebuilds, and hot-swaps the binary
# Usage: sudo bash deploy/update.sh [--no-backup] [--restart-daemon] [--no-ghost] [--help]
#
# By default, creates a timestamped backup of all user data before updating.
# Pass --no-backup to skip the backup step.
#
# Rollback: the binaries (and any systemd unit) this run replaces are kept in
# /opt/cryptirc/.rollback first. If the new build does not come up healthy (a
# real HTTP 200 from the web, the IPC socket from irc-core), everything is put
# back and restarted automatically, and the script exits non-zero.
# Exit codes: 0 = updated (or nothing to do), 1 = failed (nothing changed, or
# rolled back to the previous version), 2 = bad arguments, 3 = the rollback
# itself failed (the site may be down — the message says what to run), 4 = the
# new version failed its health check but was NOT rolled back, because it had
# already changed users' data that the previous version can't read (an update
# across the 0.5.8 data floor, after someone unlocked a vault — see DATA_FLOOR;
# the new version stays installed and the message says what to do).
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
DATA_DIR="/var/lib/cryptirc"            # default only — replaced below by the data dir the service really uses
BACKUP_DIR="/var/lib/cryptirc-backups"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
# The 0.5.8 data floor (no automatic rollback below it once users' data changed), shared with the
# installers. Checked before anything happens: a checkout without it is incomplete.
[[ -f "$SCRIPT_DIR/data-floor.sh" ]] || { echo -e "${RED}✗ deploy/data-floor.sh is missing from this checkout — it is incomplete; nothing was changed.${NC}" >&2; exit 1; }
# shellcheck source=deploy/data-floor.sh disable=SC1091
source "$SCRIPT_DIR/data-floor.sh"
# How a unit's settings are read from root-owned sources (shared with the installers).
[[ -f "$SCRIPT_DIR/unit-env.sh" ]] || { echo -e "${RED}✗ deploy/unit-env.sh is missing from this checkout — it is incomplete; nothing was changed.${NC}" >&2; exit 1; }
# shellcheck source=deploy/unit-env.sh disable=SC1091
source "$SCRIPT_DIR/unit-env.sh"

# Fingerprint the copy of this script that is RUNNING — and the helpers it sourced above, whose
# functions and values (DATA_FLOOR, the stock unit hashes…) it keeps using — before the pull below
# can swap the files at these paths (git replaces by rename, so the running interpreter safely
# keeps executing its old inode). Compared after the pull by the "Self-update handoff" block.
_self_fingerprint() {
    local f
    for f in update.sh data-floor.sh unit-env.sh; do
        sha256sum "$SCRIPT_DIR/$f" 2>/dev/null | awk '{print $1}' || true
    done
}
SELF_SHA_AT_START=$(_self_fingerprint | tr '\n' ' ')

SKIP_BACKUP=false
RESTART_DAEMON=false
NO_GHOST=false
PREBUILT_DIR="${CRYPTIRC_PREBUILT_DIR:-}"
_usage() {
    echo "Usage: sudo bash deploy/update.sh [--no-backup] [--restart-daemon] [--prebuilt DIR] [--no-ghost] [--help]"
    echo "  --no-backup       skip the pre-update data backup"
    echo "  --restart-daemon  also restart irc-core to apply a daemon change (drops + reconnects IRC)"
    echo "  --prebuilt DIR    install the cryptirc (and irc_core) binaries in DIR, built elsewhere from this"
    echo "                    checkout, instead of pulling and building here (no git pull, no cargo); DIR and"
    echo "                    the binaries must be root-owned and not group/other-writable. Also"
    echo "                    CRYPTIRC_PREBUILT_DIR=DIR."
    echo "  --no-ghost        skip the banner animation"
}
_args=("$@"); _i=0
while (( _i < ${#_args[@]} )); do
    arg=${_args[_i]}
    case "$arg" in
        --no-backup)      SKIP_BACKUP=true ;;
        --restart-daemon) RESTART_DAEMON=true ;;
        --no-ghost)       NO_GHOST=true ;;
        --prebuilt)       _i=$(( _i + 1 )); PREBUILT_DIR=${_args[_i]:-}
                          [[ -n "$PREBUILT_DIR" ]] || { echo -e "${RED}✗ --prebuilt needs a directory${NC}" >&2; _usage >&2; exit 2; } ;;
        --prebuilt=*)     PREBUILT_DIR=${arg#*=} ;;
        -h|--help)        _usage; exit 0 ;;
        # A typo (--restart-deamon) used to be silently dropped: the update ran WITHOUT the
        # daemon restart the operator asked for, and nothing said so. Refuse instead —
        # before anything (backup included) has happened.
        *)                echo -e "${RED}✗ Unknown option: '${arg}'${NC}" >&2; _usage >&2; exit 2 ;;
    esac
    _i=$(( _i + 1 ))
done

# ── Prebuilt binaries (--prebuilt DIR) ─────────────────────────────────────────
# A box that must not build (a small production host) gets binaries built elsewhere from
# this same checkout. They replace "Pulling latest code" and "Building CryptIRC" only;
# everything else (backup, unit refresh, data floor, health check, rollback) runs as always.
# Checked before anything is touched — refused, nothing changed, unless:
#  - DIR and the files in it are root-owned and not group/other-writable (they become root's
#    service binaries), regular files (no symlinks), executable;
#  - each is an ELF executable for this machine that this host's dynamic loader can load with
#    all its library versions (ldd: no "not found" — e.g. a build against a newer glibc);
#  - cryptirc is this checkout's version (Cargo.toml): the binary carries it in its own
#    "CryptIRC v<version> listening on http://" log line. Neither binary is RUN for this —
#    cryptirc has no --version and would start a server. irc_core carries no version: it is
#    run once with an EMPTY environment as nobody, where it refuses to start ("set
#    CRYPTIRC_IPC_SOCK, CRYPTIRC_DATA, or XDG_RUNTIME_DIR") before binding anything — proof
#    that it is irc_core and runs here; that it is this checkout's daemon is taken on trust
#    (the daemon-change detection below hashes this checkout's daemon sources).
BIN_DIR=target/release
if [[ -n "$PREBUILT_DIR" ]]; then
    _pb_fail() { echo -e "${RED}✗ --prebuilt ${PREBUILT_DIR}: $*${NC}" >&2; echo -e "${DIM}Nothing was changed.${NC}" >&2; exit 1; }
    [[ "$PREBUILT_DIR" == /* ]] || _pb_fail "give an absolute path"
    _pb=$(readlink -e -- "$PREBUILT_DIR" 2>/dev/null) || _pb_fail "not a directory"
    [[ -d "$_pb" ]] || _pb_fail "not a directory"
    _dir_closed "$_pb" || _pb_fail "the directory (or one above it) is not root-owned, or is writable by group/others"
    _pb_want=$( grep -m1 '^version[[:space:]]*=' "$REPO_DIR/Cargo.toml" | cut -d'"' -f2 || true )
    [[ "$_pb_want" =~ ^[0-9A-Za-z.+-]+$ ]] || _pb_fail "can't read the version from $REPO_DIR/Cargo.toml"
    case "$(uname -m)" in x86_64) _pb_mach=3e00 ;; aarch64) _pb_mach=b700 ;; *) _pb_mach="" ;; esac
    for _b in cryptirc irc_core; do
        _f="$_pb/$_b"
        if [[ "$_b" == irc_core && ! -e "$_f" && ! -L "$_f" ]]; then continue; fi    # optional, as a build without it
        [[ -f "$_f" && ! -L "$_f" ]] || _pb_fail "$_b is missing or not a regular file"
        _st=$(stat -c '%u %a' -- "$_f") || _pb_fail "can't stat $_b"
        if [[ "${_st%% *}" != 0 ]] || (( (8#${_st#* } & 8#022) != 0 || (8#${_st#* } & 8#111) == 0 )); then
            _pb_fail "$_b must be root-owned, not group/other-writable, and executable (it is: $(stat -c '%U %A' -- "$_f"))"
        fi
        _hdr=$(head -c 20 -- "$_f" | od -An -tx1 | tr -d ' \n')
        [[ "${_hdr:0:10}" == 7f454c4602 ]] || _pb_fail "$_b is not a 64-bit ELF executable"
        [[ -z "$_pb_mach" || "${_hdr:36:4}" == "$_pb_mach" ]] || _pb_fail "$_b is built for another machine than this $(uname -m)"
        _ldd=$(ldd "$_f" 2>&1) || _pb_fail "this host can't load $_b: $(printf '%s' "$_ldd" | head -3)"
        if grep -q 'not found' <<< "$_ldd"; then
            _pb_fail "this host can't load $_b — $(grep -m2 'not found' <<< "$_ldd" | sed 's|^[[:space:]]*||' | tr '\n' ' ')(built against a newer system library? build it on this distribution's release)"
        fi
    done
    grep -aqF "CryptIRC v${_pb_want} listening on http://" -- "$_pb/cryptirc" \
        || _pb_fail "cryptirc is not version ${_pb_want} (the version in $REPO_DIR/Cargo.toml) — build it from this checkout"
    HAVE_PB_CORE=false
    if [[ -f "$_pb/irc_core" ]]; then
        # (run from a private copy nobody can reach: DIR itself may well sit under /root)
        _pb_tmp=$(mktemp -d "${TMPDIR:-/tmp}/cryptirc-prebuilt.XXXXXX") || _pb_fail "can't make a temporary directory"
        chmod 711 "$_pb_tmp"; install -m 755 "$_pb/irc_core" "$_pb_tmp/irc_core" || { rm -rf "$_pb_tmp"; _pb_fail "can't copy irc_core to $_pb_tmp"; }
        _pb_rc=0; _pb_out=$(cd / && setpriv --reuid=65534 --regid=65534 --clear-groups env -i timeout 10 "$_pb_tmp/irc_core" 2>&1 </dev/null) || _pb_rc=$?
        rm -rf "$_pb_tmp"
        if [[ "$_pb_rc" != 2 || "$_pb_out" != *"refusing to start"* ]]; then
            _pb_fail "irc_core didn't behave as the daemon does when it has no settings (exit ${_pb_rc}; expected 2, \"refusing to start\") — is it irc_core, and can it run here (${TMPDIR:-/tmp} not noexec)?"
        fi
        HAVE_PB_CORE=true
    fi
    BIN_DIR="$_pb"
    echo -e "  ${GREEN}✓ Prebuilt binaries:${NC} ${_pb} ${DIM}(cryptirc v${_pb_want}$([[ "$HAVE_PB_CORE" == true ]] && echo ", irc_core"); this run doesn't pull or build)${NC}"
fi

# ── One update at a time ────────────────────────────────────────────────────
# Two overlapping runs (two admins, or cron + a human) would interleave the
# stop/swap/start and the backup pruning. The lock lives in /run (root-only, so
# no symlink games) and is held on fd 9 for the life of the process; the
# self-update handoff below `exec`s with fd 9 still open, so the new copy keeps
# the same lock instead of racing a second run for it.
UPDATE_LOCK=/run/cryptirc-update.lock
if command -v flock &>/dev/null; then
    if ! { [[ "${CRYPTIRC_UPDATE_HANDOFF:-}" == "1" ]] && { true >&9; } 2>/dev/null; }; then
        exec 9>>"$UPDATE_LOCK"
    fi
    if ! flock -n 9; then
        echo -e "${RED}✗ Another update.sh is already running (lock: ${UPDATE_LOCK}).${NC} Let it finish, then re-run if needed." >&2
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ flock not found — cannot guard against a second update.sh running at the same time.${NC}" >&2
fi

_banner

# ── Rollback state + the exit safety net ─────────────────────────────────────
# Every file this run replaces is copied into RB_DIR first, and every service it
# stops is remembered, so any way out of the "applying" window — a failed health
# check, an error, Ctrl-C, an SSH drop, a full disk — ends with the PREVIOUS
# version back in place and running, never with a stopped or half-swapped site.
RB_DIR="$INSTALL_DIR/.rollback"
CRYPTIRC_STOPPED_BY_US=false   # we stopped cryptirc and it is not confirmed back up yet
IRC_CORE_STOPPED_BY_US=false   # same for irc-core (only ever stopped under --restart-daemon)
WEB_TOUCHED=false              # we stopped or (re)started cryptirc in this run
DAEMON_TOUCHED=false           # we stopped or (re)started irc-core in this run
SWAPPED_WEB=false              # /opt/cryptirc/cryptirc is the NEW binary (old one in RB_DIR)
SWAPPED_DAEMON=false           # same for irc_core
UNITS_CHANGED=()               # unit files rewritten this run (originals in RB_DIR/units)
IRC_CORE_UNIT_CREATED=false    # pre-split migration wrote a brand-new irc-core.service
IN_WINDOW=false                # inside the apply window (services may be stopped/swapped)
USER_DATA_SNAP0=""             # per-user data fingerprint taken just before the NEW web started
ROLLBACK_WITHHELD=false        # a rollback was due but refused (data migrated) — exit 4

# Write a milestone to the terminal AND the journal (journalctl -t cryptirc-update),
# so the outcome is still on record when the SSH session that started it is gone.
# Never fails: a dead terminal (EIO) or a closed pipe must not abort the update.
_note() {
    echo -e "$*" 2>/dev/null || true
    command -v logger &>/dev/null && \
        logger -t cryptirc-update -- "$(printf '%b' "$*" | sed 's/\x1b\[[0-9;]*m//g')" 2>/dev/null
    return 0
}

_recover_on_exit() {
    local rc=$?
    # Must not die half-way: errexit/nounset off, and no signal may interrupt the recovery.
    # (Under `set -e` the old trap's first echo hit EIO after an SSH drop and aborted the
    # trap before it restarted anything — the exact case it was written for.)
    set +eu
    trap '' INT HUP TERM QUIT PIPE TSTP TTIN TTOU
    tput cnorm 2>/dev/null   # restore the cursor if a _spin/_ghost_fly was interrupted mid-animation
    rm -f "$INSTALL_DIR/cryptirc.new" "$INSTALL_DIR/irc_core.new" 2>/dev/null   # staged, never installed
    # The registration-code move's staged files, when the run ended before _regmig_apply put them
    # in place (a staging failure, an interrupt, a failure before the apply window…).
    [[ -n "${REGMIG_ENV_NEW:-}" ]] && rm -f "$REGMIG_ENV_NEW" 2>/dev/null
    [[ -n "${REGMIG_UNIT_NEW:-}" ]] && rm -f "$REGMIG_UNIT_NEW" 2>/dev/null
    if [[ "$IN_WINDOW" == "true" ]]; then
        _rollback "update.sh was interrupted (exit ${rc}) while applying the update"
        if [[ "$ROLLBACK_WITHHELD" == "true" ]]; then rc=4
        elif [[ "$ROLLBACK_OK" == "true" ]]; then rc=1
        else rc=3; fi
    fi
    # Belt and braces: never leave a service stopped that this run stopped.
    if [[ "$IRC_CORE_STOPPED_BY_US" == "true" ]] && ! systemctl is-active --quiet irc-core; then
        _note "  ${YELLOW}⚠ irc-core was left stopped — starting it again...${NC}"
        systemctl start irc-core 2>/dev/null
    fi
    if [[ "$CRYPTIRC_STOPPED_BY_US" == "true" ]] && ! systemctl is-active --quiet cryptirc; then
        _note "  ${YELLOW}⚠ cryptirc was left stopped — starting it again...${NC}"
        systemctl reset-failed cryptirc 2>/dev/null
        systemctl start cryptirc 2>/dev/null
    fi
    exit "$rc"
}
trap _recover_on_exit EXIT

# ── Where does the running install keep its data? ───────────────────────────
# Settings that end up in files root writes (the irc-core unit the pre-split migration
# generates) or in what root backs up come ONLY from root-owned sources: the unit files and
# drop-ins (`systemctl show`) and EnvironmentFile=s that are root-owned and not group/world-
# writable. Never from /proc/<pid>/environ or /proc/<pid>/cwd of the service: those belong to
# the unprivileged service account, which can rewrite them (a value with a newline written
# into a unit would let it run commands as root). The live environment is used only to
# probe the running process (port / base path / socket) and as a cross-check below.
# _proc_env <pid> <NAME>: NAME's value in that process's REAL environment. rc 1 = not set,
# rc 2 = unreadable (no such process; or it is exiting, when its environ reads back EMPTY —
# a live service always has some variables). Pure bash (no pipeline), so it behaves the
# same with SIGPIPE ignored.
_proc_env() {
    local kv any=false
    [[ "$1" =~ ^[1-9][0-9]*$ && -r "/proc/$1/environ" ]] || return 2
    { while IFS= read -r -d '' kv; do
          any=true
          if [[ "$kv" == "$2="* ]]; then printf '%s' "${kv#*=}"; return 0; fi
      done; } < "/proc/$1/environ" 2>/dev/null || return 2
    [[ "$any" == "true" ]] || return 2
    return 1
}
# _safe_path, _sane_path, _sysd_words, _dir_chain_protected, _envfile_trusted, _envfile_text,
# _envfile_get, _unit_envfiles, _unit_env: deploy/unit-env.sh, sourced at the top (shared with the
# installers).
# _pid_is_systemd <pid>: during every (re)start the unit's main PID is first systemd's own
# forked child (systemd-executor on newer systemd), which has not exec'd the service binary
# yet: its environment is systemd's, not the service's — reading CRYPTIRC_BASE_PATH there
# finds nothing and probed (and reported) the binary's /cryptirc default.
_pid_is_systemd() {
    local exe
    exe=$(readlink "/proc/$1/exe" 2>/dev/null) || return 1
    exe="${exe% (deleted)}"
    [[ "${exe##*/}" == "systemd" || "${exe##*/}" == "systemd-executor" ]]
}
# _svc_env <unit> <pid> <NAME>: prefer the live process, fall back to the unit's files. For
# PROBING the running service only (port, base path, socket): never write its result anywhere.
_svc_env() {
    local v rc
    if _pid_is_systemd "$2"; then rc=2; else v=$(_proc_env "$2" "$3"); rc=$?; fi
    (( rc == 2 )) && { v=$(_unit_env "$1" "$3"); rc=$?; }
    printf '%s' "$v"
    return "$rc"
}
# The web service's main PID right now (empty when it isn't running) — for the cross-check.
WEB_PID0=""
systemctl is-active --quiet cryptirc 2>/dev/null && WEB_PID0=$(systemctl show -p MainPID --value cryptirc 2>/dev/null || true)
[[ "$WEB_PID0" =~ ^[1-9][0-9]*$ ]] || WEB_PID0=""
_refuse_env() {   # _refuse_env <message…>: stop before anything has been touched
    echo -e "  ${RED}✗ $*${NC}" >&2
    echo -e "  ${DIM}Nothing was changed. Fix the cryptirc service's settings (systemctl cat cryptirc), then re-run.${NC}" >&2
    exit 1
}
# _web_setting <NAME>: NAME from the cryptirc unit's root-owned settings, validated as a
# plain absolute path when set. Prints the value (empty = not set). Refuses — never falls
# back to some other directory — when the value is unusable.
_web_setting() {
    local v="" rc=0 live lrc=0
    v=$(_unit_env cryptirc "$1") || rc=$?
    (( rc == 5 )) && _refuse_env "cryptirc.service has EnvironmentFile=$(_envfile_glob_unsupported cryptirc) — a wildcard in a directory part, which this script doesn't follow (only the file name may have one, e.g. /etc/cryptirc/env.d/*.env), so it can't tell what $1 the service gets. Name the directory itself, then re-run."
    (( rc == 3 )) && _refuse_env "$1 is set in an EnvironmentFile of cryptirc.service that is not root-owned, is group/world-writable, or sits (or is a symlink) in a directory others can write — or a wildcard EnvironmentFile reads a directory others can add files to ($(_unit_envfiles cryptirc | xargs)) — its value can't be trusted. Make it a root-owned file that others can't write (chown root: FILE; chmod go-w FILE), in a directory only root can write, e.g. /etc/cryptirc/."
    if (( rc == 0 )) && [[ "$v" == /* ]] && ! _sane_path "$v"; then
        _refuse_env "$1 in the cryptirc service's settings is not a usable absolute path (no control characters or ..): $(printf '%q' "$v")"
    fi
    if (( rc == 0 )) && [[ -n "$v" && "$v" != /* && ! "$v" =~ ^[A-Za-z0-9._/-]+$ ]]; then
        _refuse_env "$1 in the cryptirc service's settings is neither an absolute path nor a plain relative one: $(printf '%q' "$v")"
    fi
    # Cross-check with the running process. Its environment belongs to the service account,
    # so it is never USED — but a value there that its unit never set, and that isn't even
    # a plain path, means it was tampered with: stop and say so.
    if [[ -n "$WEB_PID0" ]]; then
        live=$(_proc_env "$WEB_PID0" "$1") || lrc=$?
        if (( lrc == 0 )) && [[ "$live" != "$v" ]]; then
            if [[ "$live" == /* ]] && _sane_path "$live" || [[ "$live" =~ ^[A-Za-z0-9._/-]+$ ]]; then
                # (CRYPTIRC_DATA: _resolve_data_dir compares the directories themselves and stops.)
                [[ "$1" == CRYPTIRC_DATA ]] || echo -e "  ${YELLOW}⚠ The running cryptirc has $1=${live}, but its unit now says ${v:-(unset)} (changed without a restart?) — using the unit's; the restarted service uses it too.${NC}" >&2
            else
                _refuse_env "The RUNNING cryptirc process reports $1=$(printf '%q' "$live"), which its unit never set and which is not a plain path. That should never happen — has the service account been tampered with? Refusing to build any configuration from it."
            fi
        fi
    fi
    printf '%s' "$v"
}
# _resolve_data_dir: the data dir the cryptirc service uses (CRYPTIRC_DATA; when unset or
# relative, the binary's ./data default resolves against the unit's WorkingDirectory). The
# backup, the irc-core checks and the pre-split migration all use it.
_resolve_data_dir() {
    local v wd
    systemctl cat cryptirc.service &>/dev/null || { printf '%s' "$DATA_DIR"; return 0; }
    v=$(_web_setting CRYPTIRC_DATA) || exit 1
    [[ -n "$v" ]] || v=./data
    if [[ "$v" != /* ]]; then
        wd=$(systemctl show -p WorkingDirectory --value cryptirc 2>/dev/null || true)
        wd="${wd#[-!+]}"; [[ "$wd" == /* ]] || wd=/
        v="${wd%/}/${v#./}"
    fi
    while [[ "$v" == */ && "$v" != / ]]; do v="${v%/}"; done
    _sane_path "$v" || _refuse_env "The cryptirc service's data directory resolves to $(printf '%q' "$v"), which is not a usable absolute path."
    # The RUNNING service must be using that directory. If it isn't (its settings were changed
    # without a restart, or something sets it that isn't read here), the backup, the data checks
    # and a rollback decision would all look at the wrong one: stop.
    if [[ -n "$WEB_PID0" ]]; then
        local live lrc=0
        live=$(_live_data_dir "$WEB_PID0") || lrc=$?
        if (( lrc == 0 )) && ! _same_dir "$live" "$v"; then
            _refuse_env "The running cryptirc uses the data directory $(printf '%q' "$live"), but its unit's settings now resolve to $(printf '%q' "$v") — this run would back up and check the wrong one. If the settings were changed on purpose (the data moved), restart it first so it runs with them: sudo systemctl daemon-reload && sudo systemctl restart cryptirc."
        fi
    fi
    printf '%s' "$v"
}
# A refusal inside the $( ) prints its reason and exits that subshell non-zero → exit here too.
DATA_DIR=$(_resolve_data_dir) || exit 1
# The web's own CRYPTIRC_IPC_SOCK (the pre-split migration copies it into the daemon's unit).
WEB_IPC_SOCK0=$(_web_setting CRYPTIRC_IPC_SOCK) || exit 1
if [[ -n "$WEB_IPC_SOCK0" ]] && ! _sane_path "$WEB_IPC_SOCK0"; then
    _refuse_env "CRYPTIRC_IPC_SOCK in the cryptirc service's settings is not a usable absolute path: $(printf '%q' "$WEB_IPC_SOCK0")"
fi
[[ "$DATA_DIR" != "/var/lib/cryptirc" ]] && echo -e "  ${DIM}Data directory: ${DATA_DIR} (from the cryptirc service's settings)${NC}"
# A pre-split install (no irc-core.service yet, and this checkout builds the daemon) is moved over by
# writing the data dir (and a custom socket path) into a NEW unit file: only a plain path will do there.
# Checked now, before the backup and the build (and once more after the build, below).
if ! systemctl cat irc-core.service &>/dev/null && systemctl cat cryptirc.service &>/dev/null \
   && [[ -f "$REPO_DIR/src/bin/irc_core.rs" ]] \
   && { ! _safe_path "$DATA_DIR" || { [[ -n "$WEB_IPC_SOCK0" ]] && ! _safe_path "$WEB_IPC_SOCK0"; }; }; then
    _refuse_env "This install predates the irc-core daemon, and moving it over writes its data directory ($(printf '%q' "$DATA_DIR"))${WEB_IPC_SOCK0:+ and socket path} into a new irc-core.service — that needs a plain absolute path (only letters, digits and . _ / -; no spaces, % or ..). Move the data to such a path (and point CRYPTIRC_DATA at it), then re-run."
fi

# ── Backup ────────────────────────────────────────────────────────────────────
# After the self-update handoff (below) this copy starts over from the top, but the copy that
# handed off has already made this update's backup: reuse it when it is of the same data dir,
# instead of archiving everything twice (and pruning one more old backup than one update should).
_bk_top() { tar tzf "$1" 2>/dev/null | head -1 | cut -d/ -f1; }
if [[ "$SKIP_BACKUP" == "false" && "${CRYPTIRC_UPDATE_HANDOFF:-}" == "1" && -n "${CRYPTIRC_UPDATE_BACKUP:-}" ]]; then
    _hb="$CRYPTIRC_UPDATE_BACKUP"; _dr=$(readlink -f -- "$DATA_DIR" 2>/dev/null || true)
    if [[ "$_hb" == "$BACKUP_DIR"/cryptirc-backup-*.tar.gz && -f "$_hb" && ! -L "$_hb" && -s "$_hb" && -n "$_dr" \
          && "$(_bk_top "$_hb")" == "$(basename "$_dr")" ]]; then
        SKIP_BACKUP=reused
        echo -e "  ${GREEN}✓ Backup:${NC} $_hb ${DIM}(made a moment ago by the copy of update.sh that handed over)${NC}"
    fi
fi
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
    # A data dir that is a SYMLINK (data moved to another volume) is archived through to
    # its target: tar stores a symlink argument as just the link, which made every backup
    # "succeed" with no data in it. Links INSIDE it (a user's directory moved to another disk,
    # e2e/<user> → …) are followed too — as the service account, never into a device, FIFO,
    # socket, /proc, /sys or /dev (deploy/data-floor.sh's _backup_data) — and an archive that
    # still holds a symlink member is refused: a link restores no data.
    DATA_REAL=$(readlink -f -- "$DATA_DIR" 2>/dev/null || true)
    if [[ -z "$DATA_REAL" || ! -d "$DATA_REAL" ]]; then
        echo -e "  ${RED}✗ Backup failed: the data directory ${DATA_DIR} does not exist — aborting update; nothing was changed.${NC}"
        echo -e "  ${DIM}It comes from CRYPTIRC_DATA in the cryptirc service (systemctl cat cryptirc). To update without a backup this once: sudo bash deploy/update.sh --no-backup${NC}"
        exit 1
    fi
    [[ "$DATA_REAL" != "$DATA_DIR" ]] && echo -e "  ${DIM}${DATA_DIR} is a symlink — backing up what it points to: ${DATA_REAL}${NC}"
    tar_rc=0; _bk_msgs=$(mktemp)
    _spin "Archiving $(basename "$DATA_REAL") …" _backup_data "$DATA_REAL" "$BACKUP_FILE" "$_bk_msgs" || tar_rc=$?
    # (Names from the data dir are in these lines, cleaned by _backup_data: printf, never echo -e.)
    while IFS= read -r _l; do printf '  %b⚠ Backup: %s%b\n' "$YELLOW" "$_l" "$NC"; done < "$_bk_msgs"
    _bk_partial=false; grep -q "can't read" "$_bk_msgs" && _bk_partial=true
    rm -f "$_bk_msgs"
    # Verify the archive is actually LISTABLE, not just non-empty — a truncated-but-nonzero
    # gzip (disk filled mid-write, returned rc 1) would pass `-s` yet be useless on restore —
    # and that it holds the directory itself (not a link to it) with its contents.
    _bk_ok=false
    if [[ ( "$tar_rc" -eq 0 || "$tar_rc" -eq 1 ) && -s "$BACKUP_FILE" ]]; then
        _bk_list=$(tar tzvf "$BACKUP_FILE" 2>/dev/null | awk 'NR == 1 { t = substr($1, 1, 1) } END { print NR " " t }') || _bk_list=""
        if [[ "$_bk_list" == *" d" ]]; then
            _bk_ok=true
            if [[ -n "$(find "$DATA_REAL" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] && (( ${_bk_list%% *} < 2 )); then
                _bk_ok=false
            fi
            if tar tzvf "$BACKUP_FILE" 2>/dev/null | awk 'substr($1, 1, 1) == "l" { found = 1 } END { exit !found }'; then
                _bk_ok=false
                echo -e "  ${RED}✗ The backup holds symlinks instead of the data behind them.${NC}"
            fi
        fi
    fi
    if [[ "$_bk_ok" == "true" ]]; then
        BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
        echo -e "  ${GREEN}✓ Backup saved:${NC} $BACKUP_FILE (${BACKUP_SIZE})"
        [[ "$tar_rc" -eq 1 ]] && echo -e "  ${DIM}(some files changed while being read — normal on a live server; the backup is still complete)${NC}"
    else
        rm -f "$BACKUP_FILE"
        echo -e "  ${RED}✗ Backup failed (tar exit ${tar_rc}) — aborting update; nothing was changed.${NC}"
        echo -e "  ${DIM}Check free space (df -h $(dirname "$DATA_REAL") $BACKUP_DIR) and that $DATA_DIR is readable, then retry.${NC}"
        echo -e "  ${DIM}To update without a backup this once: sudo bash deploy/update.sh --no-backup${NC}"
        exit 1
    fi

    # Handed over by an older update.sh (it doesn't pass its backup on): that copy archived the
    # same data seconds ago — keep only this one (newer), if it is of the same directory, so one
    # update counts once in the rotation below. (Not when this one left out files the service
    # account can't read: the older copy, made as root, still has them.)
    if [[ "${CRYPTIRC_UPDATE_HANDOFF:-}" == "1" && "$_bk_partial" != true ]]; then
        _prev_bk=""
        for _f in "$BACKUP_DIR"/cryptirc-backup-*.tar.gz; do
            [[ "$_f" == "$BACKUP_FILE" || ! -f "$_f" ]] && continue
            [[ -z "$_prev_bk" || "$_f" -nt "$_prev_bk" ]] && _prev_bk=$_f
        done
        if [[ -n "$_prev_bk" && -f "$_prev_bk" && ! -L "$_prev_bk" ]] \
           && [[ -n "$(find "$_prev_bk" -mmin -15 2>/dev/null)" ]] \
           && [[ "$(_bk_top "$_prev_bk")" == "$(basename "$DATA_REAL")" ]]; then
            rm -f "$_prev_bk" && echo -e "  ${DIM}(replaced $(basename "$_prev_bk"), the backup the previous copy of update.sh made a moment ago)${NC}"
        fi
    fi
    # Keep only the last 5 backups
    ls -1t "$BACKUP_DIR"/cryptirc-backup-*.tar.gz 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/cryptirc-backup-*.tar.gz 2>/dev/null | wc -l)
    echo -e "  ${DIM}(${BACKUP_COUNT} backups kept, older ones pruned)${NC}"
    echo ""
fi

# ── Pull latest code ──────────────────────────────────────────────────────────
cd "$REPO_DIR"
GIT_PULL_OK=true
if [[ -n "$PREBUILT_DIR" ]]; then
    _git_before=prebuilt; _git_after=prebuilt      # (nothing pulled: see the summary)
else
_progress "Pulling latest code"
# Capture HEAD before/after so the summary can state plainly whether the code actually
# ADVANCED — a failed --ff-only (diverged/force-pushed upstream) otherwise silently builds
# the OLD checkout while everything downstream reports success, i.e. a no-op "deploy".
# -c safe.directory: update.sh runs as root over a (often non-root-owned) checkout; without it
# git 2.35.2+ aborts with "dubious ownership" and the pull always fails. Scoped, no global mutation.
#
# git runs as the checkout's OWNER, not root (like the installers): a root pull left
# root-owned objects, refs and FETCH_HEAD in the operator's clone, and their own next
# `git pull` then failed with "Permission denied". Root-owned files an earlier root
# pull/build left behind are handed back first, so the owner's pull can write. (A user
# cannot create root-owned files, so every root-owned file in their checkout is ours.)
REPO_OWNER=$(stat -c %U "$REPO_DIR/.git" 2>/dev/null || echo root)
_as_owner=()
_give_back_to_owner() {   # _give_back_to_owner <dir>…: chown root-owned files there to the checkout owner
    [[ "$REPO_OWNER" != root && "$REPO_OWNER" != UNKNOWN ]] || return 0
    local d grp
    grp=$(id -gn "$REPO_OWNER" 2>/dev/null || echo "$REPO_OWNER")
    for d in "$@"; do
        [[ -d "$d" ]] && find "$d" -xdev -user root -exec chown -h "$REPO_OWNER:$grp" {} + 2>/dev/null
    done
    return 0
}
if [[ "$REPO_OWNER" != root && "$REPO_OWNER" != UNKNOWN ]] && command -v runuser &>/dev/null; then
    _owner_home=$(getent passwd "$REPO_OWNER" | cut -d: -f6 || true)
    _as_owner=(runuser -u "$REPO_OWNER" -- env HOME="${_owner_home:-/}")
    _give_back_to_owner "$REPO_DIR"
fi
_git_before=$(git -c safe.directory="$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')
"${_as_owner[@]}" git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" pull --ff-only 2>&1 || { GIT_PULL_OK=false; echo -e "  ${YELLOW}⚠ git pull failed — building from the EXISTING checkout; this may NOT be the latest code${NC}"; }
_git_after=$(git -c safe.directory="$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')
# After the self-update handoff (below) the new copy's own pull is a no-op: report the
# range the FIRST copy pulled. An older update.sh doesn't pass it on, but its pull is then
# the latest HEAD move in the reflog.
if [[ "${CRYPTIRC_UPDATE_HANDOFF:-}" == "1" && "$_git_before" == "$_git_after" ]]; then
    if [[ -n "${CRYPTIRC_UPDATE_GIT_BEFORE:-}" ]]; then
        _git_before=$CRYPTIRC_UPDATE_GIT_BEFORE
    else
        _git_before=$(git -c safe.directory="$REPO_DIR" rev-parse --short 'HEAD@{1}' 2>/dev/null || echo "$_git_before")
    fi
fi
echo ""
fi   # (not --prebuilt)

# ── Self-update handoff ───────────────────────────────────────────────────────
# Operators launch the update.sh that shipped with their PREVIOUS checkout — a
# script that by definition knows nothing about migrations added after it. That
# exact gap once shipped a web-only update across the 0.3.24 daemon split: the
# pre-split update.sh swapped the web binary, never installed irc-core.service,
# and left the site up with every user's IRC dead while the web process silently
# retried a socket nobody serves. If the pull changed THIS script — or data-floor.sh /
# unit-env.sh, which it sourced before the pull — hand execution to the new copy
# (exactly once — the env guard stops any loop) so migrations always come from the
# version that ships with the code being deployed.
# Re-running from the top is safe: backup, pull, and dep checks are idempotent,
# and nothing state-changing (build/swap/restart) has happened yet. exec skips
# the EXIT trap by design — CRYPTIRC_STOPPED_BY_US can't be true this early.
if [[ -z "$PREBUILT_DIR" && "${CRYPTIRC_UPDATE_HANDOFF:-}" != "1" && "$GIT_PULL_OK" == "true" && -n "$SELF_SHA_AT_START" ]]; then
    _self_sha_now=$(_self_fingerprint | tr '\n' ' ')
    if [[ -n "${_self_sha_now// /}" && "$_self_sha_now" != "$SELF_SHA_AT_START" ]]; then
        echo -e "  ${YELLOW}update.sh itself (or a helper it uses: deploy/data-floor.sh, deploy/unit-env.sh) changed in this pull — handing off to the new version…${NC}"
        export CRYPTIRC_UPDATE_HANDOFF=1 CRYPTIRC_UPDATE_GIT_BEFORE="$_git_before" CRYPTIRC_UPDATE_BACKUP="${BACKUP_FILE:-}"
        exec bash "$SCRIPT_DIR/update.sh" "$@"
    fi
fi

# ── Build ─────────────────────────────────────────────────────────────────────
# ── Auto-install build dependencies ──────────────────────────────────────────
# Make the box able to BUILD from a cold start: check for the toolchain the release
# build needs (C compiler + make + perl for the vendored OpenSSL, pkg-config) and
# auto-install whatever's missing via this host's package manager. Idempotent + a
# near-instant no-op once the box has built before — but means the script "just works"
# on a fresh host. (Rust itself is handled by the cargo probe just below.)
_pkgmgr=""
for _m in apt-get dnf yum pacman zypper apk brew; do command -v "$_m" &>/dev/null && { _pkgmgr="$_m"; break; }; done
if [[ -z "$PREBUILT_DIR" ]]; then
_progress "Checking build dependencies"
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
        # -S, not -Sy: refreshing the sync db without upgrading is an Arch partial upgrade.
        pacman)  pacman -S --noconfirm --needed "${_pkgs[@]}" && _ok=true \
                     || echo -e "  ${DIM}(if pacman could not find a package, run: sudo pacman -Syu — then retry)${NC}" ;;
        zypper)  zypper --non-interactive install "${_pkgs[@]}" && _ok=true ;;
        apk)     apk add --no-cache "${_pkgs[@]}" && _ok=true ;;
        brew)    brew install "${_pkgs[@]}" && _ok=true ;;
    esac
    [[ "$_ok" == "true" ]] || { echo -e "  ${RED}✗ Auto-install failed — install ${_need[*]} manually and retry.${NC}"; exit 1; }
fi
echo -e "  ${GREEN}✓ Build toolchain present${NC}"
fi   # (not --prebuilt)

# Runtime helper: exiftool. upload.rs strips metadata from GIF/WebP/AVIF/HEIC/HEIF/TIFF
# with it and refuses those uploads when it is missing (fail-closed) — and no installer
# ever installed it. Best effort: never fails the update.
if ! command -v exiftool &>/dev/null && [[ ! -x /usr/bin/vendor_perl/exiftool ]]; then
    _xt=""
    case "$_pkgmgr" in
        apt-get) _xt=libimage-exiftool-perl ;;
        pacman)  _xt=perl-image-exiftool ;;
        dnf|yum) _xt=perl-Image-ExifTool ;;
        zypper|apk|brew) _xt=exiftool ;;
    esac
    if [[ -n "$_xt" ]]; then
        echo -e "  ${YELLOW}Installing exiftool (${_xt}) — needed to strip metadata from GIF/WebP/AVIF/HEIC/TIFF uploads${NC}"
        _xok=false
        case "$_pkgmgr" in
            apt-get) { apt-get install -y -qq "$_xt" || { apt-get update -qq && apt-get install -y -qq "$_xt"; }; } >/dev/null 2>&1 && _xok=true ;;
            pacman)  pacman -S --noconfirm --needed "$_xt" >/dev/null 2>&1 && _xok=true ;;
            dnf|yum) "$_pkgmgr" install -y -q "$_xt" >/dev/null 2>&1 && _xok=true ;;
            zypper)  zypper --non-interactive install "$_xt" >/dev/null 2>&1 && _xok=true ;;
            apk)     apk add --no-cache "$_xt" >/dev/null 2>&1 && _xok=true ;;
            brew)    brew install "$_xt" >/dev/null 2>&1 && _xok=true ;;
        esac
        if [[ "$_xok" == "true" ]]; then echo -e "  ${GREEN}✓ exiftool installed${NC}"
        else echo -e "  ${YELLOW}⚠ Could not install ${_xt} — GIF/WebP/AVIF/HEIC/TIFF uploads stay disabled until it is installed.${NC}"; fi
    fi
fi
# Arch installs it to /usr/bin/vendor_perl, which is not on a systemd service's PATH.
if [[ -x /usr/bin/vendor_perl/exiftool && ! -e /usr/local/bin/exiftool && -d /usr/local/bin ]] \
   && ! PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin command -v exiftool &>/dev/null; then
    ln -s /usr/bin/vendor_perl/exiftool /usr/local/bin/exiftool 2>/dev/null \
        && echo -e "  ${GREEN}✓ exiftool linked into /usr/local/bin${NC} ${DIM}(on the services' PATH)${NC}"
fi
echo ""

if [[ -z "$PREBUILT_DIR" ]]; then
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
# GIT_OPTIONAL_LOCKS=0: build.rs runs `git status` for the version stamp, and as root that
# rewrote .git/index as a root-owned file in the operator's checkout.
_build_ok=true
GIT_OPTIONAL_LOCKS=0 cargo build --release 2>&1 | tee "$BUILD_LOG" | tail -5 || _build_ok=false
# The build runs as root (the toolchain may well be root's own), so hand target/ — and
# anything else it created in the checkout, or in a cargo/rustup home that belongs to the
# operator — back to them: their own next `cargo build` / `git pull` must keep working.
_give_back_to_owner "$REPO_DIR"
for _h in "${CARGO_HOME:-}" "${RUSTUP_HOME:-}"; do
    [[ -n "$_h" && -d "$_h" && "$(stat -c %U "$_h" 2>/dev/null)" == "$REPO_OWNER" && "$_h" != /root/* ]] && _give_back_to_owner "$_h"
done
if [[ "$_build_ok" != "true" ]]; then
    echo -e "  ${RED}✗ Build failed — the service was NOT touched. First errors:${NC}"
    grep -m3 -E '^error' "$BUILD_LOG" || tail -20 "$BUILD_LOG"
    rm -f "$BUILD_LOG"; exit 1
fi
rm -f "$BUILD_LOG"
# Guard the build-succeeded-but-no-binary case (e.g. an upstream bin rename) BEFORE we
# stop the service — matches deploy.sh. A cp on a missing source would leave it down.
[[ -f target/release/cryptirc ]] || { echo -e "  ${RED}✗ Build reported success but target/release/cryptirc is missing — aborting; service untouched.${NC}"; exit 1; }
fi   # (not --prebuilt)
# irc_core is only built once the daemon-split has landed on this checkout —
# older commits won't produce it, so its absence isn't fatal (nothing to swap).
HAVE_IRC_CORE=false
[[ -f "$BIN_DIR/irc_core" ]] && HAVE_IRC_CORE=true
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
# The pre-split migration writes the data dir (and a custom socket path) into a NEW unit file:
# there only a plain path will do. Say so now, before anything is touched.
if [[ "$HAVE_IRC_CORE" == "true" && "$HAVE_IRC_CORE_UNIT" == "false" ]] \
   && { ! _safe_path "$DATA_DIR" || { [[ -n "$WEB_IPC_SOCK0" ]] && ! _safe_path "$WEB_IPC_SOCK0"; }; }; then
    _refuse_env "This install predates the irc-core daemon, and moving it over writes its data directory ($(printf '%q' "$DATA_DIR"))${WEB_IPC_SOCK0:+ and socket path} into a new irc-core.service — that needs a plain absolute path (only letters, digits and . _ / -; no spaces, % or ..). Move the data to such a path (and point CRYPTIRC_DATA at it), then re-run."
fi

# ── The install directory belongs to root ────────────────────────────────────
# Before anything below writes into it (markers, the staged binaries, the rollback copies): the
# directory, the two binaries, the markers and .rollback are made root's, and only they (deploy/
# unit-env.sh's _secure_install_dir: never recursive, never through a link; a binary or marker that
# isn't root's is replaced by a root-owned copy, not chowned in place). The data and socket
# directories are left alone wherever they are. The services never write there (ProtectSystem=strict;
# their ReadWritePaths are the data and log dirs).
# The service account (the web unit's User=) may own what gets replaced; anyone else's file is refused.
# The services' data and socket directories (web's and irc-core's, from their root-owned settings) are excluded.
_sid_user=$(systemctl show -p User --value cryptirc 2>/dev/null || true); [[ -n "$_sid_user" ]] || _sid_user=cryptirc
# (DATA_DIR as written; _sid_service_dirs adds it fully resolved too, and irc-core's own data/socket dirs.)
_sid_dirs=(); _sid_warns=(); _sid_svc_refuse=""
while IFS= read -r _sid_l; do
    case "$_sid_l" in
        "DIR "*) _sid_dirs+=("${_sid_l#DIR }") ;; "WARN "*) _sid_warns+=("${_sid_l#WARN }") ;;
        "REFUSE "*) _sid_svc_refuse="${_sid_l#REFUSE }" ;;
    esac
done < <(_sid_service_dirs "$INSTALL_DIR" "$DATA_DIR" "$WEB_IPC_SOCK0")
if (( ${#_sid_warns[@]} )); then for _sid_l in "${_sid_warns[@]}"; do echo -e "  ${YELLOW}⚠ ${_sid_l}${NC}"; done; fi
if [[ -n "$_sid_svc_refuse" ]]; then
    echo -e "  ${RED}✗ ${_sid_svc_refuse}${NC}" >&2
    echo -e "  ${DIM}The update stopped here: no binary, unit or service was touched.${NC}" >&2
    exit 1
fi
_sid_rc=0; _sid_out=$(_secure_install_dir "$INSTALL_DIR" "$_sid_user" "${_sid_dirs[@]}") || _sid_rc=$?
_sid_summary "$_sid_out"
[[ -n "$SID_FIXED" ]] && echo -e "  ${YELLOW}⚠ ${INSTALL_DIR}: ${SID_FIXED}${NC}"
[[ -n "$SID_OTHER" ]] && echo -e "  ${YELLOW}⚠ ${INSTALL_DIR}: ${SID_OTHER}${NC}"
if (( _sid_rc != 0 )); then
    [[ -n "$SID_REFUSE" ]] || SID_REFUSE="${INSTALL_DIR} could not be handed to root."
    echo -e "  ${RED}✗ ${SID_REFUSE}${NC}" >&2
    echo -e "  ${DIM}The update stopped here: no binary, unit or service was touched.${NC}" >&2
    exit 1
fi

# ── Smart change detection ───────────────────────────────────────────────────
# Hash the freshly-built binaries against what's currently DEPLOYED (compared BEFORE
# the swap below overwrites them) and auto-decide the restart actions, instead of
# relying on the operator to remember flags. Key asymmetry: restarting the WEB never
# drops IRC connections (those live in the daemon, which the web re-attaches to); only
# a DAEMON restart drops them — so the daemon is the single real decision.
WEB_CHANGED=true
DAEMON_CHANGED=true
if [[ -f "$INSTALL_DIR/cryptirc" ]] && cmp -s "$BIN_DIR/cryptirc" "$INSTALL_DIR/cryptirc"; then
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
# Is the RUNNING irc-core executing the binary that is on disk right now? Every run
# refreshes /opt/cryptirc/irc_core even when the daemon restart is deferred, so a
# daemon started before that refresh runs a since-replaced (deleted) inode.
# Prints yes | no | down (not running) | unknown.
_daemon_runs_ondisk() {
    local pid run_id disk_id
    systemctl is-active --quiet irc-core 2>/dev/null || { echo down; return; }
    pid=$(systemctl show -p MainPID --value irc-core 2>/dev/null || true)
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || { echo unknown; return; }
    run_id=$(stat -L -c '%d:%i' "/proc/$pid/exe" 2>/dev/null || true)
    disk_id=$(stat -L -c '%d:%i' "$INSTALL_DIR/irc_core" 2>/dev/null || true)
    if [[ -z "$run_id" || -z "$disk_id" ]]; then echo unknown
    elif [[ "$run_id" == "$disk_id" ]]; then echo yes
    # Another inode with the same bytes is the same daemon: the install-dir hand-back
    # (_secure_install_dir) replaces a binary that wasn't root's by a root-owned copy.
    elif cmp -s "/proc/$pid/exe" "$INSTALL_DIR/irc_core" 2>/dev/null; then echo yes
    else echo no
    fi
}
# .irc_core.ondisk-srchash = "<source hash> <sha256 of the irc_core file>": what the binary ON
# DISK was built from (written whenever this script or the installers put one there). After a
# deferred daemon change the RUNNING daemon's marker above is stale on purpose; once the daemon
# has restarted onto the file on disk anyway (a reboot, a manual restart), the on-disk record
# says what it now runs — without it, the next update called that daemon "changed" and an
# installer re-run restarted it for nothing, dropping everyone's IRC. The file's own sha256 is
# checked, so a binary some other tool (an older update.sh) put there isn't taken for it.
_ondisk_srchash() {   # prints the recorded source hash if it still describes $INSTALL_DIR/irc_core
    local rec h s
    rec=$(cat "$INSTALL_DIR/.irc_core.ondisk-srchash" 2>/dev/null) || return 1
    h=${rec%% *}; s=${rec#* }
    [[ "$h" =~ ^[0-9a-f]{64}$ && "$s" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$(sha256sum "$INSTALL_DIR/irc_core" 2>/dev/null | cut -d' ' -f1)" == "$s" ]] || return 1
    printf '%s' "$h"
}
_record_ondisk_srchash() {   # after a new irc_core is in place (or found byte-identical to this build)
    local s
    s=$(sha256sum "$INSTALL_DIR/irc_core" 2>/dev/null | cut -d' ' -f1) && [[ -n "$s" ]] \
        && echo "$DAEMON_SRC_HASH $s" > "$INSTALL_DIR/.irc_core.ondisk-srchash" 2>/dev/null
    return 0
}
if [[ "$HAVE_IRC_CORE" == "true" ]]; then
    if [[ -f "$INSTALL_DIR/.irc-core-srchash" ]]; then
        if [[ "$(cat "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null)" == "$DAEMON_SRC_HASH" ]]; then
            DAEMON_CHANGED=false
        elif [[ "$(_ondisk_srchash)" == "$DAEMON_SRC_HASH" ]] && [[ "$(_daemon_runs_ondisk)" == "yes" ]]; then
            # A deferred change that has been applied since (the daemon restarted onto the file).
            DAEMON_CHANGED=false
            echo "$DAEMON_SRC_HASH" > "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null || true
            echo -e "  ${DIM}irc-core already runs this daemon code (it restarted onto the binary an earlier update installed) — nothing to apply.${NC}"
        fi
    elif [[ -f "$INSTALL_DIR/irc_core" ]] && cmp -s "$BIN_DIR/irc_core" "$INSTALL_DIR/irc_core"; then
        # Bootstrap (no marker yet): the freshly-built daemon binary is byte-identical to
        # what's deployed. That only proves the daemon is current if the daemon actually
        # RUNS the deployed file: a previous run may have refreshed it on disk while
        # deferring the restart, leaving the old code running from a deleted inode. (The
        # old version seeded the marker here unconditionally, so that deferred change was
        # forgotten for good and a later --restart-daemon was refused as "unchanged".)
        case "$(_daemon_runs_ondisk)" in
            yes|down)
                # Running (or, once started, will run) exactly this binary → current.
                DAEMON_CHANGED=false
                echo "$DAEMON_SRC_HASH" > "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null || true ;;
            *)
                echo -e "  ${YELLOW}⚠ No .irc-core-srchash marker, and the running irc-core predates the irc_core binary on disk${NC}"
                echo -e "  ${DIM}(an earlier update installed it without restarting the daemon) — treating the daemon as CHANGED.${NC}" ;;
        esac
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
# Is the installed irc-core.service a STOCK unit — exactly one that some CryptIRC release
# shipped — that differs from deploy/irc-core.service? Only such a unit is refreshed from
# the repo under --restart-daemon (see "Refresh the irc-core unit" below). ANY local change
# (a custom CRYPTIRC_IPC_SOCK, extra ReadWritePaths, another user, …) makes it custom, and a
# custom unit is never replaced: the old check compared only ExecStart/User/CRYPTIRC_DATA,
# so a refresh silently dropped every other setting.
# _unit_body, _unit_norm_hash, STOCK_IRC_CORE_UNITS, _stock_unit_hashes: deploy/unit-env.sh (shared
# with the installers, which make the same call before replacing an irc-core.service).
IRC_CORE_UNIT_STALE=false
IRC_CORE_UNIT_CUSTOM=false
if [[ "$HAVE_IRC_CORE_UNIT" == "true" && -f "$SCRIPT_DIR/irc-core.service" && -f /etc/systemd/system/irc-core.service ]] \
   && [[ "$(_unit_body /etc/systemd/system/irc-core.service)" != "$(_unit_body "$SCRIPT_DIR/irc-core.service")" ]]; then
    _inst_unit_hash=$(_unit_norm_hash < /etc/systemd/system/irc-core.service)
    _stock_hashes=$(_stock_unit_hashes)
    # (a string match, not `| grep -q`: under pipefail grep's early exit would SIGPIPE the lister)
    if [[ "$_inst_unit_hash" != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
          && $'\n'"$_stock_hashes"$'\n' == *$'\n'"$_inst_unit_hash"$'\n'* ]]; then
        IRC_CORE_UNIT_STALE=true
    else
        IRC_CORE_UNIT_CUSTOM=true
    fi
fi
# Daemon: resolve the restart decision.
if [[ "$HAVE_IRC_CORE_UNIT" == "true" ]]; then
    if [[ "$DAEMON_CHANGED" == "false" && "$RESTART_DAEMON" == "true" && "$IRC_CORE_UNIT_STALE" == "true" ]]; then
        # The daemon CODE is current, but the repo ships a newer irc-core.service (hardening,
        # limits, watchdog). The unit only takes effect on a restart, and the operator asked
        # for one — honour it, or unit fixes could never reach an installed box.
        echo -e "${DIM}irc-core code is unchanged, but deploy/irc-core.service differs from the installed unit — restarting the daemon to apply it (--restart-daemon).${NC}"
    elif [[ "$DAEMON_CHANGED" == "false" ]]; then
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

# ── Health checks, unit edits and rollback (used by the apply window below) ──
# _http_code <port> <path>: HTTP status of GET http://127.0.0.1:<port><path>, 000 on any
# failure. curl when present, else a bare /dev/tcp request (no extra dependency).
# `timeout -k`: children inherit the window's ignored SIGTERM, so a plain timeout could
# never stop a hung probe. --noproxy '*': an http_proxy / all_proxy in root's environment must
# never route this loopback probe through a proxy (it would fail every check and roll back a
# working build). <path> is already in request form (see _url_path); curl sends it
# exactly as given: -g (no [] {} globbing) and, only for a path with a ./ or ../ segment
# (curl would squash those; older curl lacks the option), --path-as-is.
_http_code() {
    local code="" asis=()
    [[ "$2/" == */./* || "$2/" == */../* ]] && asis=(--path-as-is)
    if command -v curl &>/dev/null; then
        code=$(curl -s -g --noproxy '*' ${asis[@]+"${asis[@]}"} -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$1$2" 2>/dev/null)
    else
        # shellcheck disable=SC2016  # $1/$2 are the inner bash's own arguments
        code=$(timeout -k 1 4 bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1" || exit 1
            printf "GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" "$2" >&3
            IFS=" " read -r _ c _ <&3 && printf "%s" "$c"' _ "$1" "$2" 2>/dev/null)
    fi
    [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
    printf '%s' "$code"
}
# _url_path <path>: <path> as a client writes it in a request: the characters RFC 3986 allows
# in a path (letters, digits, - . _ ~ ! $ & ' ( ) * + , ; = : @ / and %) stay as they are —
# the server matches its base path against the raw request path, so /irc+chat must be sent
# as /irc+chat — and every other byte (space, ?, #, non-ASCII, control…) is %-encoded, which
# is what a browser sends for the same URL. Bytewise (LC_ALL=C).
_url_path() {
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
# _web_healthy <secs>: cryptirc is genuinely serving — the unit is active and the SAME
# main PID answers HTTP 200 for its index three probes in a row (~3 s), on the port and
# base path that process really uses. "systemd says active" alone is NOT enough: with
# Type=simple + Restart=on-failure a crash-looping binary reads active between crashes,
# which is how a broken build used to be reported as a successful update.
# A slow-starting big install may override the wait: CRYPTIRC_HEALTH_TIMEOUT=<secs>.
WEB_LAST_CODE=000; WEB_PROBE_DESC=""
HEALTH_TIMEOUT=${CRYPTIRC_HEALTH_TIMEOUT:-60}
[[ "$HEALTH_TIMEOUT" =~ ^[0-9]+$ ]] || HEALTH_TIMEOUT=60
_web_healthy() {
    local deadline=$(( SECONDS + ${1:-$HEALTH_TIMEOUT} )) pid last="" streak=0 n0 n v port path
    n0=$(systemctl show -p NRestarts --value cryptirc 2>/dev/null); [[ "$n0" =~ ^[0-9]+$ ]] || n0=0
    WEB_LAST_CODE=000
    while (( SECONDS < deadline )); do
        n=$(systemctl show -p NRestarts --value cryptirc 2>/dev/null); [[ "$n" =~ ^[0-9]+$ ]] || n=$n0
        if (( n - n0 >= 2 )); then WEB_LAST_CODE="crash-loop (restarted $(( n - n0 ))x)"; return 1; fi
        pid=$(systemctl show -p MainPID --value cryptirc 2>/dev/null)
        if systemctl is-active --quiet cryptirc && [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
            port=9001; path=/cryptirc   # the binary's own defaults when the variables are unset
            if v=$(_svc_env cryptirc "$pid" CRYPTIRC_PORT) && [[ "$v" =~ ^[0-9]{1,5}$ ]] && (( 10#$v >= 1 && 10#$v <= 65535 )); then
                port=$(( 10#$v ))
            fi
            if v=$(_svc_env cryptirc "$pid" CRYPTIRC_BASE_PATH); then
                while [[ "$v" == */ ]]; do v=${v%/}; done   # main.rs trims trailing '/'
                # Any value the server accepts is probed as such (it mounts the literal
                # string). It only ever goes into the probe URL, in request form (_url_path),
                # so nothing in the live value (it is the service's) can reach curl as syntax.
                path=$(_url_path "$v")
                # (A value without the leading '/' makes the server refuse to start, so
                # this only keeps the probe URL well-formed.)
                if [[ -n "$path" && "$path" != /* ]]; then path="/$path"; fi
            fi
            WEB_PROBE_DESC="127.0.0.1:${port}${path}/"
            WEB_LAST_CODE=$(_http_code "$port" "${path}/")
            if [[ "$WEB_LAST_CODE" == "200" ]]; then
                if [[ "$pid" == "$last" ]]; then streak=$(( streak + 1 )); else streak=1; fi
                last=$pid
                (( streak >= 3 )) && return 0
            else
                streak=0; last=""
            fi
        else
            streak=0; last=""; WEB_LAST_CODE="000 (service $(systemctl is-active cryptirc 2>/dev/null))"
        fi
        sleep 1
    done
    return 1
}
# _daemon_healthy <secs>: irc-core has no HTTP endpoint; its functional signal is the
# unit being active AND its IPC socket existing (proof it bound the listener).
_daemon_healthy() {
    local i pid sock data
    for (( i = 0; i < ${1:-15}; i++ )); do
        if systemctl is-active --quiet irc-core; then
            pid=$(systemctl show -p MainPID --value irc-core 2>/dev/null)
            if ! sock=$(_svc_env irc-core "$pid" CRYPTIRC_IPC_SOCK) || [[ -z "$sock" ]]; then
                data=$(_svc_env irc-core "$pid" CRYPTIRC_DATA) || data=""
                [[ -z "$data" ]] && data=$DATA_DIR
                sock="${data%/}/irc-core.sock"
            fi
            [[ -S "$sock" ]] && return 0
        fi
        sleep 1
    done
    return 1
}
# _replace_file <src> <dst> [mode owner]: copy src over dst atomically (temp file in dst's
# directory, then rename) with src's mode/owner, or the given ones. A failed copy (full
# disk) leaves dst intact — a plain `cp src dst` truncates dst first and could leave a
# half-written unit file behind.
_replace_file() {
    local tmp
    tmp=$(mktemp "$(dirname "$2")/.$(basename "$2").XXXXXX") || return 1
    if cp -p "$1" "$tmp" && { [[ -z "${3:-}" ]] || { chmod "$3" "$tmp" && chown "$4" "$tmp"; }; } \
       && mv -f "$tmp" "$2"; then
        return 0
    fi
    rm -f "$tmp"
    return 1
}
# _migrate_unit_lines <web|daemon>: line-exact fixes for shipped defaults that later
# proved harmful, applied to the INSTALLED unit (only the exact stock line is touched,
# so a value an operator customised is left alone). rc 0 = the unit was rewritten.
#   web:    LimitNPROC=512 → TasksMax=512   LimitNPROC=64 → (removed)   (daemon)
# RLIMIT_NPROC counts every thread of the shared `cryptirc` uid, so the web process's
# threads used up irc-core's 64 (DNS hung, restarts failed with EAGAIN); TasksMax is a
# per-unit cgroup cap instead (irc-core keeps its own TasksMax=256).
_migrate_unit_lines() {
    local f tmp
    case "$1" in
        web)    f=/etc/systemd/system/cryptirc.service; [[ -f "$f" && ! -L "$f" ]] && grep -qx 'LimitNPROC=512' "$f" || return 1 ;;
        daemon) f=/etc/systemd/system/irc-core.service; [[ -f "$f" && ! -L "$f" ]] && grep -qx 'LimitNPROC=64'  "$f" || return 1 ;;
        *) return 1 ;;
    esac
    tmp=$(mktemp "$(dirname "$f")/.$(basename "$f").XXXXXX") || return 1
    if [[ "$1" == "web" ]]; then
        if grep -q '^TasksMax=' "$f"; then sed '/^LimitNPROC=512$/d' "$f"; else sed 's/^LimitNPROC=512$/TasksMax=512/' "$f"; fi
    else
        sed '/^LimitNPROC=64$/d' "$f"
    fi > "$tmp" && chown --reference="$f" "$tmp" && chmod --reference="$f" "$tmp" && mv -f "$tmp" "$f" && return 0
    rm -f "$tmp"
    return 1
}
# _lift_live_nproc <unit>: a rewritten unit only applies on the next restart, but the
# RUNNING process keeps the old per-user RLIMIT_NPROC — hand it the unit's new value
# now (prlimit, util-linux), so the fix lands without dropping anyone's IRC session.
_lift_live_nproc() {
    local pid soft hard
    command -v prlimit &>/dev/null || return 1
    pid=$(systemctl show -p MainPID --value "$1" 2>/dev/null); [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    hard=$(systemctl show -p LimitNPROC --value "$1" 2>/dev/null)
    soft=$(systemctl show -p LimitNPROCSoft --value "$1" 2>/dev/null)
    [[ "$hard" == "infinity" ]] && hard=unlimited
    [[ "$soft" == "infinity" ]] && soft=unlimited
    [[ "$hard" =~ ^([0-9]+|unlimited)$ && "$soft" =~ ^([0-9]+|unlimited)$ ]] || return 1
    prlimit --pid "$pid" --nproc="${soft}:${hard}" 2>/dev/null
}

# ── The registration code out of the web unit (installs made before 0.5.8) ───
# Installers before 0.5.8 wrote the fallback registration code into cryptirc.service as an
# Environment= line, and every local user can read those (`systemctl show cryptirc`),
# whatever the unit file's permissions. The installers now keep it in the root-only
# EnvironmentFile /etc/cryptirc/cryptirc.env; an update moves an existing install over the
# same way (same file format, so a later installer run sees nothing to change). Only the
# stock line is moved — exactly one `Environment="CRYPTIRC_REG_CODE=…"` assignment per line
# in the unit file itself; a line that also sets other things, or a drop-in that sets the
# code, is the operator's own and is only pointed out.
WEB_UNIT=/etc/systemd/system/cryptirc.service
REG_ENV_DIR=/etc/cryptirc
REG_ENV_FILE=$REG_ENV_DIR/cryptirc.env
REG_LINE_RE='^[[:space:]]*Environment=("CRYPTIRC_REG_CODE=([^"\\]|\\.)*"|CRYPTIRC_REG_CODE=[^[:space:]"]*)[[:space:]]*$'
REGMIG=false; REGMIG_ENV_NEW=""; REGMIG_UNIT_NEW=""; REGMIG_ENV_EXISTED=false; REGMIG_ENV_APPLIED=false
_regcode_in_unit() {
    [[ -f "$WEB_UNIT" && ! -L "$WEB_UNIT" ]] && grep -qE '^[[:space:]]*Environment=.*CRYPTIRC_REG_CODE=' "$WEB_UNIT" 2>/dev/null
}
# _regmig_prepare: decide, and stage the new env file and unit next to their targets (nothing
# is replaced yet). Sets REGMIG=true when the move is staged; otherwise says why not.
_regmig_prepare() {
    local val rc=0 l d esc line t k own=() owner mode
    _regcode_in_unit || return 0
    while IFS= read -r l; do
        [[ "$l" =~ $REG_LINE_RE ]] || {
            echo -e "  ${YELLOW}⚠ $WEB_UNIT sets CRYPTIRC_REG_CODE on a line that also sets other things — not moved. Every local user can read it (systemctl show cryptirc): move it to $REG_ENV_FILE yourself.${NC}"
            return 0; }
    done < <(grep -E '^[[:space:]]*Environment=.*CRYPTIRC_REG_CODE=' "$WEB_UNIT")
    for d in $(systemctl show cryptirc -p DropInPaths --value 2>/dev/null); do
        if [[ -f "$d" ]] && grep -qE '^[[:space:]]*Environment=.*CRYPTIRC_REG_CODE=' "$d" 2>/dev/null; then
            echo -e "  ${YELLOW}⚠ The drop-in $d sets CRYPTIRC_REG_CODE too — not moved. Every local user can read it (systemctl show cryptirc): move it to $REG_ENV_FILE yourself.${NC}"
            return 0
        fi
    done
    # The value the service gets now (systemd's precedence: an EnvironmentFile beats Environment=).
    val=$(_unit_env cryptirc CRYPTIRC_REG_CODE) || rc=$?
    if (( rc == 3 || rc == 5 )); then
        echo -e "  ${YELLOW}⚠ CRYPTIRC_REG_CODE is in $WEB_UNIT and in an EnvironmentFile that can't be trusted — not moved.${NC}"
        return 0
    fi
    if [[ "$val" == *[[:cntrl:]]* ]]; then
        echo -e "  ${YELLOW}⚠ The registration code in $WEB_UNIT contains a control character — not moved; move it to $REG_ENV_FILE yourself.${NC}"
        return 0
    fi
    if [[ -e "$REG_ENV_DIR" || -L "$REG_ENV_DIR" ]]; then
        if [[ -L "$REG_ENV_DIR" || ! -d "$REG_ENV_DIR" ]] || ! _dir_chain_protected "$REG_ENV_DIR"; then
            echo -e "  ${YELLOW}⚠ $REG_ENV_DIR is not a root-only directory — the registration code was not moved out of $WEB_UNIT.${NC}"
            return 0
        fi
    else
        install -d -m 700 -o root -g root "$REG_ENV_DIR" || return 0
    fi
    if [[ -e "$REG_ENV_FILE" || -L "$REG_ENV_FILE" ]]; then
        if [[ -L "$REG_ENV_FILE" || ! -f "$REG_ENV_FILE" ]] || ! _envfile_trusted "$REG_ENV_FILE"; then
            echo -e "  ${YELLOW}⚠ $REG_ENV_FILE exists but is not a root-owned regular file — the registration code was not moved out of $WEB_UNIT.${NC}"
            return 0
        fi
        REGMIG_ENV_EXISTED=true
        # Keep everything else in it (the operator's own settings), as the installers do.
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%$'\r'}"; t="${line#"${line%%[![:space:]]*}"}"
            case "$line" in
                "# CryptIRC — written by the installer. Root-only (0600): systemd reads it, local users"|\
                "# can't (unlike Environment= lines, which \`systemctl show\` reveals to everyone)."|\
                "# Fallback only — admin_settings.json (Settings -> Admin) is authoritative.") continue ;;
            esac
            [[ "$t" == "# Your own settings below are kept as they are when the installer runs again:" ]] && continue
            if [[ "$t" == *=* ]]; then k="${t%%=*}"; k="${k%"${k##*[![:space:]]}"}"; [[ "$k" == CRYPTIRC_REG_CODE ]] && continue; fi
            own+=("$line")
        done < "$REG_ENV_FILE"
        while (( ${#own[@]} )) && [[ -z "${own[0]//[[:space:]]/}" ]]; do own=("${own[@]:1}"); done
        while (( ${#own[@]} )) && [[ -z "${own[-1]//[[:space:]]/}" ]]; do unset 'own[-1]'; done
    fi
    esc=${val//\\/\\\\}; esc=${esc//\"/\\\"}; esc=${esc//\`/\\\`}; esc=${esc//\$/\\\$}
    REGMIG_ENV_NEW=$(mktemp "$REG_ENV_DIR/.cryptirc.env.XXXXXX") || return 0
    if ! {
        printf '%s\n' "# CryptIRC — written by the installer. Root-only (0600): systemd reads it, local users" \
            "# can't (unlike Environment= lines, which \`systemctl show\` reveals to everyone)." \
            "# Fallback only — admin_settings.json (Settings -> Admin) is authoritative."
        printf 'CRYPTIRC_REG_CODE="%s"\n' "$esc"
        if (( ${#own[@]} )); then
            printf '\n%s\n' "# Your own settings below are kept as they are when the installer runs again:"
            printf '%s\n' "${own[@]}"
        fi
    } > "$REGMIG_ENV_NEW" || ! chmod 600 "$REGMIG_ENV_NEW" || ! chown root:root "$REGMIG_ENV_NEW"; then
        rm -f "$REGMIG_ENV_NEW"; REGMIG_ENV_NEW=""; return 0
    fi
    # The unit without those lines; the first one becomes the EnvironmentFile= line (unless
    # the unit already loads that file).
    owner=$(stat -c '%u:%g' "$WEB_UNIT"); mode=$(stat -c '%a' "$WEB_UNIT")
    REGMIG_UNIT_NEW=$(mktemp "$(dirname "$WEB_UNIT")/.cryptirc.service.XXXXXX") || { rm -f "$REGMIG_ENV_NEW"; return 0; }
    local have_ef=0
    grep -qE '^[[:space:]]*EnvironmentFile=-?/etc/cryptirc/cryptirc\.env[[:space:]]*$' "$WEB_UNIT" && have_ef=1
    if ! RE="$REG_LINE_RE" awk -v have="$have_ef" -v ef="EnvironmentFile=-$REG_ENV_FILE" '
        $0 ~ ENVIRON["RE"] { if (!have) { print "# The fallback registration code lives in this root-only file (not in an Environment="
                              print "# line: `systemctl show` would show it to every local user)."
                              print ef; have = 1 }
                  next }
        { print }' "$WEB_UNIT" > "$REGMIG_UNIT_NEW" \
       || ! chown "$owner" "$REGMIG_UNIT_NEW" || ! chmod "$mode" "$REGMIG_UNIT_NEW"; then
        rm -f "$REGMIG_ENV_NEW" "$REGMIG_UNIT_NEW"; REGMIG_ENV_NEW=""; REGMIG_UNIT_NEW=""; return 0
    fi
    REGMIG=true
}
# _regmig_apply: put the staged env file and unit in place (inside the apply window; the
# unit's original is in RB_DIR/units, the env file's in RB_DIR/cryptirc.env).
_regmig_apply() {
    local ts
    [[ "$REGMIG" == "true" ]] || return 1
    ts=$(date +%Y%m%d-%H%M%S)
    mkdir -p "$REG_ENV_DIR/backups" && chmod 700 "$REG_ENV_DIR/backups"
    cp -p "$WEB_UNIT" "$REG_ENV_DIR/backups/cryptirc.service.$ts" 2>/dev/null
    if [[ "$REGMIG_ENV_EXISTED" == "true" ]]; then
        cp -p "$REG_ENV_FILE" "$REG_ENV_DIR/backups/cryptirc.env.$ts" 2>/dev/null
        cp -p "$REG_ENV_FILE" "$RB_DIR/cryptirc.env" || return 1
    fi
    mv -f "$REGMIG_ENV_NEW" "$REG_ENV_FILE" || return 1
    REGMIG_ENV_APPLIED=true; REGMIG_ENV_NEW=""
    mv -f "$REGMIG_UNIT_NEW" "$WEB_UNIT" || return 1
    REGMIG_UNIT_NEW=""
    return 0
}
# _regmig_undo: (rollback) the env file as it was before this run.
_regmig_undo() {
    [[ "$REGMIG_ENV_APPLIED" == "true" ]] || return 0
    if [[ "$REGMIG_ENV_EXISTED" == "true" ]]; then
        _replace_file "$RB_DIR/cryptirc.env" "$REG_ENV_FILE" 600 root:root
    else
        rm -f "$REG_ENV_FILE"
    fi
    REGMIG_ENV_APPLIED=false
}

# ── Keep one-time secrets out of Caddy's access log (installs made before 0.5.8) ─
# Since 0.5.8 the installers' Caddy site gives CryptIRC's access log a filter that redacts
# the reset / verification token and paste password in the query string and drops the
# Referer. An older site (the 0.5.7 installers' main Caddyfile, an older INSTALL.md copy)
# keeps logging live reset links. Every `log { … }` block that writes
# /var/log/caddy/cryptirc.log and has no `format` of its own gets that filter; a block with
# its own format is only pointed out. Each changed file is backed up first, the result must
# `caddy validate`, and Caddy reloads (or restarts, for a config with `admin off`); any
# failure puts the old files back. Never touches irc-core.
_caddy_redact_awk() {
    awk '
function strip(l) { sub(/#.*/, "", l); return l }
{ L[NR] = $0 }
END {
    depth = 0; inlog = 0
    for (i = 1; i <= NR; i++) {
        l = strip(L[i]); t = l
        gsub(/^[ \t]+|[ \t\r]+$/, "", t)
        o = gsub(/\{/, "{", l); c = gsub(/\}/, "}", l)
        nd = depth + o - c
        if (!inlog && t ~ /^log[ \t]*\{$/) {
            inlog = 1; ld = depth; ours = 0; fmt = 0; red = 0
            match(L[i], /^[ \t]*/); ind = substr(L[i], 1, RLENGTH) "    "
            print L[i]; depth = nd; continue
        }
        if (inlog && depth == ld + 1) {
            if (t ~ /^output[ \t]+file[ \t]+\/var\/log\/caddy\/cryptirc\.log([ \t{]|$)/) {
                ours = 1; match(L[i], /^[ \t]*/); ind = substr(L[i], 1, RLENGTH)
            }
            if (t ~ /^format([ \t{]|$)/) fmt = 1
        }
        if (inlog && t ~ /replace[ \t]+token[ \t]+REDACTED/) red = 1
        if (inlog && nd <= ld) {
            if (ours && !fmt) {
                s = ind
                print s "# Keep one-time secrets out of the access log: email-verify / password-reset"
                print s "# tokens and paste passwords travel in the query string (and the Referer of a"
                print s "# page opened from such a link would repeat them)."
                print s "format filter {"
                print s "    request>uri query {"
                print s "        replace token REDACTED"
                print s "        replace password REDACTED"
                print s "    }"
                print s "    request>headers>Referer delete"
                print s "}"
                changed++
            } else if (ours && fmt && !red) {
                print "CUSTOM " i > "/dev/stderr"
            }
            inlog = 0
        }
        print L[i]; depth = nd
    }
}
'
}
_caddy_log_redaction() {
    local f files=() changed=() baks=() tmp ts log_existed=false custom out
    command -v caddy &>/dev/null && [[ -d /etc/caddy ]] || return 0
    for f in /etc/caddy/Caddyfile /etc/caddy/conf.d/*.caddy; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        [[ "$(stat -c %u "$f" 2>/dev/null)" == 0 ]] || continue
        grep -qE 'output[[:space:]]+file[[:space:]]+/var/log/caddy/cryptirc\.log' "$f" 2>/dev/null && files+=("$f")
    done
    (( ${#files[@]} )) || return 0
    ts=$(date +%Y%m%d-%H%M%S)
    [[ -e /var/log/caddy/cryptirc.log ]] && log_existed=true
    for f in "${files[@]}"; do
        tmp=$(mktemp "$(dirname "$f")/.$(basename "$f").XXXXXX") || continue
        custom=$(_caddy_redact_awk < "$f" 2>&1 >"$tmp")
        [[ -n "$custom" ]] && echo -e "  ${YELLOW}⚠ $f: CryptIRC's access log there sets its own format, so reset links may still be logged — add the token filter from INSTALL.md to it.${NC}"
        if [[ -s "$tmp" ]] && ! cmp -s "$tmp" "$f"; then
            chown --reference="$f" "$tmp" && chmod --reference="$f" "$tmp" \
                && cp -p "$f" "/etc/caddy/$(basename "$f").bak.$ts" && baks+=("/etc/caddy/$(basename "$f").bak.$ts") \
                && mv -f "$tmp" "$f" && changed+=("$f") && continue
            echo -e "  ${YELLOW}⚠ Could not update $f — its access log still records reset links.${NC}"
        fi
        rm -f "$tmp"
    done
    (( ${#changed[@]} )) || return 0
    _caddy_put_back() {
        local i
        for (( i = 0; i < ${#changed[@]}; i++ )); do cp -p "${baks[$i]}" "${changed[$i]}"; done
    }
    if ! out=$(caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1); then
        _caddy_put_back
        echo -e "  ${YELLOW}⚠ Caddy's access log still records reset links: the redaction filter did not validate with this Caddy, so your files were put back.${NC}"
        printf '%s\n' "$out" | grep -v '"level":"info"' | tail -n 3 | sed 's/^/      /'
        return 0
    fi
    # `caddy validate` (run as root) creates a missing log file as root:root; Caddy itself runs
    # as `caddy` and could not open it. The empty file it made is removed again, and Caddy
    # creates its own when it loads the config below. (Never chown it: /var/log/caddy belongs
    # to caddy, so by now the name may be a hard link caddy planted to some other root-owned
    # file. unlink only ever removes the name.)
    if [[ "$log_existed" == "false" && -f /var/log/caddy/cryptirc.log && ! -L /var/log/caddy/cryptirc.log \
          && ! -s /var/log/caddy/cryptirc.log && "$(stat -c %u /var/log/caddy/cryptirc.log 2>/dev/null)" == 0 ]]; then
        rm -f /var/log/caddy/cryptirc.log
    fi
    if systemctl is-active --quiet caddy; then
        if ! systemctl reload caddy >/dev/null 2>&1; then
            # A config with `admin off` (0.5.7 installers, INSTALL.md) can't reload: restart
            # (open connections drop once; every client reconnects by itself).
            systemctl restart caddy >/dev/null 2>&1
        fi
        sleep 1
        if ! systemctl is-active --quiet caddy; then
            _caddy_put_back
            systemctl reset-failed caddy >/dev/null 2>&1; systemctl restart caddy >/dev/null 2>&1
            echo -e "  ${RED}✗ Caddy did not come back with the redaction filter — your previous Caddy files were put back ($(systemctl is-active caddy 2>/dev/null)).${NC}"
            echo -e "  ${DIM}Check: journalctl -u caddy -n 30 --no-pager${NC}"
            return 0
        fi
    fi
    echo -e "  ${GREEN}✓ Caddy access log: reset / verification tokens and paste passwords are now redacted${NC} ${DIM}(${changed[*]}; previous: ${baks[*]})${NC}"
}

# ── The data floor (DATA_FLOOR, _ver_ge, _floor_crossed, _user_data_snapshot, _user_data_changed):
# deploy/data-floor.sh, sourced at the top — shared with the installers.
# _persist_deploy_markers: the files the NEXT run's change detection reads, for the binaries
# now installed. .version → the "from" version (and the data-floor check) next time.
# .irc-core-srchash → the daemon SOURCE hash the RUNNING daemon was built from; written ONLY
# when the daemon was (re)started from this build, so a DEFERRED daemon change still reads
# as "changed".
_persist_deploy_markers() {
    echo "$NEW_VER" > "$INSTALL_DIR/.version" 2>/dev/null
    if { [[ "$RESTART_DAEMON" == "true" ]] || [[ "$MIGRATED_TO_DAEMON" == "true" ]] || [[ "$DAEMON_RECOVERED" == "true" ]]; } \
       && [[ "$HAVE_IRC_CORE" == "true" ]] && systemctl is-active --quiet irc-core 2>/dev/null; then
        echo "$DAEMON_SRC_HASH" > "$INSTALL_DIR/.irc-core-srchash" 2>/dev/null
    fi
    return 0
}
# _withhold_rollback <changed dirs>: the failed update stays installed (see DATA_FLOOR). The
# new web is started again (_rollback stopped it for the check), the installed version is
# recorded, nothing else is touched, and the operator is told what to do.
_withhold_rollback() {
    local what="" d prev
    ROLLBACK_WITHHELD=true
    for d in $1; do
        case "$d" in
            e2e)      what+="${what:+, }end-to-end keys (${DATA_DIR}/e2e/<user>/)" ;;
            networks) what+="${what:+, }saved networks (${DATA_DIR}/networks/)" ;;
            vaults)   what+="${what:+, }vaults (${DATA_DIR}/vaults/)" ;;
        esac
    done
    if [[ "$OLD_VER" == "unknown" ]]; then prev="the previous version"; else prev="v${OLD_VER}"; fi
    if [[ "$WEB_TOUCHED" == "true" ]]; then
        systemctl reset-failed cryptirc 2>/dev/null
        systemctl start cryptirc 2>/dev/null
        systemctl is-active --quiet cryptirc && CRYPTIRC_STOPPED_BY_US=false
    fi
    _persist_deploy_markers
    _note "  ${YELLOW}${BOLD}⚠ NOT rolled back automatically: v${NEW_VER} has already changed users' data.${NC}"
    _note "    Changed since it started: ${what} — someone used it (e.g. unlocked"
    _note "    their vault, which moves their end-to-end keys to a format ${prev} can't read)."
    _note "    Putting ${prev} back now would make it replace those keys with new ones: those users'"
    _note "    encrypted conversations and verified identities would be lost for good (updating again"
    _note "    doesn't bring them back), and saved channel keys / perform commands would go to IRC encrypted."
    _note "  ${YELLOW}v${NEW_VER} stays installed and was started again, but it FAILED the health check — the site may not work.${NC}"
    _note "  ${BOLD}What to do:${NC}"
    _note "    1. See why:  journalctl -u cryptirc -n 50 --no-pager   ·   systemctl status cryptirc"
    _note "    2. Stay on v${NEW_VER} or later: fix the cause and run  sudo systemctl restart cryptirc,"
    _note "       or update to a fixed version:  sudo bash deploy/update.sh"
    _note "    3. Going back anyway: read \"Going back by hand\" in deploy/README.md first. The previous"
    _note "       binaries and units are in ${RB_DIR}."
    d="${BACKUP_FILE:-${CRYPTIRC_UPDATE_BACKUP:-}}"
    [[ -n "$d" ]] && _note "  ${DIM}(The data backup made before this update: ${d})${NC}"
    return 0
}

# _rollback <why>: put back every file this run replaced, restart what it stopped, and
# verify. Sets ROLLBACK_OK. Safe to call from any point of the window (and from the
# EXIT trap); it only undoes what the state flags say was actually done.
# Except across the data floor: once the NEW web has run and users' data changed since it
# started, nothing is put back (ROLLBACK_WITHHELD; see DATA_FLOOR) and the operator is told
# what to do instead.
ROLLBACK_OK=false
_rollback() {
    local ok=true u datachg
    IN_WINDOW=false   # one-shot: the EXIT trap must not run it a second time
    set +eu
    trap '' INT HUP TERM QUIT PIPE TSTP TTIN TTOU
    _note ""
    _note "  ${RED}✗ $1${NC}"
    # 0. The data floor. Decided with the new web STOPPED, so nothing it writes can land after
    #    the check: started again below if the rollback is withheld (it is what users' data
    #    now needs), stopped anyway by step 1 otherwise.
    if [[ "$SWAPPED_WEB" == "true" && -n "$USER_DATA_SNAP0" ]] && _floor_crossed "$OLD_VER" "$NEW_VER"; then
        if [[ "$WEB_TOUCHED" == "true" ]]; then
            CRYPTIRC_STOPPED_BY_US=true
            systemctl stop cryptirc 2>/dev/null; systemctl reset-failed cryptirc 2>/dev/null
        fi
        datachg=$(_user_data_changed "$USER_DATA_SNAP0" "$DATA_DIR")
        if [[ -n "$datachg" ]]; then
            _withhold_rollback "$datachg"
            return
        fi
        _note "  ${DIM}(no user's data changed while v${NEW_VER} ran — safe to put the previous version back)${NC}"
    fi
    _note "  ${YELLOW}↺ Rolling back to the previous version...${NC}"
    # 1. Stop what this run touched; clear a crash loop's start-limit latch.
    if [[ "$WEB_TOUCHED" == "true" ]]; then
        CRYPTIRC_STOPPED_BY_US=true
        systemctl stop cryptirc 2>/dev/null; systemctl reset-failed cryptirc 2>/dev/null
    fi
    if [[ "$DAEMON_TOUCHED" == "true" ]]; then
        IRC_CORE_STOPPED_BY_US=true
        systemctl stop irc-core 2>/dev/null; systemctl reset-failed irc-core 2>/dev/null
    fi
    # 2. Previous files back in place (rename within $INSTALL_DIR: needs no free space).
    if [[ "$SWAPPED_WEB" == "true" ]]; then
        if [[ -f "$RB_DIR/cryptirc" ]] && mv -f "$RB_DIR/cryptirc" "$INSTALL_DIR/cryptirc"; then
            SWAPPED_WEB=false; _note "  ${GREEN}✓ previous cryptirc binary restored${NC}"
        else
            ok=false; _note "  ${RED}✗ could not restore the previous cryptirc binary from $RB_DIR${NC}"
        fi
    fi
    if [[ "$SWAPPED_DAEMON" == "true" ]]; then
        if [[ -f "$RB_DIR/irc_core" ]] && mv -f "$RB_DIR/irc_core" "$INSTALL_DIR/irc_core"; then
            rm -f "$INSTALL_DIR/.irc_core.ondisk-srchash"    # (no longer describes the file there)
            SWAPPED_DAEMON=false; _note "  ${GREEN}✓ previous irc_core binary restored${NC}"
        else
            ok=false; _note "  ${RED}✗ could not restore the previous irc_core binary from $RB_DIR${NC}"
        fi
    fi
    for u in "${UNITS_CHANGED[@]}"; do
        if [[ -f "$RB_DIR/units/$u" ]] && _replace_file "$RB_DIR/units/$u" "/etc/systemd/system/$u"; then
            _note "  ${GREEN}✓ previous $u restored${NC}"
        else
            ok=false; _note "  ${RED}✗ could not restore /etc/systemd/system/$u from $RB_DIR/units${NC}"
        fi
    done
    UNITS_CHANGED=()
    _regmig_undo
    if [[ "$IRC_CORE_UNIT_CREATED" == "true" ]]; then
        # Pre-split box: the previous web binary dials IRC itself and needs no daemon.
        systemctl disable irc-core >/dev/null 2>&1
        rm -f /etc/systemd/system/irc-core.service
        IRC_CORE_UNIT_CREATED=false; HAVE_IRC_CORE_UNIT=false
        DAEMON_TOUCHED=false; IRC_CORE_STOPPED_BY_US=false
        _note "  ${GREEN}✓ removed the irc-core.service this run created${NC}"
    fi
    systemctl daemon-reload 2>/dev/null || ok=false
    # 3. Bring back what was running, and check it really serves.
    if [[ "$DAEMON_TOUCHED" == "true" ]]; then
        if systemctl start irc-core 2>/dev/null && _daemon_healthy 15; then
            IRC_CORE_STOPPED_BY_US=false; _note "  ${GREEN}✓ irc-core is running the previous version${NC}"
        else
            ok=false; _note "  ${RED}✗ irc-core did not come back — journalctl -u irc-core -n 50${NC}"
        fi
    fi
    if [[ "$WEB_TOUCHED" == "true" ]]; then
        if systemctl start cryptirc 2>/dev/null && _web_healthy "$HEALTH_TIMEOUT"; then
            CRYPTIRC_STOPPED_BY_US=false; _note "  ${GREEN}✓ cryptirc is serving again (HTTP 200 on ${WEB_PROBE_DESC})${NC}"
        else
            ok=false; _note "  ${RED}✗ cryptirc did not come back (last probe: ${WEB_LAST_CODE}) — journalctl -u cryptirc -n 50${NC}"
        fi
    fi
    _note ""
    if [[ "$ok" == "true" ]]; then
        ROLLBACK_OK=true
        if [[ "$OLD_VER" == "unknown" ]]; then _prev="the previous version"; else _prev="the previous version (v${OLD_VER})"; fi
        _note "  ${YELLOW}${BOLD}Rolled back: ${_prev} is running again. This update was NOT applied.${NC}"
        _note "  ${DIM}See why the new build failed: journalctl -u cryptirc -n 50   (and: journalctl -u irc-core -n 50)${NC}"
        _note "  ${DIM}Do NOT restore a data backup for this — your data is intact. (If the new build got as far as a${NC}"
        _note "  ${DIM}one-time data migration, e.g. 0.5.8's upload-index move, the previous version may show some lists,${NC}"
        _note "  ${DIM}such as your uploaded files, as empty until the next successful update. Nothing is lost.)${NC}"
    else
        ROLLBACK_OK=false
        _note "  ${RED}${BOLD}✗ The rollback could not bring everything back up — the site may be DOWN.${NC}"
        _note "  ${DIM}Check: systemctl status cryptirc irc-core · journalctl -u cryptirc -n 50 · ls -la $INSTALL_DIR $RB_DIR${NC}"
        _note "  ${DIM}Then: sudo systemctl reset-failed cryptirc && sudo systemctl start cryptirc${NC}"
    fi
}
# _fail <why>: roll back and exit non-zero (1 = rolled back cleanly, 3 = rollback failed,
# 4 = rollback withheld across the data floor).
_fail() {
    _rollback "$1"
    [[ "$ROLLBACK_WITHHELD" == "true" ]] && exit 4
    [[ "$ROLLBACK_OK" == "true" ]] && exit 1
    exit 3
}

# ── Stage everything BEFORE stopping anything ────────────────────────────────
# Copies of what is about to be replaced go to RB_DIR; the new binaries to *.new next to
# their targets. A failure here (full disk, read-only mount) aborts with the running
# site untouched — the swap later is only rename(2), which needs no free space. (The old
# code copied INTO the stopped window, so a full disk left the web up but irc-core down.)
_progress "Applying update"
SWAP_WEB=false
[[ "$WEB_CHANGED" == "true" ]] && SWAP_WEB=true
SWAP_DAEMON=false
if [[ "$HAVE_IRC_CORE" == "true" ]] && ! { [[ -f "$INSTALL_DIR/irc_core" ]] && cmp -s "$BIN_DIR/irc_core" "$INSTALL_DIR/irc_core"; }; then
    SWAP_DAEMON=true
elif [[ "$HAVE_IRC_CORE" == "true" ]]; then
    _record_ondisk_srchash      # the file on disk is byte-identical to this build
fi
_stage_fail() {
    rm -f "$INSTALL_DIR/cryptirc.new" "$INSTALL_DIR/irc_core.new" 2>/dev/null || true
    rm -rf "$RB_DIR.new" 2>/dev/null || true
    echo -e "  ${RED}✗ $1 — aborting; nothing was changed (the running services were not touched).${NC}"
    echo -e "  ${DIM}Check free space: df -h $INSTALL_DIR${NC}"
    exit 1
}
_units_may_change=false
{ [[ "$RESTART_DAEMON" == "true" ]] || [[ "$HAVE_IRC_CORE" == "true" && "$HAVE_IRC_CORE_UNIT" == "false" ]] \
  || grep -qsx 'LimitNPROC=512' /etc/systemd/system/cryptirc.service \
  || grep -qsx 'LimitNPROC=64' /etc/systemd/system/irc-core.service || _regcode_in_unit; } && _units_may_change=true
if [[ "$SWAP_WEB" == "true" || "$SWAP_DAEMON" == "true" || "$_units_may_change" == "true" ]]; then
    # RB_DIR holds what the most recent update replaced (root-only: the web unit embeds the
    # registration code). Built fresh each time, swapped in only once complete.
    { rm -rf "$RB_DIR.new" && mkdir -m 700 "$RB_DIR.new" "$RB_DIR.new/units"; } \
        || _stage_fail "Could not create $RB_DIR.new"
    if [[ "$SWAP_WEB" == "true" && -f "$INSTALL_DIR/cryptirc" ]]; then
        cp -p "$INSTALL_DIR/cryptirc" "$RB_DIR.new/cryptirc" || _stage_fail "Could not keep a rollback copy of the current cryptirc binary"
    fi
    if [[ "$SWAP_DAEMON" == "true" && -f "$INSTALL_DIR/irc_core" ]]; then
        cp -p "$INSTALL_DIR/irc_core" "$RB_DIR.new/irc_core" || _stage_fail "Could not keep a rollback copy of the current irc_core binary"
    fi
    for _u in cryptirc.service irc-core.service; do
        if [[ -f "/etc/systemd/system/$_u" ]]; then
            cp -p "/etc/systemd/system/$_u" "$RB_DIR.new/units/$_u" || _stage_fail "Could not back up /etc/systemd/system/$_u"
        fi
    done
    echo "$OLD_VER" > "$RB_DIR.new/version" || _stage_fail "Could not write $RB_DIR.new/version"
    { rm -rf "$RB_DIR" && mv "$RB_DIR.new" "$RB_DIR"; } || _stage_fail "Could not move $RB_DIR.new into place"
fi
_regmig_prepare      # (stages the move of the registration code out of the unit; replaces nothing yet)
if [[ "$SWAP_WEB" == "true" ]]; then
    rm -f "$INSTALL_DIR/cryptirc.new"
    { cp "$BIN_DIR/cryptirc" "$INSTALL_DIR/cryptirc.new" && chmod 755 "$INSTALL_DIR/cryptirc.new" \
      && chown root:root "$INSTALL_DIR/cryptirc.new"; } || _stage_fail "Could not stage the new cryptirc binary"
fi
if [[ "$SWAP_DAEMON" == "true" ]]; then
    rm -f "$INSTALL_DIR/irc_core.new"
    { cp "$BIN_DIR/irc_core" "$INSTALL_DIR/irc_core.new" && chmod 755 "$INSTALL_DIR/irc_core.new" \
      && chown root:root "$INSTALL_DIR/irc_core.new"; } || _stage_fail "Could not stage the new irc_core binary"
fi

# ── The apply window ─────────────────────────────────────────────────────────
# From the first stop until the services are verified healthy (or rolled back) nothing may
# cut the script short. Ctrl-C, Ctrl-Z, a terminal hangup (SSH drop), SIGTERM and SIGPIPE
# are IGNORED — and that is inherited by systemctl/sleep/etc., so no child dies mid-step either
# — and errexit is OFF: every step is checked explicitly and a failure rolls back. A dead
# terminal then only costs output (EIO is ignored); milestones also go to the journal
# (journalctl -t cryptirc-update). The window stays this way to the end of the script.
trap '' INT HUP TERM QUIT PIPE TSTP TTIN TTOU
set +eu
IN_WINDOW=true
if [[ "$WEB_RESTART" == "true" || "$RESTART_DAEMON" == "true" ]]; then
    echo -e "  ${DIM}(applying — Ctrl-C or a dropped SSH session now waits until the services are back up)${NC}"
fi

# ── Stop service(s) ──────────────────────────────────────────────────────────
if [[ "$WEB_RESTART" == "true" ]]; then
    if systemctl is-active --quiet cryptirc; then
        WEB_TOUCHED=true; CRYPTIRC_STOPPED_BY_US=true
        systemctl stop cryptirc || _fail "systemctl stop cryptirc failed"
        echo -e "  ${GREEN}✓ CryptIRC stopped${NC}"
    else
        echo -e "  ${YELLOW}⚠ CryptIRC was not running${NC}"
    fi
else
    echo -e "  ${DIM}cryptirc web binary unchanged — left running (no web restart needed)${NC}"
fi
if [[ "$RESTART_DAEMON" == "true" && "$HAVE_IRC_CORE_UNIT" == "true" ]]; then
    if systemctl is-active --quiet irc-core; then
        DAEMON_TOUCHED=true; IRC_CORE_STOPPED_BY_US=true
        systemctl stop irc-core || _fail "systemctl stop irc-core failed"
        echo -e "  ${GREEN}✓ irc-core stopped${NC} ${DIM}(--restart-daemon passed — every connected user's IRC session will drop and reconnect)${NC}"
    else
        echo -e "  ${YELLOW}⚠ irc-core was not running${NC}"
    fi
elif [[ "$HAVE_IRC_CORE_UNIT" == "true" ]]; then
    echo -e "  ${DIM}irc-core left running (pass --restart-daemon to also update/restart it) — no IRC connections will drop${NC}"
fi
echo ""

# ── Swap binary(ies) ─────────────────────────────────────────────────────────
# rename(2) of the staged *.new, not a plain cp: irc-core is deliberately LEFT RUNNING
# when --restart-daemon isn't passed — its executable is still mapped by the live process,
# and a plain cp over it fails with "Text file busy" (hit for real on the first production
# use of this script). `mv` just repoints the directory entry to a new inode, which the
# kernel allows even while the old inode is still executing.
if [[ "$SWAP_WEB" == "true" ]]; then
    echo -e "${BOLD}Installing new binary...${NC}"
    mv -f "$INSTALL_DIR/cryptirc.new" "$INSTALL_DIR/cryptirc" || _fail "Could not install the new cryptirc binary"
    SWAPPED_WEB=true
    echo -e "  ${GREEN}✓ Binary updated${NC} ${DIM}(previous one kept in $RB_DIR)${NC}"
fi
if [[ "$SWAP_DAEMON" == "true" ]]; then
    # Refreshed on disk every run regardless of --restart-daemon, so the new
    # code is already in place the next time the daemon itself restarts.
    mv -f "$INSTALL_DIR/irc_core.new" "$INSTALL_DIR/irc_core" || _fail "Could not install the new irc_core binary"
    SWAPPED_DAEMON=true
    _record_ondisk_srchash
    echo -e "  ${GREEN}✓ irc_core binary updated on disk${NC}"
fi
[[ "$SWAP_WEB" == "true" || "$SWAP_DAEMON" == "true" ]] && echo ""

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
    if [[ "$IRC_CORE_UNIT_STALE" == "true" ]]; then
        _replace_file "$REPO_UNIT" "$INST_UNIT" 644 root:root || _fail "Could not refresh $INST_UNIT"
        UNITS_CHANGED+=(irc-core.service)
        echo -e "  ${GREEN}✓ irc-core.service refreshed from repo${NC} ${DIM}(watchdog/hardening applied on the restart below; previous unit kept in $RB_DIR/units)${NC}"
    elif [[ "$IRC_CORE_UNIT_CUSTOM" == "true" ]]; then
        echo -e "  ${YELLOW}⚠ Installed irc-core.service has local changes (it is not a unit any release shipped) — NOT auto-refreshed.${NC}"
        echo -e "  ${YELLOW}  The daemon restarts with the NEW binary but your OLD unit — if that unit is${NC}"
        echo -e "  ${YELLOW}  Type=simple / lacks WatchdogSec, the never-die watchdog will NOT be active.${NC}"
        echo -e "  ${DIM}Reconcile it against deploy/irc-core.service (Type=notify + WatchdogSec + StartLimitIntervalSec=0) for full protection.${NC}"
    fi
fi

# ── Known-bad stock unit lines (applies to every installed box) ──────────────
# See _migrate_unit_lines. Both are safe to apply to a running service; the running
# processes get the new process limit immediately via _lift_live_nproc below.
if [[ "$REGMIG" == "true" ]]; then
    _regmig_apply || _fail "Could not move the registration code into $REG_ENV_FILE"
    UNITS_CHANGED+=(cryptirc.service)
    echo -e "  ${GREEN}✓ cryptirc.service: the registration code moved to the root-only $REG_ENV_FILE${NC} ${DIM}(local users could read it with systemctl show; previous unit in $REG_ENV_DIR/backups/)${NC}"
fi
if _migrate_unit_lines web; then
    [[ " ${UNITS_CHANGED[*]} " == *" cryptirc.service "* ]] || UNITS_CHANGED+=(cryptirc.service)
    echo -e "  ${GREEN}✓ cryptirc.service: LimitNPROC=512 → TasksMax=512${NC} ${DIM}(the per-user thread cap was shared with irc-core)${NC}"
fi
if _migrate_unit_lines daemon; then
    [[ " ${UNITS_CHANGED[*]} " == *" irc-core.service "* ]] || UNITS_CHANGED+=(irc-core.service)
    echo -e "  ${GREEN}✓ irc-core.service: removed LimitNPROC=64${NC} ${DIM}(per-user, so the web's threads starved the daemon; TasksMax=256 still caps it)${NC}"
fi
if (( ${#UNITS_CHANGED[@]} > 0 )); then
    systemctl daemon-reload || _fail "systemctl daemon-reload failed after updating ${UNITS_CHANGED[*]}"
    if [[ " ${UNITS_CHANGED[*]} " == *" irc-core.service "* && "$RESTART_DAEMON" != "true" ]] && systemctl is-active --quiet irc-core; then
        _lift_live_nproc irc-core && echo -e "  ${DIM}running irc-core given the new process limit in place — no restart, no dropped connections${NC}"
    fi
    if [[ " ${UNITS_CHANGED[*]} " == *" cryptirc.service "* && "$WEB_RESTART" != "true" ]] && systemctl is-active --quiet cryptirc; then
        _lift_live_nproc cryptirc && echo -e "  ${DIM}running cryptirc given the new process limit in place${NC}"
    fi
    echo ""
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
    # Both come from the web service as it was running when this update started (or its
    # Environment= AND EnvironmentFile= settings if it wasn't) — see _resolve_data_dir.
    MIG_DATA="$DATA_DIR"
    # The web process resolves its socket as CRYPTIRC_IPC_SOCK first, only then
    # $CRYPTIRC_DATA/irc-core.sock (src/main.rs). If the legacy web unit pins a
    # custom socket path, the daemon MUST bind that same path or they'd never
    # meet — so carry it through verbatim (empty → daemon uses the data-dir default).
    MIG_IPC_SOCK="$WEB_IPC_SOCK0"
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
    # Everything below goes into a unit file root writes: plain names and paths only.
    [[ "$MIG_USER" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ && "$MIG_GROUP" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] \
        || _fail "Refusing to write irc-core.service: unexpected service user/group $(printf '%q %q' "$MIG_USER" "$MIG_GROUP")"
    if ! _safe_path "$MIG_DATA" || { [[ -n "$MIG_IPC_SOCK" ]] && ! _safe_path "$MIG_IPC_SOCK"; }; then
        _fail "Refusing to write irc-core.service: the data dir / socket path is not a plain absolute path"
    fi
    # Only emit an Environment=CRYPTIRC_IPC_SOCK line when the legacy unit had one. A socket
    # outside the data dir also needs its directory writable: under ProtectSystem=strict the
    # daemon could not bind it there (the update then rolled back). Created if missing.
    MIG_IPC_SOCK_LINE=""; MIG_SOCK_RW_LINE=""
    if [[ -n "$MIG_IPC_SOCK" ]]; then
        MIG_IPC_SOCK_LINE="Environment=CRYPTIRC_IPC_SOCK=$MIG_IPC_SOCK"
        _sd=$(dirname "$MIG_IPC_SOCK")
        if [[ "$_sd/" != "${MIG_DATA%/}/"* ]]; then
            [[ -d "$_sd" ]] || install -d -m 700 -o "$MIG_USER" -g "$MIG_GROUP" "$_sd" \
                || _fail "Could not create the socket directory $_sd for irc-core"
            # "-": a socket directory that is gone at boot must not stop the unit from starting
            # at all (status 226/NAMESPACE); the daemon then logs why it can't bind.
            MIG_SOCK_RW_LINE="ReadWritePaths=-$_sd"
            # On /run (a tmpfs: empty after every boot) the directory must also come back by
            # itself: systemd (re)creates a RuntimeDirectory= before each start, owned by the
            # unit's user, and Preserve keeps it (and the socket) across daemon restarts.
            _rd=""
            case "$_sd" in /run/?*) _rd=${_sd#/run/} ;; /var/run/?*) _rd=${_sd#/var/run/} ;; esac
            if [[ -n "$_rd" ]]; then
                MIG_SOCK_RW_LINE="# The socket directory is on /run, emptied at every boot: systemd recreates it.
RuntimeDirectory=$_rd
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
$MIG_SOCK_RW_LINE"
            fi
        fi
    fi

    IRC_CORE_UNIT_CREATED=true; DAEMON_TOUCHED=true   # rollback removes it again if anything below fails
    cat > /etc/systemd/system/irc-core.service <<UNIT || _fail "Could not write /etc/systemd/system/irc-core.service"
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
$MIG_SOCK_RW_LINE
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

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload || _fail "systemctl daemon-reload failed after writing irc-core.service"
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
        # The new web binary cannot do IRC without the daemon, so continuing would bring
        # the site up with every user's IRC dead. Roll back instead: the previous
        # (pre-split) web binary dials IRC itself, and the new unit is removed again.
        _fail "irc-core was installed but failed to start (journalctl -u irc-core -n 50) — the new web binary needs it for IRC"
    fi
    echo ""
fi


# ── Start service(s) ─────────────────────────────────────────────────────────
# Skip when we just migrated: the migration block already installed, started and
# health-checked irc-core, so re-running the daemon start here would be a no-op
# that misleadingly reprints "Starting irc-core..." for a box that never had it.
DAEMON_RECOVERED=false
if [[ "$RESTART_DAEMON" == "true" && "$HAVE_IRC_CORE_UNIT" == "true" && "$MIGRATED_TO_DAEMON" == "false" ]]; then
    echo -e "${BOLD}Starting irc-core...${NC}"
    DAEMON_TOUCHED=true; IRC_CORE_STOPPED_BY_US=true
    systemctl reset-failed irc-core 2>/dev/null
    # Not a bare start under errexit any more: a failed start (Type=notify process dying
    # before READY) used to exit right here with irc-core down — now it rolls back.
    systemctl start irc-core || _fail "irc-core failed to start (journalctl -u irc-core -n 50)"
    # irc-core has no HTTP endpoint, so the functional signal is its IPC socket
    # actually existing (proof it bound its listener, not just that it forked).
    _daemon_healthy 15 || _fail "irc-core started, but is not active or its IPC socket never appeared (journalctl -u irc-core -n 50)"
    IRC_CORE_STOPPED_BY_US=false
    echo -e "  ${GREEN}✓ irc-core started${NC}"
    echo ""
elif [[ "$HAVE_IRC_CORE_UNIT" == "true" && "$MIGRATED_TO_DAEMON" == "false" ]] \
     && systemctl is-enabled --quiet irc-core 2>/dev/null && ! systemctl is-active --quiet irc-core; then
    # Recovery: the daemon is enabled but down (e.g. an earlier update was killed in its
    # window). Nobody is connected, so starting it drops nothing — and the web can't do IRC
    # without it. Best effort: it was down before this run, so a failure is not a rollback.
    echo -e "  ${YELLOW}⚠ irc-core is enabled but not running — starting it.${NC}"
    systemctl reset-failed irc-core 2>/dev/null
    if systemctl start irc-core 2>/dev/null && _daemon_healthy 15; then
        DAEMON_RECOVERED=true
        echo -e "  ${GREEN}✓ irc-core started${NC}"
    else
        echo -e "  ${RED}✗ irc-core still isn't running — check: journalctl -u irc-core -n 50${NC}"
    fi
    echo ""
fi

if [[ "$WEB_RESTART" == "true" ]]; then
    echo -e "${BOLD}Starting CryptIRC...${NC}"
    WEB_TOUCHED=true; CRYPTIRC_STOPPED_BY_US=true
    # Across the data floor, fingerprint users' data now, while no cryptirc runs: whatever
    # differs when a health-check failure would roll back was written by the NEW version
    # (see DATA_FLOOR / _rollback).
    if [[ "$SWAPPED_WEB" == "true" ]] && _floor_crossed "$OLD_VER" "$NEW_VER"; then
        USER_DATA_SNAP0=$(_user_data_snapshot "$DATA_DIR") || USER_DATA_SNAP0=unknown
    fi
    systemctl reset-failed cryptirc 2>/dev/null   # a crash loop's start-limit latch would refuse the start
    systemctl start cryptirc || _fail "systemctl start cryptirc failed (journalctl -u cryptirc -n 50)"
    # A real HTTP 200 from the app's own port + base path, from a process that stays up —
    # see _web_healthy. Anything less is a failed update and is rolled back.
    _web_healthy "$HEALTH_TIMEOUT" || _fail "The new cryptirc did not come up healthy: no steady HTTP 200 from ${WEB_PROBE_DESC:-its local port} within ${HEALTH_TIMEOUT}s (last: ${WEB_LAST_CODE})"
    CRYPTIRC_STOPPED_BY_US=false
    echo -e "  ${GREEN}✓ CryptIRC restarted successfully${NC} ${DIM}(HTTP 200 on ${WEB_PROBE_DESC})${NC}"
else
    echo -e "  ${DIM}cryptirc left running (unchanged) — it re-attaches to irc-core automatically if the daemon restarted${NC}"
fi

# ── Committed ────────────────────────────────────────────────────────────────
IN_WINDOW=false
# Persist the deploy markers used by the NEXT run's change detection now, before the
# summary (see _persist_deploy_markers).
_persist_deploy_markers

# Not part of the binary update (a failure here rolls back only itself): see _caddy_log_redaction.
_caddy_log_redaction

# ── Summary: what actually changed, and what this run did about it ────────────
echo ""
echo -e "${BOLD}Summary${NC}"
if [[ "$OLD_VER" != "unknown" && "$OLD_VER" != "$NEW_VER" ]]; then
    echo -e "  version:         ${CYAN}v${OLD_VER}${NC} → ${CYAN}${BOLD}v${NEW_VER}${NC}"
else
    echo -e "  version:         ${CYAN}${BOLD}v${NEW_VER}${NC}"
fi
if [[ -n "$PREBUILT_DIR" ]]; then
    echo -e "  code:            ${GREEN}prebuilt binaries from ${BIN_DIR}${NC} ${DIM}(nothing pulled or built here)${NC}"
elif [[ "${GIT_PULL_OK:-true}" != "true" ]]; then
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
    if [[ "$RESTART_DAEMON" == "true" && "$DAEMON_CHANGED" != "true" ]]; then
        echo -e "  irc-core daemon: ${GREEN}unit refreshed → restarted${NC} ${DIM}(IRC sessions dropped: they reconnect by themselves for users whose vault is unlocked, the rest on their next unlock)${NC}"
    elif [[ "$DAEMON_CHANGED" != "true" ]]; then
        if [[ "$DAEMON_RECOVERED" == "true" ]]; then
            echo -e "  irc-core daemon: ${YELLOW}unchanged, was down → started${NC}"
        else
            echo -e "  irc-core daemon: ${DIM}unchanged → left running${NC}"
        fi
        if [[ "$IRC_CORE_UNIT_STALE" == "true" ]]; then
            echo -e "    ${DIM}deploy/irc-core.service differs from the installed unit — it is applied by: sudo bash deploy/update.sh --restart-daemon${NC}"
        elif [[ "$IRC_CORE_UNIT_CUSTOM" == "true" ]]; then
            echo -e "    ${DIM}your irc-core.service has local changes, so it is never auto-refreshed — compare it with deploy/irc-core.service yourself${NC}"
        fi
    elif [[ "$RESTART_DAEMON" == "true" ]]; then
        echo -e "  irc-core daemon: ${GREEN}changed → restarted${NC} ${DIM}(IRC sessions dropped: they reconnect by themselves for users whose vault is unlocked, the rest on their next unlock)${NC}"
    elif [[ "$DAEMON_RECOVERED" == "true" ]]; then
        echo -e "  irc-core daemon: ${GREEN}changed, was down → started on the new code${NC}"
    else
        # Deferred restart: changed but left running — the new daemon code is on disk but
        # the running process still executes the OLD code until it restarts.
        echo -e "  irc-core daemon: ${YELLOW}CHANGED but NOT restarted${NC}"
        echo -e "    ${YELLOW}⚠ The new daemon code is installed but the running daemon is still on the OLD code.${NC}"
        echo -e "    ${YELLOW}  Re-run with --restart-daemon to apply it (this will drop + reconnect IRC sessions).${NC}"
    fi
fi

if [[ -d "$RB_DIR" ]]; then
    echo -e "  rollback copy:   ${DIM}$RB_DIR (the files the most recent update replaced; an update that fails its health check restores them itself)${NC}"
fi

_note ""
_note "${GREEN}${BOLD}✓ Update complete!${NC}"
echo -e "${DIM}   CryptIRC by ${NC}${CYAN}${BOLD}gh0st${NC}${DIM}  ·  irc.twistednet.org  ·  ${NC}${CYAN}#twisted #dev${NC}"
if [[ "$MIGRATED_TO_DAEMON" == "true" ]]; then
    echo -e "  ${DIM}Migrated to the irc-core daemon — this was a one-time reconnect. From now"
    echo -e "  on, routine updates swap only the web binary and won't drop IRC connections.${NC}"
fi
