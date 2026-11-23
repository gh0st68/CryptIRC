#!/usr/bin/env bash
# Reset a CryptIRC user's password — and fix accounts that can't log in.
#
# Usage:
#   sudo ./resetpass.sh <username>                  # reset password: prompts twice, input hidden
#   sudo ./resetpass.sh -g <username>               # reset to a generated password, printed once
#   sudo ./resetpass.sh --verify <username>         # do NOT change the password; just mark the
#                                                   #   account verified (fixes "wrong password"
#                                                   #   complaints from unverified accounts)
#   sudo ./resetpass.sh --check [username]          # read-only: diagnose why an account can't
#                                                   #   log in (scans ALL accounts if no username)
#   sudo ./resetpass.sh --enable <username>         # lift an admin "Disable login" ban (same as
#                                                   #   the admin panel's Enable login)
#   printf '%s\n' "$PW" | sudo ./resetpass.sh --password-stdin <username>
#                                                   # non-interactive reset (first stdin line)
#   sudo ./resetpass.sh -- <-name>                  # a username starting with '-' goes after --
#
# Why --verify exists: login returns the SAME generic "Invalid username or
# password" for a wrong password AND for an unverified account (deliberate
# anti-enumeration, src/auth.rs #56). Users who registered on an old client
# and never completed email verification therefore report "wrong pass" after
# updating. --check spots them; --verify (or any reset, which now also marks
# the account verified — see --keep-unverified) fixes them.
#
# A reset also does what the web's password reset does: earlier reset links stop working, the
# account's push notification subscriptions go (a device someone else subscribed stops getting
# its messages), and every existing session of the account is signed out (sessions_valid_after).
# No reset and no --verify lifts a ban (Disable login) — also not one an older version stored as
# "unverified"; only --enable does.
# Exit status: 0 = done, or nothing to do (already verified / not disabled); 1 = refused or failed.
#
# The password is NEVER accepted as a positional argument — argv is readable by
# every local user via `ps`/`/proc/*/cmdline`. The same goes for
# `sudo CRYPTIRC_NEW_PASS=... ./resetpass.sh`: sudo keeps that in its OWN argv and
# its log. That form still works but warns; scripts should use --password-stdin.
# A new password must meet the app's policy: 10-1024 bytes with upper case, lower
# case, a digit and a symbol (src/auth.rs register / change_password).
#
# CRYPTIRC_DATA overrides the data dir (default /var/lib/cryptirc) — used by the
# Docker deploy and the test harness.
set -euo pipefail

DATA_DIR="${CRYPTIRC_DATA:-/var/lib/cryptirc}"

# ── Look & feel ───────────────────────────────────────────────────────────────
# Full styling + animation on a real terminal; auto-disabled when output is piped
# or NO_COLOR is set, so a captured generated password stays clean. Everything
# below goes to stderr for the same reason — stdout carries only the result.
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
    WHITE='\033[1;37m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'; FANCY=true
else
    GREEN=''; YELLOW=''; CYAN=''; WHITE=''; BOLD=''; DIM=''; NC=''; FANCY=false
fi
# The animation hides the cursor — guarantee it comes back on any exit.
[[ "$FANCY" == true ]] && trap 'printf "\033[?25h" >&2 2>/dev/null || true' EXIT

# A ghost drifts across the terminal. Purely decorative, interactive-only, and
# skippable with CRYPTIRC_NO_GHOST=1 — same gate the installer uses.
ghostfly() {
    [[ "$FANCY" == true && "${CRYPTIRC_NO_GHOST:-}" != "1" ]] || return 0
    local cols i trail=". · ∴ ~"
    cols=$(tput cols 2>/dev/null || echo 70); (( cols > 70 )) && cols=70; (( cols < 20 )) && cols=20
    printf '\033[?25l' >&2
    for ((i=0; i<=cols-6; i+=2)); do
        printf "\r%*s${DIM}${CYAN}%s${NC} ${WHITE}${BOLD}.-.${NC}"  "$i" "" "$trail" >&2
        printf "\n%*s      ${WHITE}${BOLD}(o o)${NC}"               "$i" "" >&2
        printf "\n%*s      ${WHITE}${BOLD} \\~/ ${NC}"              "$i" "" >&2
        sleep 0.018 || true
        printf "\033[2A" >&2   # cursor up 2 lines for the next frame
    done
    printf "\033[2B\r%*s\r" "$cols" "" >&2   # settle below the ghost + clear the line
    printf '\033[?25h' >&2
}

banner() {
    [[ "$FANCY" == true ]] || return 0
    ghostfly
    echo -e "  ${CYAN}${BOLD}CryptIRC${NC} ${DIM}·${NC} ${WHITE}${BOLD}password reset${NC}" >&2
    echo -e "  ${DIM}developed by gh0st  ·  irc.twistednet.org  ·  #twisted #dev${NC}" >&2
    echo >&2
}

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

MODE=reset          # reset | verify | check | enable
MODE_SET=""         # the mode option given, if any (only one may be)
GENERATE=0
KEEP_UNVERIFIED=0
PW_STDIN=0
USERNAME=""
_set_username() {
    if [[ -n "$USERNAME" ]]; then
        echo "Error: the password is no longer accepted as an argument (visible in \`ps\`)." >&2
        echo "Run without it to be prompted, or use --password-stdin / -g." >&2
        exit 1
    fi
    USERNAME="$1"
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        -g|--generate)        GENERATE=1; shift ;;
        --password-stdin)     PW_STDIN=1; shift ;;
        --verify|--check|--enable)
                              # One thing at a time: `--check --verify` used to run --verify (the last
                              # one won), changing an account the operator only meant to look at.
                              if [[ -n "$MODE_SET" && "$MODE_SET" != "$1" ]]; then
                                  echo "Error: $MODE_SET and $1 do different things; run them separately" >&2; exit 1
                              fi
                              MODE_SET="$1"; MODE="${1#--}"; shift ;;
        -k|--keep-unverified) KEEP_UNVERIFIED=1; shift ;;
        -h|--help)            usage 0 ;;
        --)                   shift
                              # Everything after `--` is positional: usernames may legally start
                              # with '-' (is_safe_username allows it), same as makeadmin.sh.
                              while [[ $# -gt 0 ]]; do _set_username "$1"; shift; done ;;
        -*)                   echo "Error: unknown option '$1' (a username that starts with '-' goes after --)" >&2; usage ;;
        *)                    _set_username "$1"; shift ;;
    esac
done

# Options that only mean something for a password reset are refused elsewhere instead of
# being silently ignored (e.g. `--check -g` printed nothing, `--verify -g` changed no password).
if [[ "$MODE" != reset ]]; then
    if [[ "$GENERATE" == 1 ]]; then echo "Error: -g sets a new password; it can't be combined with $MODE_SET" >&2; exit 1; fi
    if [[ "$PW_STDIN" == 1 ]]; then echo "Error: --password-stdin sets a new password; it can't be combined with $MODE_SET" >&2; exit 1; fi
    if [[ "$KEEP_UNVERIFIED" == 1 && "$MODE" != verify ]]; then
        echo "Error: --keep-unverified only goes with a password reset" >&2; exit 1
    fi
fi
if [[ "$MODE" == verify && "$KEEP_UNVERIFIED" == 1 ]]; then
    echo "Error: --verify marks the account verified; --keep-unverified says not to — pick one" >&2; exit 1
fi
if [[ "$GENERATE" == 1 && "$PW_STDIN" == 1 ]]; then
    echo "Error: -g generates the password, --password-stdin reads one — pick one" >&2; exit 1
fi
# Only --check may run without a username (scan-all mode).
if [[ -z "$USERNAME" && "$MODE" != check ]]; then
    usage
fi

if [[ -n "$USERNAME" ]]; then
    # LC_ALL=C: ASCII case mapping only (under tr_TR.UTF-8, for one, `I` doesn't lower to `i`).
    USERNAME=$(printf '%s' "$USERNAME" | LC_ALL=C tr '[:upper:]' '[:lower:]')
    # Mirror src/auth.rs is_safe_username(): [a-z0-9_-], 3-32 chars (post-lowercase).
    # Rejecting anything else is also what makes the path join below traversal-safe.
    # LC_ALL=C matters: under a UTF-8 locale glibc's collation makes [a-z] match
    # accented letters, so 'alícé' would sail through and we'd claim success for a
    # record register() can never create. LANG=C also makes ${#...} count bytes,
    # matching the byte length src/auth.rs checks.
    if ! LC_ALL=C bash -c '[[ "$1" =~ ^[a-z0-9_-]{3,32}$ ]]' _ "$USERNAME"; then
        echo "Error: invalid username (3-32 chars; letters, numbers, _ and - only)" >&2
        exit 1
    fi
fi

banner

# ─── --check: read-only diagnosis ───────────────────────────────────────────
if [[ "$MODE" == check ]]; then
    if [[ ! -d "$DATA_DIR/users" ]]; then
        echo "Error: no users directory at $DATA_DIR/users" >&2
        exit 1
    fi
    _D="$DATA_DIR" _U="$USERNAME" python3 - <<'PY'
import sys
sys.path[:] = [p for p in sys.path if p not in ('', '.')]   # never import from the cwd as root
import json, os, stat

data_dir = os.environ['_D']
target   = os.environ.get('_U') or None
users    = os.path.join(data_dir, 'users')
# Read-only, but still never through a symlink planted in the service-owned users/ dir
# (a link to /dev/zero would hang a plain open(); one to a root-only file would be read as root).
try:
    dfd = os.open(users, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except PermissionError:
    sys.exit(f"Cannot read {users} — re-run with sudo.")
except OSError as e:
    sys.exit(f"Cannot open {users} ({e.strerror}) — it must be a real directory, not a symlink.")
def load(fn, dir_fd=dfd, limit=1 << 20):
    fd = os.open(fn, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise ValueError("not a regular file (a symlink, device or > 1 MiB)")
        return json.loads(f.read()), st

# Bans recorded before the `disabled` flag existed — the server's migrate_legacy_disabled_flag
# rules (src/auth.rs), as in the reset/verify code below (keep the two copies in step).
def pending_signup_mtime_ns(name):
    try:
        pfd = os.open(os.path.join(data_dir, 'pending'), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None
    best = None
    try:
        for fn in os.listdir(pfd):
            if not fn.endswith('.json'):
                continue
            try:
                lst = os.stat(fn, dir_fd=pfd, follow_symlinks=False)
                if not stat.S_ISREG(lst.st_mode):
                    continue
                rec, _ = load(fn, pfd, 64 << 10)
            except (OSError, ValueError):
                continue
            if not (isinstance(rec, dict) and all(isinstance(rec.get(k), str) for k in ('username', 'email', 'token'))
                    and isinstance(rec.get('expires_at'), int) and not isinstance(rec.get('expires_at'), bool)):
                continue
            if rec['username'].lower() == name and (best is None or lst.st_mtime_ns > best):
                best = lst.st_mtime_ns
    finally:
        os.close(pfd)
    return best

def legacy_ban(u, rec_mtime_ns, name):
    if 'disabled' in u or u.get('verified') is not False:
        return None, ''
    ll = u.get('last_login')
    if isinstance(ll, int) and not isinstance(ll, bool) and ll > 0:
        return True, "it has logged in before, and only an admin ban unverifies an account after that"
    if u.get('admin') is True:
        return False, ''
    if u.get('email', '') == '':
        return True, "it has no email, and no signup leaves an account unverified without one"
    p = pending_signup_mtime_ns(name)
    if p is None:
        return True, "no email-verification record of its signup is left to show it is an untouched signup"
    if rec_mtime_ns > p:
        return True, "it was changed after its signup's email-verification record was written"
    return False, ''

REQUIRED = ("username", "email", "password_hash", "verified", "created_at")
TUNED    = '$argon2id$v=19$m=65536,t=3,p=1$'

names = [f"{target}.json"] if target else sorted(
    f for f in os.listdir(dfd) if f.endswith('.json'))

broken = 0
for fn in names:
    uname, path = fn[:-5], os.path.join(users, fn)
    problems, notes = [], []

    if not os.path.lexists(path):
        # Point at case-mismatched files: login lowercases, so Foo.json is unreachable.
        cand = [f for f in os.listdir(dfd) if f.lower() == fn.lower()]
        hint = f" (found case-mismatched {cand[0]!r} — unreachable by login)" if cand else ""
        print(f"{uname}: NO ACCOUNT — no {fn} in {users}{hint}")
        broken += 1
        continue

    if fn != fn.lower():
        problems.append("uppercase filename — login lowercases, so this file is never found")

    try:
        u, ust = load(fn)
        if not isinstance(u, dict):
            raise ValueError("not a JSON object")
    except Exception as e:
        print(f"{uname}: BROKEN — corrupt JSON or unreadable file ({e}); login fails with the generic error")
        broken += 1
        continue

    missing = [k for k in REQUIRED if k not in u]
    if missing:
        problems.append(f"missing field(s) {missing} — record won't parse; login says wrong password")

    h = u.get('password_hash', '')
    if 'password_hash' in u:
        if not (h.startswith('$argon2') and h.count('$') >= 5):
            problems.append(f"foreign/unparseable hash scheme {h[:12]!r} — password can NEVER verify; reset required")
        elif not h.startswith(TUNED):
            notes.append("legacy argon2 params (login still works; weaker than tuned — heals on next reset/password change)")

    # A disabled account ALSO has verified=false (src/auth.rs disable_user) — check the ban
    # first so it is never mistaken for an unverified signup and "fixed" with --verify.
    legacy, why = legacy_ban(u, ust.st_mtime_ns, uname.lower())
    if u.get('disabled') is True or legacy is True:
        problems.append("DISABLED by an admin (banned) — login is refused on purpose. NOT an "
                        "unverified account: --verify and resets do not lift it; only the admin "
                        "panel (Enable login) or --enable does, if you really mean to"
                        + (f" (recorded the pre-0.5.8 way, as verified=false: {why})" if legacy else ""))
    elif u.get('verified') is not True:
        problems.append("UNVERIFIED — login says 'Invalid username or password' even with the CORRECT "
                        "password; fix: --verify (keeps their password) or a reset")

    if problems:
        broken += 1
        print(f"{uname}: BROKEN — " + "; ".join(problems))
    else:
        print(f"{uname}: OK" + (f" ({'; '.join(notes)})" if notes else ""))

total = len(names)
print(f"\n{total - broken}/{total} OK, {broken} broken", file=sys.stderr)
sys.exit(1 if broken else 0)
PY
    exit $?
fi

USER_FILE="$DATA_DIR/users/${USERNAME}.json"
if [[ ! -f "$USER_FILE" ]]; then
    echo "Error: user '$USERNAME' not found (no $USER_FILE)" >&2
    echo "Hint: run '$0 --check' to scan all accounts (also catches case-mismatched files)." >&2
    exit 1
fi

# ─── Obtain the new password (reset mode only) ──────────────────────────────
PASSWORD=""
if [[ "$MODE" == reset ]]; then
    if [[ $GENERATE -eq 1 ]]; then
        # 24 chars that always meet the app's policy (at least one of each class); the
        # symbols are ones that survive copy/paste into a shell or a form unquoted.
        PASSWORD=$(python3 -I -c 'import secrets, string
sym = "-_.@+="
abc = string.ascii_letters + string.digits + sym
while True:
    pw = "".join(secrets.choice(abc) for _ in range(24))
    if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw) and any(c in sym for c in pw)):
        break
print(pw)')
    elif [[ $PW_STDIN -eq 1 ]]; then
        IFS= read -r PASSWORD || [[ -n "$PASSWORD" ]] || { echo "Error: --password-stdin: nothing on stdin" >&2; exit 1; }
        PASSWORD="${PASSWORD%$'\r'}"
    elif [[ -n "${CRYPTIRC_NEW_PASS:-}" ]]; then
        echo "WARNING: 'sudo CRYPTIRC_NEW_PASS=... ./resetpass.sh' shows the password to every local user (ps)" >&2
        echo "         and in sudo's log. Use the prompt, or --password-stdin from scripts." >&2
        PASSWORD="$CRYPTIRC_NEW_PASS"
    else
        if [[ ! -t 0 ]]; then
            echo "Error: stdin is not a terminal; use --password-stdin or -g" >&2
            exit 1
        fi
        read -rs -p "New password for '$USERNAME': " PASSWORD; echo >&2
        read -rs -p "Confirm password: " PASSWORD2; echo >&2
        if [[ "$PASSWORD" != "$PASSWORD2" ]]; then
            echo "Error: passwords do not match" >&2
            exit 1
        fi
    fi

    # The app's own policy (src/auth.rs register / change_password / reset_password): this
    # script writes the hash directly, so the server never gets a chance to re-check it.
    # Length is in BYTES, as Rust's str::len() counts it. -I: never import from the cwd.
    if ! printf '%s\n' "$PASSWORD" | python3 -I -c 'import sys
try:
    pw = sys.stdin.buffer.readline().rstrip(b"\n").decode("utf-8")
except UnicodeDecodeError:
    sys.exit("Error: the password is not valid UTF-8")
n = len(pw.encode("utf-8"))
if n < 10:
    sys.exit("Error: password must be at least 10 characters")
if n > 1024:
    sys.exit("Error: password is too long (max 1024 characters)")
if not (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
        and any(c in "0123456789" for c in pw) and any(not c.isalnum() for c in pw)):
    sys.exit("Error: password must contain uppercase, lowercase, number, and special character")'; then
        exit 1
    fi
fi

# ─── Rewrite the user record atomically ─────────────────────────────────────
# Argon2id params MUST stay in lock-step with tuned_argon2() in src/auth.rs
# (m=65536 KiB, t=3, p=1, 32-byte hash, v=19). The login handler equalizes
# timing against a dummy hash computed with those same params, so drifting here
# re-opens a username-enumeration timing oracle — and lighter params weaken the
# stored hash. There is no rehash-on-login: whatever we write stays until the
# user's next password change.
#
# Both modes mark the account verified (unless --keep-unverified): an operator
# running this as root IS the out-of-band verification, and an unverified
# account fails login with the generic wrong-password error, which is exactly
# the support case this script exists to fix.
# Exit status of the block: 0 = changed, 3 = nothing to do (already in the state asked for;
# it said so), anything else = refused / failed.
_RC=0
_MODE="$MODE" \
_CRYPTIRC_PW="$PASSWORD" \
_KEEP="$KEEP_UNVERIFIED" \
_F="$USER_FILE" \
_U="$USERNAME" \
_D="$DATA_DIR" \
python3 - <<'PY' || _RC=$?
import sys
sys.path[:] = [p for p in sys.path if p not in ('', '.')]   # never import from the cwd as root
import errno, fcntl, json, os, secrets, signal, stat, time

mode     = os.environ['_MODE']
path     = os.environ['_F']
uname    = os.environ['_U']
data_dir = os.environ['_D']
users_dir = os.path.join(data_dir, 'users')
fname     = os.path.basename(path)

# users/ (and resets/) sit in the data dir the unprivileged service account owns, so a
# compromised service could swap names in them while this runs as root. Everything goes
# through a descriptor for the directory itself (refused if it is a symlink): records are
# opened O_NOFOLLOW, the new record is created O_EXCL and given its owner/mode with
# fchown/fchmod on the open descriptor — never by pathname — and renamed into place
# relative to that same descriptor.
try:
    dfd = os.open(users_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
except PermissionError:
    sys.exit(f"Cannot read {users_dir} — re-run with sudo.")
except OSError as e:
    sys.exit(f"Cannot open {users_dir} ({e.strerror}) — it must be a real directory, not a symlink.")

def read_small(name, dir_fd, limit=1 << 20):
    """(raw bytes, stat) of a regular file <= limit, never through a symlink; (None, None) if not."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        return None, None
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None, None
        return f.read(), st

def read_record():
    raw, st = read_small(fname, dfd)
    if raw is None:
        if os.path.islink(path):
            sys.exit(f"{path} is a symlink, not an account file; refusing to touch it.")
        sys.exit(f"Cannot read {path} as a regular account file — re-run with sudo, or run --check.")
    return raw, st

lock_fail = lambda msg: sys.exit(msg[0].upper() + msg[1:] + ("" if msg.endswith(".") else "."))
LOCK_NAME = ".cryptirc-admin.lock"
LOCK_WAIT = 30
def take_lock():
    """The account lock: flock(LOCK_EX) on <data>/.cryptirc-admin.lock. adduser.sh / resetpass.sh /
    makeadmin.sh take it exclusively; the running server takes it SHARED around every account
    read-modify-write and around the email check + create of a sign-up. So while this holds it, no
    server write to an account is half-way (read but not yet written back), and none starts.
    Waits (blocking, bounded) for a holder to finish; held until this process exits.

    The data dir belongs to the service account, so the name may hold anything it put there. The
    owner of a file is only ever changed on a file this run itself created (O_CREAT|O_EXCL|O_NOFOLLOW,
    fchown on that new descriptor): created by root, the lock goes to the data dir owner, because the
    server runs as that account and must be able to open it. A file found there must be a plain lock
    file (regular, one link, owned by root or the data dir owner); anything else (a hard link to some
    other file, a symlink, a FIFO) loses its name (unlink never touches the file behind it) and a fresh
    one is created. A root-owned lock left by an older script is replaced, not chowned."""
    try:
        ddfd = os.open(data_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as e:
        lock_fail(f"cannot open {data_dir} ({e.strerror})")
    dst = os.fstat(ddfd)
    handover = os.geteuid() == 0 and dst.st_uid != 0

    def create(name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=ddfd)
        if handover:
            os.fchown(fd, dst.st_uid, dst.st_gid)
        return fd

    def wait_for(fd):
        nonlocal noted
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            pass
        if not noted:
            noted = True
            print("Waiting for the account lock (the CryptIRC server or another admin script is using it)...",
                  file=sys.stderr)
        left = int(deadline - time.monotonic()) + 1
        def _timeout(signum, frame):
            raise TimeoutError
        old = signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(max(1, left))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except TimeoutError:
            lock_fail(f"the account lock was still held after {LOCK_WAIT} s (by the server or another adduser.sh / "
                      "resetpass.sh / makeadmin.sh run); nothing was changed — try again in a moment")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)

    deadline, noted = time.monotonic() + LOCK_WAIT, False
    for _ in range(20):
        try:
            try:
                lfd = create(LOCK_NAME)
            except FileExistsError:
                try:
                    lfd = os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=ddfd)
                    st = os.fstat(lfd)
                    plain = stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid in (0, dst.st_uid)
                except OSError as e:
                    if e.errno != errno.ELOOP:
                        raise
                    lfd, plain = -1, False            # a symlink
                if not plain:
                    if lfd >= 0:
                        os.close(lfd)
                    os.unlink(LOCK_NAME, dir_fd=ddfd)
                    print(f"NOTE: {data_dir}/{LOCK_NAME} was not a plain lock file — replaced it.", file=sys.stderr)
                    continue
            wait_for(lfd)
            # Holding the lock on a file that is no longer at the name (replaced while we waited) would
            # exclude nobody: check, and start over if so.
            try:
                cur = os.stat(LOCK_NAME, dir_fd=ddfd, follow_symlinks=False)
            except FileNotFoundError:
                cur = None
            st = os.fstat(lfd)
            if cur is None or (cur.st_ino, cur.st_dev) != (st.st_ino, st.st_dev):
                os.close(lfd)
                continue
            if handover and st.st_uid == 0:
                # A root-only lock (made by an older script) that the server could not open: put a fresh,
                # service-owned one in its place while holding this one, already locked.
                tmp = f"{LOCK_NAME}.{secrets.token_hex(6)}"
                nfd = create(tmp)
                try:
                    fcntl.flock(nfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    os.rename(tmp, LOCK_NAME, src_dir_fd=ddfd, dst_dir_fd=ddfd)
                except BaseException:
                    os.close(nfd)
                    try:
                        os.unlink(tmp, dir_fd=ddfd)
                    except OSError:
                        pass
                    raise
                os.close(lfd)
                lfd = nfd
            os.close(ddfd)
            return lfd
        except FileNotFoundError:
            continue                                # the name went away between two steps: again
        except PermissionError:
            lock_fail(f"cannot write to {data_dir} — re-run with sudo")
        except OSError as e:
            lock_fail(f"cannot open the lock file {data_dir}/{LOCK_NAME} ({e.strerror})")
    lock_fail(f"{data_dir}/{LOCK_NAME} keeps being replaced by something else; nothing was changed")

# --- Bans recorded before the `disabled` flag existed (keep in step with the copy in --check) ---
# Until 0.5.8 an admin "Disable login" was stored as verified=false only, which on disk looks
# exactly like a signup that never verified its email. A new server classifies such records
# once, at start-up (src/auth.rs migrate_legacy_disabled_flag) — but this script may run
# before that (say, from a fresh checkout while the old server still runs). So it applies the
# same rules, in the same order, to the same evidence, and never lifts such a ban by calling it
# "unverified".
def pending_signup_mtime_ns(name):
    """Newest mtime (ns) of a pending/<token>.json email-verification record for `name`: a regular
    file that parses as the server's PendingVerification. None if there is none (or pending/ can't
    be read — the server's rule then has no witness either)."""
    try:
        pfd = os.open(os.path.join(data_dir, 'pending'), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    best = None
    try:
        for fn in os.listdir(pfd):
            if not fn.endswith('.json'):
                continue
            try:
                lst = os.stat(fn, dir_fd=pfd, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(lst.st_mode):
                continue
            raw_p, _ = read_small(fn, pfd, 64 << 10)
            try:
                rec = json.loads(raw_p) if raw_p is not None else None
            except ValueError:
                rec = None
            if not (isinstance(rec, dict) and all(isinstance(rec.get(k), str) for k in ('username', 'email', 'token'))
                    and isinstance(rec.get('expires_at'), int) and not isinstance(rec.get('expires_at'), bool)):
                continue
            if rec['username'].lower() != name:
                continue
            if best is None or lst.st_mtime_ns > best:
                best = lst.st_mtime_ns
    finally:
        os.close(pfd)
    return best

def legacy_ban(u, rec_mtime_ns, name):
    """(verdict, why) for a record without the `disabled` key whose verified is false: verdict True =
    an admin ban, False = a signup awaiting email verification. (None, '') for any other record."""
    if 'disabled' in u or u.get('verified') is not False:
        return None, ''
    ll = u.get('last_login')
    if isinstance(ll, int) and not isinstance(ll, bool) and ll > 0:
        return True, "it has logged in before, and only an admin ban unverifies an account after that"
    if u.get('admin') is True:
        return False, ''
    if u.get('email', '') == '':
        return True, "it has no email, and no signup leaves an account unverified without one"
    p = pending_signup_mtime_ns(name)
    if p is None:
        return True, "no email-verification record of its signup is left to show it is an untouched signup"
    if rec_mtime_ns > p:
        return True, "it was changed after its signup's email-verification record was written"
    return False, ''

pw_hash = None
def nothing_to_do(msg):
    """Already in the state asked for: say so and exit 3, which the wrapper turns into success (an
    idempotent no-op, like makeadmin.sh's "already an admin"), without the success banner."""
    print(msg, file=sys.stderr)
    sys.exit(3)

def apply(raw, st):
    """Decide and make this run's change on a freshly read record. Returns
    (user, was_unverified, is_disabled, legacy_why), or exits when there is nothing (allowed) to do."""
    global pw_hash
    try:
        user = json.loads(raw)
    except ValueError as e:
        sys.exit(f"{path} is not valid JSON ({e}); refusing to touch it.")
    if not isinstance(user, dict) or 'password_hash' not in user:
        sys.exit(f"{path} does not look like a CryptIRC user record; aborting")

    was_unverified = user.get('verified') is not True
    legacy, legacy_why = legacy_ban(user, st.st_mtime_ns, fname[:-5].lower())
    is_disabled = user.get('disabled') is True or legacy is True   # admin ban (src/auth.rs disable_user)
    if legacy is not None:
        # Write the verdict into the record, as the server's migration would: this rewrite changes
        # the record's mtime, which is part of the evidence, so it must not be left to the server.
        user['disabled'] = legacy

    if mode == 'enable':
        if not is_disabled:
            nothing_to_do("Nothing to do: account is not disabled. If they still can't log in, run --check.")
        # Inverse of disable_user (which sets disabled=true AND verified=false): exactly what the
        # admin panel's Enable login does.
        user['disabled'] = False
        user['verified'] = True
    elif mode == 'reset':
        if pw_hash is None:
            from argon2 import PasswordHasher
            from argon2.low_level import Type
            ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1,
                                hash_len=32, salt_len=16, type=Type.ID)
            pw_hash = ph.hash(os.environ['_CRYPTIRC_PW'])
            # Self-check: refuse to write anything but the expected tuned-params format.
            if not pw_hash.startswith('$argon2id$v=19$m=65536,t=3,p=1$'):
                sys.exit(f"refusing to write hash with unexpected params: {pw_hash[:32]}...")
        user['password_hash'] = pw_hash
        user.pop('passkeys', None)
        user.pop('mcp_token_hash', None)
    elif is_disabled:
        sys.exit("Refusing: this account was DISABLED by an admin (banned) — it is not merely "
                 "unverified, and --verify does not lift a ban."
                 + (f" (Recorded the pre-0.5.8 way, as verified=false: {legacy_why}.)" if legacy else "")
                 + " If you really mean to re-enable it, use --enable (or Enable login in the admin panel).")
    elif not was_unverified:
        nothing_to_do("Nothing to do: account is already verified, and --verify does not change "
                      "the password. If they still can't log in, run --check and see what it says.")

    # A banned account keeps verified=false (the server's disable invariant); only --enable lifts it.
    if mode != 'enable' and os.environ['_KEEP'] != '1' and not is_disabled:
        user['verified'] = True
    return user, was_unverified, is_disabled, (legacy_why if legacy else '')

def purge_reset_links(names):
    """Delete this account's outstanding password-reset records (resets/<token>.json, whose
    "username" names the account — src/auth.rs PendingReset). An admin reset must not leave
    a link someone else may hold able to replace the new password within its hour."""
    try:
        rfd = os.open(os.path.join(data_dir, 'resets'), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return 0
    except OSError as e:
        print(f"WARNING: could not check {data_dir}/resets ({e.strerror}) — a password-reset link this "
              "account requested earlier may still work for up to an hour.", file=sys.stderr)
        return 0
    n = 0
    try:
        for fn in os.listdir(rfd):
            if not fn.endswith('.json'):
                continue
            raw, _ = read_small(fn, rfd, 64 << 10)
            try:
                rec = json.loads(raw) if raw is not None else None
            except ValueError:
                rec = None
            if isinstance(rec, dict) and rec.get('username') in names:
                try:
                    os.unlink(fn, dir_fd=rfd)
                    n += 1
                except FileNotFoundError:
                    pass
    finally:
        os.close(rfd)
    return n

def purge_push(names):
    """What the web's password reset also does (src/main.rs route_reset_password → purge_push_subscriptions):
    a reset means the account may have been compromised, so its Web Push subscriptions
    (push/<user>.json) and notification settings (notif_prefs/<user>.json) go — a device someone
    else subscribed would otherwise keep receiving the account's DMs and mentions (the server reads
    them from disk for every notification, so this takes effect at once). The user subscribes again
    on their next opt-in. Returns the files removed."""
    gone = []
    safe = {''.join(c for c in n if c.isascii() and (c.isalnum() or c in '_-')) for n in names} - {''}
    for sub in ('push', 'notif_prefs'):
        try:
            sfd = os.open(os.path.join(data_dir, sub), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            continue
        except OSError as e:
            print(f"WARNING: could not check {data_dir}/{sub} ({e.strerror}) — this account's push "
                  "notification subscriptions may still be active; remove its file there by hand.", file=sys.stderr)
            continue
        try:
            for n in sorted(safe):
                try:
                    os.unlink(f"{n}.json", dir_fd=sfd)        # unlink never follows a link
                    gone.append(f"{sub}/{n}.json")
                except FileNotFoundError:
                    pass
                except OSError as e:
                    print(f"WARNING: could not remove {data_dir}/{sub}/{n}.json ({e.strerror}).", file=sys.stderr)
        finally:
            os.close(sfd)
    return gone

raw, st = read_record()
user, was_unverified, is_disabled, legacy_why = apply(raw, st)   # (the slow Argon2 hash happens here, once — before the lock)
lock = take_lock()
# Decide again on the record as it is now that no other writer can be half-way: an edit that
# landed while the password was being hashed (a ban, say) is kept, and the checks in apply()
# (nothing to do? banned?) see the current state.
now_raw, now_st = read_record()
if now_raw != raw or (now_st.st_ino, now_st.st_dev) != (st.st_ino, st.st_dev):
    raw, st = now_raw, now_st
    user, was_unverified, is_disabled, legacy_why = apply(raw, st)
reset_names = {uname, str(user.get('username', uname)).lower()}
purged = purge_reset_links(reset_names) if mode == 'reset' else 0

# Atomic replace so a crash mid-write can never truncate the account file. Owner and mode
# come from the record being replaced (deploy-agnostic: native uses cryptirc:cryptirc, the
# Docker deploy has its own uid mapping).
#
# The running server rewrites whole records too (a login stamps last_login; an admin ban,
# a password change). A server that takes the account lock (see take_lock) can't be half-way
# through such a write now, so none of them can land later with the old record. One that
# doesn't (older than this script) is still checked for: immediately before the rename the
# record is read again, and if it changed since it was read (new bytes or a new inode — the
# server always renames a fresh file in), this run's change is applied to the NEW record and
# the write retried. The read-back after the rename stays.
def stamp_sessions(u):
    """A reset ends every existing session of the account: sessions_valid_after (unix seconds) makes the
    server reject any session created before it, on every validation path, within about a second, no
    restart (src/auth.rs; a server from before that ignores the field). Set at write time, under the
    account lock, never lowered: max(current value, now + 1). Every other field stays as it is."""
    cur = u.get('sessions_valid_after')
    if isinstance(cur, bool) or not isinstance(cur, (int, float)):
        cur = 0
    u['sessions_valid_after'] = max(int(cur), int(time.time()) + 1)

for attempt in range(5):
    if mode == 'reset':
        stamp_sessions(user)
    data = json.dumps(user, indent=2).encode()
    tmp = f".pwreset-{secrets.token_hex(8)}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    except PermissionError:
        sys.exit(f"Cannot write to {users_dir} — re-run with sudo.")
    renamed = False
    try:
        # fchown before fchmod: chown clears setuid/setgid.
        if os.geteuid() == 0:
            os.fchown(fd, st.st_uid, st.st_gid)
        os.fchmod(fd, stat.S_IMODE(st.st_mode) & 0o777)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        now_raw, now_st = read_record()
        if now_raw == raw and (now_st.st_ino, now_st.st_dev) == (st.st_ino, st.st_dev):
            os.rename(tmp, fname, src_dir_fd=dfd, dst_dir_fd=dfd)
            renamed = True
    finally:
        if fd >= 0:
            os.close(fd)
        if not renamed:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except FileNotFoundError:
                pass
    if renamed:
        break
    # Changed under us: start over from the record as it is now.
    raw, st = now_raw, now_st
    user, was_unverified, is_disabled, legacy_why = apply(raw, st)
else:
    sys.exit("This account kept changing while resetpass.sh was writing it (the server is busy with "
             "it). Nothing was changed — re-run the command.")
try:
    os.fsync(dfd)     # make the rename itself survive a power cut
except OSError:
    pass
push_gone = []
if mode == 'reset':
    # Again, for a link requested while the password was being hashed.
    purged += purge_reset_links(reset_names)
    push_gone = purge_push(reset_names)

# Read it back: a server write to this account that read the record before our rename and
# lands after it would silently put the OLD state back.
back_raw, _ = read_small(fname, dfd)
try:
    back = json.loads(back_raw) if back_raw is not None else None
except ValueError:
    back = None
if (not isinstance(back, dict)
        or back.get('password_hash') != user['password_hash']
        or back.get('verified') != user.get('verified')
        or back.get('disabled') != user.get('disabled')
        or back.get('sessions_valid_after') != user.get('sessions_valid_after')):
    sys.exit("Wrote the change but it is not in the file — the server most likely rewrote "
             "this account at the same moment. Re-run the command.")

# Human-facing notes go to stderr: stdout carries only a -g password, so
# PW=$(resetpass.sh -g user) must capture exactly that and nothing else.
if purged:
    print(f"NOTE: {purged} earlier password-reset link(s) for this account no longer work.", file=sys.stderr)
if push_gone:
    print("NOTE: removed this account's push notification subscriptions and settings (" + ", ".join(push_gone)
          + ") — no device keeps getting its DMs or mentions; they turn notifications on again to resubscribe.",
          file=sys.stderr)
if mode == 'reset' and is_disabled:
    print("NOTE: account is DISABLED by an admin — the password was changed, but it still cannot "
          "log in until the ban is lifted (admin panel: Enable login, or --enable)."
          + (f" (Recorded the pre-0.5.8 way, as verified=false: {legacy_why}.)" if legacy_why else ""), file=sys.stderr)
elif was_unverified and mode != 'enable':
    if os.environ['_KEEP'] == '1':
        print("NOTE: account is UNVERIFIED and was left that way (--keep-unverified) — "
              "login will STILL say 'Invalid username or password'.", file=sys.stderr)
    else:
        print("NOTE: account was UNVERIFIED — that is why login said 'Invalid username "
              "or password' even with the correct password. Marked verified.", file=sys.stderr)
PY
case "$_RC" in
    0) ;;
    3) exit 0 ;;             # an idempotent no-op (already verified / not disabled) — not an error
    *) exit "$_RC" ;;
esac

if [[ "$MODE" == verify ]]; then
    echo -e "  ${GREEN}✓${NC} Account ${BOLD}$USERNAME${NC} marked verified — password unchanged; they can" >&2
    echo -e "    log in with the password they already know." >&2
elif [[ "$MODE" == enable ]]; then
    echo -e "  ${GREEN}✓${NC} Account ${BOLD}$USERNAME${NC} re-enabled — the admin ban is lifted; they can" >&2
    echo -e "    log in with the password they already know." >&2
else
    echo -e "  ${GREEN}✓${NC} Password reset for ${BOLD}$USERNAME${NC}." >&2
    if [[ $GENERATE -eq 1 ]]; then
        echo -e "  ${YELLOW}Generated password${NC} ${DIM}(shown once, stored nowhere else)${NC}:" >&2
        # Indented on a terminal; bare when captured, so PW=$(resetpass.sh -g user) gets
        # exactly the password (the two leading spaces made a captured one unusable).
        if [[ -t 1 ]]; then printf '  %s\n' "$PASSWORD"; else printf '%s\n' "$PASSWORD"; fi
    fi
fi
# The version of the cryptirc service that runs on THIS data dir — only to say truthfully whether the
# reset just signed the account's sessions out: sessions_valid_after is honoured from 0.5.8 on, an
# older server ignores it. Local only: the running process's own settings (root reads its
# /proc/<pid>/environ), then its app.js on 127.0.0.1 (every version stamps CRYPTIRC_VERSION into
# it), else /opt/cryptirc/.version when the process runs that very binary. Prints the version;
# rc 1 = unknown (no such service, another data dir, not root, no answer…). Never changes anything.
running_server_version() {
    local pid kv port=9001 base=/cryptirc data=./data body exe dd v
    command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet cryptirc 2>/dev/null || return 1
    pid=$(systemctl show -p MainPID --value cryptirc 2>/dev/null) || return 1
    [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/environ" ]] || return 1
    while IFS= read -r -d '' kv; do
        case "$kv" in
            CRYPTIRC_PORT=*)      port=${kv#*=} ;;
            CRYPTIRC_BASE_PATH=*) base=${kv#*=} ;;
            CRYPTIRC_DATA=*)      data=${kv#*=} ;;
        esac
    done < "/proc/$pid/environ" 2>/dev/null
    # Is it the server of THIS data dir? (A relative CRYPTIRC_DATA is relative to its working dir.)
    [[ "$data" == /* ]] || data="$(readlink "/proc/$pid/cwd" 2>/dev/null)/${data#./}"
    dd=$(readlink -f -- "$DATA_DIR" 2>/dev/null) || return 1
    [[ -n "$dd" && "$(readlink -f -- "$data" 2>/dev/null)" == "$dd" ]] || return 1
    while [[ "$base" == */ ]]; do base=${base%/}; done
    if [[ "$port" =~ ^[0-9]{1,5}$ && "$base" =~ ^(/[A-Za-z0-9._~+-]+)*$ ]] && command -v curl >/dev/null 2>&1; then
        body=$(curl -s --noproxy '*' --max-time 3 "http://127.0.0.1:${port}${base}/app.js" 2>/dev/null) || body=""
        if [[ "$body" =~ CRYPTIRC_VERSION=\'([0-9][0-9A-Za-z.+-]*)\' ]]; then printf '%s' "${BASH_REMATCH[1]}"; return 0; fi
    fi
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
    if [[ "$exe" == /opt/cryptirc/cryptirc ]] && v=$(head -c 64 /opt/cryptirc/.version 2>/dev/null | tr -d '[:space:]') && [[ -n "$v" ]]; then
        printf '%s' "$v"; return 0
    fi
    return 1
}
# ver_ge <a> <b>: numeric major.minor.patch comparison (a -suffix ignored); rc 1 if a < b or not a version.
ver_ge() {
    local a="${1%%[!0-9.]*}" b="${2%%[!0-9.]*}" i x y
    local -a A B
    [[ "$a" =~ ^[0-9]+(\.[0-9]+)*$ ]] || return 1
    IFS=. read -ra A <<< "$a"; IFS=. read -ra B <<< "$b"
    for i in 0 1 2; do
        x=$(( 10#${A[i]:-0} )); y=$(( 10#${B[i]:-0} ))
        (( x > y )) && return 0
        (( x < y )) && return 1
    done
    return 0
}
if [[ "$MODE" == reset ]]; then
    echo >&2
    SRV_VER=$(running_server_version) || SRV_VER=""
    if [[ -n "$SRV_VER" ]] && ver_ge "$SRV_VER" 0.5.8; then
        echo -e "  ${DIM}Every existing session of '$USERNAME' is signed out (the running server, v${SRV_VER}, honours${NC}" >&2
        echo -e "  ${DIM}it): web pages within a few seconds, open live connections within about 30 seconds.${NC}" >&2
    else
        echo -e "  ${YELLOW}Sessions of '$USERNAME' that are already open may stay signed in:${NC} the running server" >&2
        echo -e "  ${DIM}($([[ -n "$SRV_VER" ]] && echo "v$SRV_VER, older than 0.5.8" || echo "version unknown")) may not support signing them out from here. To sign out${NC}" >&2
        echo -e "  ${DIM}existing sessions now: sudo systemctl restart cryptirc (that signs out ALL users).${NC}" >&2
    fi
fi
