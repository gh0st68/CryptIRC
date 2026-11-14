#!/usr/bin/env bash
# Grant (or remove) CryptIRC admin rights for an account.
#
# Usage:
#   sudo ./makeadmin.sh <username>            # grant admin
#   sudo ./makeadmin.sh --revoke <username>   # remove admin
#   sudo ./makeadmin.sh --list                # show every account and who is an admin
#
# A fresh install has NO admins, and there is no in-app way to create one — the
# admin panel is gated on the flag this script sets, so the first admin has to
# be made from the server. Run this once after creating your account, reload the
# page, and Settings will show Admin.
#
# The change is picked up immediately: the server re-reads the account file on
# every permission check, so there is nothing to restart. The person does need
# to reload their browser tab before the Admin entry appears in Settings.
#
# Admin also implies upload permission (see can_upload() in src/auth.rs), so an
# admin can upload files whether or not the upload flag is set separately.
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
    CYAN='\033[0;36m'; WHITE='\033[1;37m'
    BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'; FANCY=true
else
    CYAN=''; WHITE=''; BOLD=''; DIM=''; NC=''; FANCY=false
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
    echo -e "  ${CYAN}${BOLD}CryptIRC${NC} ${DIM}·${NC} ${WHITE}${BOLD}admin rights${NC}" >&2
    echo -e "  ${DIM}developed by gh0st  ·  irc.twistednet.org  ·  #twisted #dev${NC}" >&2
    echo >&2
}

usage() {
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

MODE=grant          # grant | revoke | list
FORCE=0
REVOKE_ASKED=0
LIST_ASKED=0
USERNAME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --revoke)      MODE=revoke; REVOKE_ASKED=1; shift ;;
        --list)        MODE=list; LIST_ASKED=1; shift ;;
        -f|--force)    FORCE=1; shift ;;
        -h|--help)     usage 0 ;;
        --)            shift
                       # Everything after `--` is positional. Usernames may legally
                       # start with '-' (is_safe_username allows it anywhere), and
                       # without this such an account could never be made admin.
                       while [[ $# -gt 0 ]]; do
                           if [[ -n "$USERNAME" ]]; then
                               echo "Error: only one username at a time (got '$USERNAME' and '$1')" >&2
                               exit 1
                           fi
                           USERNAME="$1"; shift
                       done ;;
        -*)            echo "Error: unknown option '$1'" >&2; usage ;;
        *)
            if [[ -n "$USERNAME" ]]; then
                echo "Error: only one username at a time (got '$USERNAME' and '$1')" >&2
                exit 1
            fi
            USERNAME="$1"; shift ;;
    esac
done

# --list is read-only; silently performing a revoke because a later flag won
# would be a nasty surprise.
if [[ "$LIST_ASKED" == 1 && "$REVOKE_ASKED" == 1 ]]; then
    echo "Error: --list and --revoke do different things; run them separately" >&2
    exit 1
fi
if [[ "$LIST_ASKED" == 1 && -n "$USERNAME" ]]; then
    echo "Error: --list takes no username" >&2
    exit 1
fi
if [[ "$MODE" != revoke && "$FORCE" == 1 ]]; then
    echo "Error: --force only means something with --revoke" >&2
    exit 1
fi

if [[ ! -d "$DATA_DIR/users" ]]; then
    echo "Error: no users directory at $DATA_DIR/users" >&2
    echo "Hint: is CryptIRC installed here? Set CRYPTIRC_DATA if your data dir is elsewhere." >&2
    exit 1
fi

if [[ "$MODE" == list ]]; then
    if [[ -n "$USERNAME" ]]; then
        echo "Error: --list takes no username" >&2
        exit 1
    fi
else
    if [[ -z "$USERNAME" ]]; then
        usage
    fi
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

# ─── --list: read-only roster ───────────────────────────────────────────────
if [[ "$MODE" == list ]]; then
    _D="$DATA_DIR" python3 - <<'PY'
import sys
sys.path[:] = [p for p in sys.path if p not in ('', '.')]   # never import from the cwd as root
import json, os, stat

users = os.path.join(os.environ['_D'], 'users')
# Read-only, but still never through a symlink planted in the service-owned users/ dir
# (a link to /dev/zero would hang a plain open(); one to a root-only file would be read as root).
try:
    dfd = os.open(users, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except PermissionError:
    sys.exit(f"Cannot read {users} — re-run with sudo.")
except OSError as e:
    sys.exit(f"Cannot open {users} ({e.strerror}) — it must be a real directory, not a symlink.")
def load(fn):
    fd = os.open(fn, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > 1 << 20:
            raise ValueError('not a regular account file')
        return json.loads(f.read())
rows, admins, unreadable = [], 0, 0
for fn in sorted(f for f in os.listdir(dfd) if f.endswith('.json')):
    try:
        u = load(fn)
        if not isinstance(u, dict):
            raise ValueError('not a JSON object')
    except Exception as e:
        rows.append((fn[:-5], '?', f'unreadable ({e})'))
        unreadable += 1
        continue
    is_admin = u.get('admin') is True
    admins += is_admin
    notes = []
    # A disabled (banned) account also has verified=false (src/auth.rs disable_user), so
    # report the ban, not "unverified" — the unverified fix (--verify) must not be applied.
    if u.get('disabled') is True:
        notes.append('DISABLED by an admin — cannot log in')
    elif u.get('verified') is not True:
        notes.append('UNVERIFIED — cannot log in')
    if not is_admin and u.get('can_upload') is True:
        notes.append('can upload')
    if fn != fn.lower():
        notes.append('uppercase filename — unreachable by login')
    rows.append((fn[:-5], 'ADMIN' if is_admin else '-', '; '.join(notes)))

if not rows:
    print('No accounts yet.')
    sys.exit(0)

w = max(len(r[0]) for r in rows)
for name, flag, notes in rows:
    print(f'{name:<{w}}  {flag:<5}  {notes}')
print(f'\n{admins} admin(s) of {len(rows)} account(s)', file=sys.stderr)
if not admins:
    print('No admins — the admin panel is unreachable until you grant one:\n'
          '  sudo ./makeadmin.sh <username>', file=sys.stderr)
if unreadable:
    print(f'{unreadable} account file(s) could not be read.', file=sys.stderr)
PY
    exit $?
fi

USER_FILE="$DATA_DIR/users/${USERNAME}.json"
if [[ ! -f "$USER_FILE" ]]; then
    echo "Error: user '$USERNAME' not found (no $USER_FILE)" >&2
    # Point at case-mismatched files: login lowercases, so Foo.json is unreachable.
    CAND=$(find "$DATA_DIR/users" -maxdepth 1 -iname "${USERNAME}.json" -printf '%f\n' 2>/dev/null | head -1 || true)
    if [[ -n "$CAND" ]]; then
        echo "Hint: found case-mismatched '$CAND' — that file is unreachable by login." >&2
    else
        echo "Hint: run '$0 --list' to see the accounts that exist." >&2
    fi
    exit 1
fi

# ─── Flip the flag atomically ───────────────────────────────────────────────
# Only the `admin` key is touched; every other field is written back exactly as
# read, so this cannot corrupt an account or drop a field the app relies on.
RC=0
_MODE="$MODE" _F="$USER_FILE" _U="$USERNAME" _DIR="$DATA_DIR" _FORCE="$FORCE" python3 - <<'PY' || RC=$?
import sys
sys.path[:] = [p for p in sys.path if p not in ('', '.')]   # never import from the cwd as root
import errno, fcntl, json, os, re, secrets, signal, stat, time

mode  = os.environ['_MODE']
path  = os.environ['_F']
uname = os.environ['_U']
want  = (mode == 'grant')
data_dir  = os.environ['_DIR']
users_dir = os.path.join(data_dir, 'users')
fname     = os.path.basename(path)

# users/ sits in the data dir the unprivileged service account owns, so a compromised
# service could swap names in it (a symlink to /etc/shadow, say) while this runs as root.
# Everything below goes through a descriptor for users/ itself (refused if users/ is a
# symlink): records are opened O_NOFOLLOW, the new record is created O_EXCL and given its
# owner/mode with fchown/fchmod on the open descriptor — never by pathname — and renamed
# into place relative to that same descriptor.
try:
    dfd = os.open(users_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
except PermissionError:
    sys.exit(f"Cannot read {users_dir} — re-run with sudo.")
except OSError as e:
    sys.exit(f"Cannot open {users_dir} ({e.strerror}) — it must be a real directory, not a symlink.")

def read_record(name=fname, quiet=False):
    """(raw bytes, stat) of users/<name>, never through a symlink; regular files <= 1 MiB only."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except OSError as e:
        if quiet:
            return None, None
        if e.errno == errno.EACCES:
            sys.exit(f"Cannot read {path} — re-run with sudo.")
        if e.errno == errno.ELOOP:
            sys.exit(f"{path} is a symlink, not an account file; refusing to touch it.")
        sys.exit(f"Cannot open {path} ({e.strerror}).")
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > 1 << 20:
            if quiet:
                return None, None
            sys.exit(f"{path} is not a regular account file; refusing to touch it.")
        return f.read(), st

def parse(raw):
    try:
        user = json.loads(raw)
    except ValueError as e:
        sys.exit(f"{path} is not valid JSON ({e}); refusing to touch it.")
    # Same shape check resetpass.sh uses: refuse to rewrite anything that isn't
    # recognisably a CryptIRC account record.
    if not isinstance(user, dict) or 'password_hash' not in user:
        sys.exit(f"{path} does not look like a CryptIRC user record; aborting")
    return user

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

def other_usable_admins():
    """(admins other than this account who could actually sign in, unreadable files)."""
    others, unreadable = 0, 0
    for fn in os.listdir(dfd):
        if not fn.endswith('.json') or fn[:-5] == uname:
            continue
        # Only an admin who could actually SIGN IN counts as the safety net.
        # Skipped: uppercase filenames (login lowercases, so the file is never
        # found) and stems that fail is_safe_username() in src/auth.rs. Both look
        # like admins on disk but can never reach the panel to undo a lockout.
        if fn != fn.lower() or not re.fullmatch(r'[a-z0-9_-]{3,32}', fn[:-5]):
            continue
        r, _ = read_record(fn, quiet=True)
        try:
            u = json.loads(r) if r is not None else None
        except ValueError:
            u = None
        if u is None:
            unreadable += 1
            continue
        if not isinstance(u, dict):
            continue
        # An unverified account cannot log in either — login returns the generic
        # "invalid username or password" — so it is not a safety net. This script
        # can itself create that situation: it grants admin to unverified accounts.
        # Nor is a disabled (banned) admin.
        if u.get('admin') is True and u.get('verified') is True and u.get('disabled') is not True:
            others += 1
    return others, unreadable

def check_preconditions(user):
    """Exit when there is nothing (allowed) to do. Run again once the lock is held."""
    if (user.get('admin') is True) == want:
        print(f"'{uname}' is already " + ("an admin" if want else "not an admin") + " — nothing to do.",
              file=sys.stderr)
        sys.exit(4)
    # Removing the last admin locks everyone out of the admin panel, and there is no
    # in-app way back in. Refuse unless the operator insists.
    if not want and os.environ['_FORCE'] != '1':
        others, unreadable = other_usable_admins()
        if others == 0:
            if unreadable:
                print(f"WARNING: {unreadable} account file(s) could not be read while checking for "
                      f"other admins — if you are not root, re-run with sudo.", file=sys.stderr)
            sys.exit(f"Refusing to remove the last admin ('{uname}') — nobody could reach the "
                     f"admin panel afterwards, and there is no in-app way to grant it back.\n"
                     f"Grant someone else admin first, or re-run with --force if you mean it.")

raw, st = read_record()
check_preconditions(parse(raw))      # a quick answer before waiting for the lock
lock = take_lock()
# Everything decided above is decided again now that no other writer can be half-way: the
# record as it is now, and the last-admin count (two revokes of the last two admins at once
# would otherwise both pass and leave none).
raw, st = read_record()
user = parse(raw)
check_preconditions(user)

# Atomic replace so a crash mid-write can never truncate the account file. Only the
# `admin` key is touched; every other field is written back exactly as read. Owner and
# mode come from the record being replaced (deploy-agnostic: native uses
# cryptirc:cryptirc, the Docker deploy has its own uid mapping).
#
# The running server rewrites whole records too (a login stamps last_login). A server that
# takes the account lock (see take_lock) can't be half-way through such a write now. One that
# doesn't (older than this script) is still checked for: immediately before the rename the
# record is read again, and if it changed since it was read (new bytes or a new inode — the
# server always renames a fresh file in), the flag is applied to the NEW record and the write
# is retried, so a ban, password change or other edit that landed meanwhile is never rolled
# back. The read-back after the rename stays as the last check.
for attempt in range(5):
    user['admin'] = want
    data = json.dumps(user, indent=2).encode()
    tmp = f".makeadmin-{secrets.token_hex(8)}"
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
    # Changed under us (a server that doesn't take the account lock): start over from the
    # record as it is now, deciding everything again.
    raw, st = now_raw, now_st
    user = parse(raw)
    check_preconditions(user)
else:
    sys.exit("This account kept changing while makeadmin.sh was writing it (the server is busy with "
             "it). Nothing was changed — re-run the command.")
# fsync the directory so the rename itself survives a power cut.
try:
    os.fsync(dfd)
except OSError:
    pass

# Read it back: a server write that read the record before our rename and lands after it
# would silently drop the flag.
back_raw, _ = read_record(quiet=True)
try:
    back = json.loads(back_raw) if back_raw is not None else None
except ValueError:
    back = None
if not isinstance(back, dict) or (back.get('admin') is True) != want:
    sys.exit("Wrote the change but it is not in the file — the server most likely "
             "rewrote this account at the same moment. Re-run the command.")

print(("Granted admin to '%s'." if want else "Removed admin from '%s'.") % uname, file=sys.stderr)
if want and user.get('disabled') is True:
    print("NOTE: this account is DISABLED by an admin, so it still cannot log in. Lift the ban "
          f"only if you mean to:  sudo ./resetpass.sh --enable {uname}  (or Enable login in the "
          "admin panel)", file=sys.stderr)
elif want and user.get('verified') is not True:
    print("NOTE: this account is UNVERIFIED, so it still cannot log in — login returns the "
          "generic 'Invalid username or password'. Fix it with:  sudo ./resetpass.sh --verify "
          f"{uname}", file=sys.stderr)
if not want and user.get('can_upload') is not True:
    print("NOTE: admin implied upload permission; this account can no longer upload. Grant it "
          "back from the admin panel if they still need it.", file=sys.stderr)
sys.exit(0 if want else 3)
PY

# 0 = granted, 3 = revoked, 4 = already in that state, anything else = failure.
case "$RC" in
    0)  echo >&2
        echo -e "  ${DIM}Takes effect immediately — the server re-reads the account file on every${NC}" >&2
        echo -e "  ${DIM}permission check, so there is nothing to restart. '$USERNAME' needs to reload${NC}" >&2
        echo -e "  ${DIM}their browser tab before Settings shows the Admin entry.${NC}" >&2 ;;
    3)  echo >&2
        echo -e "  ${DIM}Takes effect immediately. '$USERNAME' keeps the Admin entry on screen until${NC}" >&2
        echo -e "  ${DIM}they reload, but every admin action is refused from now on.${NC}" >&2 ;;
    4)  : ;;                 # no-op; python already said so
    *)  exit "$RC" ;;
esac
exit 0
