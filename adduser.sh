#!/usr/bin/env bash
# Add a CryptIRC user from the command line (pre-verified; email is optional)
#
# Usage:
#   sudo bash adduser.sh <username> [email]
#       prompts for the password twice (input hidden)
#   printf '%s\n' "$PW" | sudo bash adduser.sh --password-stdin <username> [email]
#       for scripts: the password is the first line on stdin
#   sudo bash adduser.sh -- <-name> [email]
#       a username that starts with '-' goes after --
#
# The password is never taken from the command line or from sudo's environment:
# `sudo VAR=pw cmd` puts "VAR=pw" in sudo's own argv — readable by every local user
# via ps / /proc/<pid>/cmdline — and sudo writes it to the auth log. The old forms
# (CRYPTIRC_NEW_PASS=... or a 3rd argument) still work for now, but print a
# deprecation warning.
#
# Same rules as signing up in the app (src/auth.rs register): username 3-32 chars
# of a-z 0-9 _ - ; the email (if any) not already used by another account; a
# password of 10-1024 bytes with upper case, lower case, a digit and a symbol.
#
# CRYPTIRC_DATA overrides the data dir (default /var/lib/cryptirc).
set -euo pipefail

DATA_DIR="${CRYPTIRC_DATA:-/var/lib/cryptirc}"

usage() {
    sed -n '4,10p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit "${1:-1}"
}

PW_STDIN=0
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --password-stdin) PW_STDIN=1; shift ;;
        -h|--help)        usage 0 ;;
        --)               shift; ARGS+=("$@"); break ;;
        -*)               echo "Error: unknown option '$1' (a username that starts with '-' goes after --: adduser.sh -- $1)" >&2
                          usage ;;
        *)                ARGS+=("$1"); shift ;;
    esac
done
if [[ ${#ARGS[@]} -lt 1 || ${#ARGS[@]} -gt 3 ]]; then
    usage
fi
USERNAME="${ARGS[0]}"
EMAIL="${ARGS[1]:-}"

# ── The password: stdin, prompt, or (deprecated) env / 3rd argument ─────────
PASSWORD=""
if [[ ${#ARGS[@]} -eq 3 ]]; then
    if [[ $PW_STDIN -eq 1 ]]; then
        echo "Error: give the password one way — --password-stdin or the 3rd argument, not both" >&2
        exit 1
    fi
    echo "WARNING: passing the password as an argument is deprecated — it is visible to every local user in ps." >&2
    echo "         Use: sudo bash adduser.sh <username> [email]   (prompts), or --password-stdin." >&2
    PASSWORD="${ARGS[2]}"
elif [[ $PW_STDIN -eq 1 ]]; then
    [[ -n "${CRYPTIRC_NEW_PASS:-}" ]] && echo "Note: --password-stdin given; ignoring CRYPTIRC_NEW_PASS." >&2
    IFS= read -r PASSWORD || [[ -n "$PASSWORD" ]] || { echo "Error: --password-stdin: nothing on stdin" >&2; exit 1; }
    PASSWORD="${PASSWORD%$'\r'}"
elif [[ -n "${CRYPTIRC_NEW_PASS:-}" ]]; then
    echo "WARNING: CRYPTIRC_NEW_PASS is deprecated — 'sudo CRYPTIRC_NEW_PASS=... bash adduser.sh' shows the" >&2
    echo "         password to every local user (ps) and in sudo's log. Use the prompt or --password-stdin." >&2
    PASSWORD="$CRYPTIRC_NEW_PASS"
elif [[ -t 0 ]]; then
    read -rs -p "Password for the new account: " PASSWORD; echo >&2
    read -rs -p "Confirm password: " PASSWORD2; echo >&2
    if [[ "$PASSWORD" != "$PASSWORD2" ]]; then
        echo "Error: passwords do not match" >&2
        exit 1
    fi
    unset PASSWORD2
else
    echo "Error: no password given and stdin is not a terminal." >&2
    printf '%s\n' "For scripts: printf '%s\\n' \"\$PW\" | sudo bash adduser.sh --password-stdin <username> [email]" >&2
    exit 1
fi
if [[ -z "$PASSWORD" ]]; then
    echo "Error: the password is empty" >&2
    exit 1
fi

USERNAME=$(printf '%s' "$USERNAME" | LC_ALL=C tr '[:upper:]' '[:lower:]')

# Match the app's account rules (src/auth.rs register / is_safe_username): 3-32 bytes of
# ASCII [a-z0-9_-]. Skipping this would write an account the app can't manage — delete/
# disable/set-admin all reject it via is_safe_username() — i.e. an orphaned first admin.
# LC_ALL=C matters: under a UTF-8 locale glibc's collation makes [a-z] match accented and
# fullwidth letters ('alícé', 'ａｂｃ'), which the app can never create or manage.
if ! LC_ALL=C bash -c '[[ "$1" =~ ^[a-z0-9_-]{3,32}$ ]]' _ "$USERNAME"; then
    echo "Error: invalid username (3-32 characters; only a-z, 0-9, underscore (_) and hyphen (-))" >&2
    exit 1
fi

if [[ ! -d "$DATA_DIR" ]]; then
    echo "Error: no data directory at $DATA_DIR (is CryptIRC installed? set CRYPTIRC_DATA if it lives elsewhere)" >&2
    exit 1
fi

# Everything else — email + password policy, the duplicate-email scan and the write —
# happens in one python call. The password goes in on stdin (never argv or env).
# -I-ish hardening: the code drops '' (the cwd) from sys.path before importing anything,
# so a json.py/argon2.py lying in the directory sudo was run from can't be imported as root.
RC=0
# shellcheck disable=SC2016  # the single-quoted python program is not meant to expand
printf '%s\n' "$PASSWORD" | _D="$DATA_DIR" _U="$USERNAME" _E="$EMAIL" python3 -c '
import sys
sys.path[:] = [p for p in sys.path if p not in ("", ".")]
import errno, fcntl, json, os, secrets, signal, stat, time

def die(msg, rc=1):
    print("Error: " + msg, file=sys.stderr)
    sys.exit(rc)

data_dir, uname = os.environ["_D"], os.environ["_U"]
email = os.environ["_E"].strip().lower()   # register(): email.trim().to_lowercase()
try:
    pw = sys.stdin.buffer.readline().rstrip(b"\n").decode("utf-8")
except UnicodeDecodeError:
    die("the password is not valid UTF-8")

# ── Email: same checks as src/auth.rs register + email::validate_email ──
if email:
    if (len(email) > 254 or email.count("@") != 1 or any(c.isspace() or ord(c) < 32 or ord(c) == 127
            or c in ",;" for c in email) or not all(email.split("@"))):
        die(f"{email!r} is not a valid email address — or omit it to create an account with no email")

# ── Password: same policy as register / change_password / reset_password ──
b = pw.encode("utf-8")
if len(b) < 10:
    die("password must be at least 10 characters")
if len(b) > 1024:
    die("password is too long (max 1024 characters)")
if not (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
        and any(c in "0123456789" for c in pw) and any(not c.isalnum() for c in pw)):
    die("password must contain uppercase, lowercase, number, and special character")

# ── The users dir, opened without following a symlink ──
# users/ lives in the data dir the unprivileged service account owns, so a compromised
# service could plant symlinks there. Every operation below is relative to this fd and
# uses O_NOFOLLOW / O_EXCL: no path we touch can be redirected at a root-owned file.
users_path = os.path.join(data_dir, "users")
try:
    dfd = os.open(users_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except FileNotFoundError:
    # Server never started yet: create it the way the server does (0700, owned like the data dir).
    os.mkdir(users_path, 0o700)
    st = os.stat(data_dir)
    if os.geteuid() == 0:
        os.chown(users_path, st.st_uid, st.st_gid, follow_symlinks=False)
    dfd = os.open(users_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as e:
    die(f"cannot open {users_path} ({e.strerror}) — it must be a real directory, not a symlink")
dst = os.fstat(dfd)

def read_json(name, dir_fd):
    """Read a small regular file without following symlinks; None if it is not one."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 1 << 20:
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            return json.loads(f.read())
    except (OSError, ValueError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)

target = uname + ".json"

def check_free():
    """Exit unless the username and the email are still free (mirrors AuthManager::register /
    email_in_use). Checked once for a quick answer, and again under the account lock."""
    try:
        os.stat(target, dir_fd=dfd, follow_symlinks=False)
        die(f"user {uname!r} already exists")
    except FileNotFoundError:
        pass
    if not email:
        return
    # One account per email: login-by-email and password reset resolve an email to ONE account
    # and assume register() kept it unique; a second account on the same email made them pick
    # by readdir order.
    for fn in os.listdir(dfd):
        if fn.endswith(".json"):
            u = read_json(fn, dfd)
            if isinstance(u, dict) and u.get("email") == email:
                die(f"that email is already used by account {fn[:-5]!r} (one account per email)")
    # In-flight sign-ups waiting for email verification count too, unless orphaned (their
    # account was deleted, or now has another email). Fail closed like the server does.
    try:
        pfd = os.open(os.path.join(data_dir, "pending"), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        pfd = None
    if pfd is not None:
        now = int(time.time())
        for fn in os.listdir(pfd):
            p = read_json(fn, pfd)
            if not isinstance(p, dict) or p.get("email") != email:
                continue
            if not isinstance(p.get("expires_at"), int) or p["expires_at"] < now:
                continue
            owner = str(p.get("username", ""))
            try:
                os.stat(owner + ".json", dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                continue        # orphan: the account is gone
            except OSError:
                die("that email has a pending sign-up (could not check it — refusing)")
            u = read_json(owner + ".json", dfd)
            if not isinstance(u, dict) or u.get("email") == email:
                die(f"that email has a pending sign-up for account {owner!r} (one account per email)")
        os.close(pfd)

lock_fail = die
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

check_free()            # a quick answer before the slow hash

# ── Hash: params MUST stay in lock-step with tuned_argon2() in src/auth.rs ──
# (m=65536 KiB, t=3, p=1, 32-byte hash, Argon2id v=19). The login handler equalizes
# timing against a dummy hash computed with those same params; drifting here re-opens
# a username-enumeration timing oracle, and lighter params weaken the stored hash.
# Same params in resetpass.sh.
try:
    from argon2 import PasswordHasher
    from argon2.low_level import Type
except ImportError:
    die("the Python argon2-cffi package is missing — install it: sudo apt-get install python3-argon2 "
        "(Arch: sudo pacman -S python-argon2-cffi)")
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16, type=Type.ID)
pw_hash = ph.hash(pw)
if not pw_hash.startswith("$argon2id$v=19$m=65536,t=3,p=1$"):
    die(f"refusing to write a hash with unexpected params: {pw_hash[:32]}...")
record = json.dumps({
    "username": uname,
    "email": email,
    "password_hash": pw_hash,
    "verified": True,
    "created_at": int(time.time()),
}, indent=2).encode()

# The hash is done; only now take the lock (held for milliseconds, not the whole Argon2 run)
# and check again — the email scan and the link() below then happen with no sign-up or other
# script able to claim that name or email in between.
lock = take_lock()
check_free()

# ── Write: temp file (O_EXCL|O_NOFOLLOW) → fsync → link() into place ──
# link() never follows or replaces anything at the target name: if <name>.json appeared
# meanwhile (the server registered it, or a symlink was planted) it fails with EEXIST.
# Owner = the users dir owner (the service account), mode 0600 like the server writes.
tmp = f".adduser-{secrets.token_hex(8)}.tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
try:
    if os.geteuid() == 0:
        os.fchown(fd, dst.st_uid, dst.st_gid)
    os.fchmod(fd, 0o600)
    view = memoryview(record)
    while view:
        view = view[os.write(fd, view):]
    os.fsync(fd)
    os.close(fd)
    fd = -1
    try:
        os.link(tmp, target, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
    except FileExistsError:
        die(f"user {uname!r} already exists")
    except OSError as e:
        if e.errno not in (errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP):
            raise
        # Filesystem without hard links: exclusive create of the final name instead.
        ffd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            if os.geteuid() == 0:
                os.fchown(ffd, dst.st_uid, dst.st_gid)
            os.fchmod(ffd, 0o600)
            os.write(ffd, record)
            os.fsync(ffd)
        finally:
            os.close(ffd)
    os.fsync(dfd)
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(tmp, dir_fd=dfd)
    except FileNotFoundError:
        pass
' || RC=$?
unset PASSWORD
[[ $RC -eq 0 ]] || exit "$RC"

echo "User '$USERNAME' created and verified. They can log in immediately."
