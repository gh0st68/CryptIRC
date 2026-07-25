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
    USERNAME=$(printf '%s' "$USERNAME" | tr '[:upper:]' '[:lower:]')
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
import json, os, sys

users = os.path.join(os.environ['_D'], 'users')
rows, admins, unreadable = [], 0, 0
for fn in sorted(f for f in os.listdir(users) if f.endswith('.json')):
    path = os.path.join(users, fn)
    try:
        u = json.load(open(path))
        if not isinstance(u, dict):
            raise ValueError('not a JSON object')
    except Exception as e:
        rows.append((fn[:-5], '?', f'unreadable ({e})'))
        unreadable += 1
        continue
    is_admin = u.get('admin') is True
    admins += is_admin
    notes = []
    if u.get('verified') is not True:
        notes.append('UNVERIFIED — cannot log in')
    if u.get('disabled') is True:
        notes.append('disabled')
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
import json, os, re, sys, tempfile

mode  = os.environ['_MODE']
path  = os.environ['_F']
uname = os.environ['_U']
want  = (mode == 'grant')

try:
    with open(path) as f:
        user = json.load(f)
except PermissionError:
    sys.exit(f"Cannot read {path} — re-run with sudo.")
except json.JSONDecodeError as e:
    sys.exit(f"{path} is not valid JSON ({e}); refusing to touch it.")
# Same shape check resetpass.sh uses: refuse to rewrite anything that isn't
# recognisably a CryptIRC account record.
if not isinstance(user, dict) or 'password_hash' not in user:
    sys.exit(f"{path} does not look like a CryptIRC user record; aborting")

current = user.get('admin') is True
if current == want:
    print(f"'{uname}' is already " + ("an admin" if want else "not an admin") + " — nothing to do.",
          file=sys.stderr)
    sys.exit(4)

# Removing the last admin locks everyone out of the admin panel, and there is no
# in-app way back in. Refuse unless the operator insists.
if not want and os.environ['_FORCE'] != '1':
    users_dir = os.path.join(os.environ['_DIR'], 'users')
    others, unreadable = 0, 0
    for fn in os.listdir(users_dir):
        if not fn.endswith('.json') or fn[:-5] == uname:
            continue
        # Only an admin who could actually SIGN IN counts as the safety net.
        # Skipped: uppercase filenames (login lowercases, so the file is never
        # found) and stems that fail is_safe_username() in src/auth.rs. Both look
        # like admins on disk but can never reach the panel to undo a lockout.
        if fn != fn.lower() or not re.fullmatch(r'[a-z0-9_-]{3,32}', fn[:-5]):
            continue
        try:
            u = json.load(open(os.path.join(users_dir, fn)))
        except Exception:
            unreadable += 1
            continue
        if not isinstance(u, dict):
            continue
        # An unverified account cannot log in either — login returns the generic
        # "invalid username or password" — so it is not a safety net. This script
        # can itself create that situation: it grants admin to unverified accounts.
        if u.get('admin') is True and u.get('verified') is True:
            others += 1
    if others == 0:
        if unreadable:
            print(f"WARNING: {unreadable} account file(s) could not be read while checking for "
                  f"other admins — if you are not root, re-run with sudo.", file=sys.stderr)
        sys.exit(f"Refusing to remove the last admin ('{uname}') — nobody could reach the "
                 f"admin panel afterwards, and there is no in-app way to grant it back.\n"
                 f"Grant someone else admin first, or re-run with --force if you mean it.")

user['admin'] = want

# Atomic replace so a crash mid-write can never truncate the account file.
# Ownership and mode are preserved from the original (deploy-agnostic: native
# uses cryptirc:cryptirc, the Docker deploy has its own uid mapping).
st = os.stat(path)
d = os.path.dirname(path)
try:
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.makeadmin-')
except PermissionError:
    sys.exit(f"Cannot write to {d} — re-run with sudo.")
try:
    with os.fdopen(fd, 'w') as f:
        json.dump(user, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    # chown first: it clears setuid/setgid, so chmod must come after it.
    if os.geteuid() == 0:
        os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, path)
    # fsync the directory so the rename itself survives a power cut.
    try:
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
except BaseException:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    raise

# The running server serializes its own writes under a per-user lock that an
# outside process cannot take. If it happened to rewrite this record between our
# read and our replace, our change is the one that survives — but the reverse
# (its write landing after ours) would silently drop the flag. Read it back.
try:
    with open(path) as f:
        if json.load(f).get('admin') is not want:
            sys.exit("Wrote the change but it is not in the file — the server most likely "
                     "rewrote this account at the same moment. Re-run the command.")
except OSError:
    pass

print(("Granted admin to '%s'." if want else "Removed admin from '%s'.") % uname, file=sys.stderr)
if want and user.get('verified') is not True:
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
