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
#   sudo CRYPTIRC_NEW_PASS=<pass> ./resetpass.sh <username>   # non-interactive reset
#
# Why --verify exists: login returns the SAME generic "Invalid username or
# password" for a wrong password AND for an unverified account (deliberate
# anti-enumeration, src/auth.rs #56). Users who registered on an old client
# and never completed email verification therefore report "wrong pass" after
# updating. --check spots them; --verify (or any reset, which now also marks
# the account verified — see --keep-unverified) fixes them.
#
# The password is NEVER accepted as a positional argument — argv is readable by
# every local user via `ps`/`/proc/*/cmdline`. The env form is for scripts; the
# sudo line still lands in your shell history, so humans should use the prompt.
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
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

MODE=reset          # reset | verify | check
GENERATE=0
KEEP_UNVERIFIED=0
USERNAME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -g|--generate)        GENERATE=1; shift ;;
        --verify)             MODE=verify; shift ;;
        --check)              MODE=check; shift ;;
        -k|--keep-unverified) KEEP_UNVERIFIED=1; shift ;;
        -h|--help)            usage 0 ;;
        -*)                   echo "Error: unknown option '$1'" >&2; usage ;;
        *)
            if [[ -n "$USERNAME" ]]; then
                echo "Error: the password is no longer accepted as an argument (visible in \`ps\`)." >&2
                echo "Run without it to be prompted, or use CRYPTIRC_NEW_PASS / -g." >&2
                exit 1
            fi
            USERNAME="$1"; shift ;;
    esac
done

# Only --check may run without a username (scan-all mode).
if [[ -z "$USERNAME" && "$MODE" != check ]]; then
    usage
fi

if [[ -n "$USERNAME" ]]; then
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

# ─── --check: read-only diagnosis ───────────────────────────────────────────
if [[ "$MODE" == check ]]; then
    if [[ ! -d "$DATA_DIR/users" ]]; then
        echo "Error: no users directory at $DATA_DIR/users" >&2
        exit 1
    fi
    _D="$DATA_DIR" _U="$USERNAME" python3 - <<'PY'
import json, os, sys

data_dir = os.environ['_D']
target   = os.environ.get('_U') or None
users    = os.path.join(data_dir, 'users')
REQUIRED = ("username", "email", "password_hash", "verified", "created_at")
TUNED    = '$argon2id$v=19$m=65536,t=3,p=1$'

names = [f"{target}.json"] if target else sorted(
    f for f in os.listdir(users) if f.endswith('.json'))

broken = 0
for fn in names:
    uname, path = fn[:-5], os.path.join(users, fn)
    problems, notes = [], []

    if not os.path.isfile(path):
        # Point at case-mismatched files: login lowercases, so Foo.json is unreachable.
        cand = [f for f in os.listdir(users) if f.lower() == fn.lower()]
        hint = f" (found case-mismatched {cand[0]!r} — unreachable by login)" if cand else ""
        print(f"{uname}: NO ACCOUNT — no {fn} in {users}{hint}")
        broken += 1
        continue

    if fn != fn.lower():
        problems.append("uppercase filename — login lowercases, so this file is never found")

    try:
        u = json.load(open(path))
        if not isinstance(u, dict):
            raise ValueError("not a JSON object")
    except Exception as e:
        print(f"{uname}: BROKEN — corrupt JSON ({e}); login fails with the generic error")
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

    if u.get('verified') is not True:
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
        PASSWORD=$(python3 -c 'import secrets, string
print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24)))')
    elif [[ -n "${CRYPTIRC_NEW_PASS:-}" ]]; then
        PASSWORD="$CRYPTIRC_NEW_PASS"
    else
        if [[ ! -t 0 ]]; then
            echo "Error: stdin is not a terminal; set CRYPTIRC_NEW_PASS or use -g" >&2
            exit 1
        fi
        read -rs -p "New password for '$USERNAME': " PASSWORD; echo >&2
        read -rs -p "Confirm password: " PASSWORD2; echo >&2
        if [[ "$PASSWORD" != "$PASSWORD2" ]]; then
            echo "Error: passwords do not match" >&2
            exit 1
        fi
    fi

    # Match src/auth.rs (register / change_password): minimum 10 chars.
    if [[ ${#PASSWORD} -lt 10 ]]; then
        echo "Error: password must be at least 10 characters" >&2
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
_MODE="$MODE" \
_CRYPTIRC_PW="$PASSWORD" \
_KEEP="$KEEP_UNVERIFIED" \
_F="$USER_FILE" \
python3 - <<'PY'
import json, os, sys, tempfile

mode = os.environ['_MODE']
path = os.environ['_F']

with open(path) as f:
    user = json.load(f)
if not isinstance(user, dict) or 'password_hash' not in user:
    sys.exit(f"{path} does not look like a CryptIRC user record; aborting")

was_unverified = user.get('verified') is not True

if mode == 'reset':
    from argon2 import PasswordHasher
    from argon2.low_level import Type
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1,
                        hash_len=32, salt_len=16, type=Type.ID)
    pw_hash = ph.hash(os.environ['_CRYPTIRC_PW'])
    # Self-check: refuse to write anything but the expected tuned-params format.
    if not pw_hash.startswith('$argon2id$v=19$m=65536,t=3,p=1$'):
        sys.exit(f"refusing to write hash with unexpected params: {pw_hash[:32]}...")
    user['password_hash'] = pw_hash
elif not was_unverified:
    sys.exit("Nothing to do: account is already verified, and --verify does not change "
             "the password. If they still can't log in, run --check and see what it says.")

if os.environ['_KEEP'] != '1':
    user['verified'] = True

# Atomic replace so a crash mid-write can never truncate the account file.
# Ownership and mode are preserved from the original (deploy-agnostic: native
# uses cryptirc:cryptirc, the Docker deploy has its own uid mapping).
st = os.stat(path)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.pwreset-')
try:
    with os.fdopen(fd, 'w') as f:
        json.dump(user, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, st.st_mode & 0o7777)
    if os.geteuid() == 0:
        os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, path)
except BaseException:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    raise

if was_unverified:
    if os.environ['_KEEP'] == '1':
        print("NOTE: account is UNVERIFIED and was left that way (--keep-unverified) — "
              "login will STILL say 'Invalid username or password'.")
    else:
        print("NOTE: account was UNVERIFIED — that is why login said 'Invalid username "
              "or password' even with the correct password. Marked verified.")
PY

if [[ "$MODE" == verify ]]; then
    echo -e "  ${GREEN}✓${NC} Account ${BOLD}$USERNAME${NC} marked verified — password unchanged; they can" >&2
    echo -e "    log in with the password they already know." >&2
else
    echo -e "  ${GREEN}✓${NC} Password reset for ${BOLD}$USERNAME${NC}." >&2
    if [[ $GENERATE -eq 1 ]]; then
        echo -e "  ${YELLOW}Generated password${NC} ${DIM}(shown once, stored nowhere else)${NC}:" >&2
        printf '  %s\n' "$PASSWORD"
    fi
fi
echo >&2
echo -e "  ${DIM}Sessions live in the web daemon's memory — anyone already logged in as${NC}" >&2
echo -e "  ${DIM}'$USERNAME' stays logged in until their session idles out or the service is${NC}" >&2
echo -e "  ${DIM}restarted (sudo systemctl restart cryptirc — that drops ALL users' sessions).${NC}" >&2
