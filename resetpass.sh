#!/usr/bin/env bash
# Reset a CryptIRC user's password from the command line.
#
# Usage:
#   sudo ./resetpass.sh <username>                    # prompts twice, input hidden (preferred)
#   sudo ./resetpass.sh -g <username>                 # generate a strong random password, print once
#   sudo CRYPTIRC_NEW_PASS=<pass> ./resetpass.sh <username>   # non-interactive, for automation
#
# The password is NEVER accepted as a positional argument — argv is readable by
# every local user via `ps`/`/proc/*/cmdline`. The env form is for scripts; the
# sudo line still lands in your shell history, so humans should use the prompt.
#
# CRYPTIRC_DATA overrides the data dir (default /var/lib/cryptirc) — used by the
# Docker deploy and the test harness.
set -euo pipefail

DATA_DIR="${CRYPTIRC_DATA:-/var/lib/cryptirc}"

usage() {
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

GENERATE=0
USERNAME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -g|--generate) GENERATE=1; shift ;;
        -h|--help)     usage 0 ;;
        -*)            echo "Error: unknown option '$1'" >&2; usage ;;
        *)
            if [[ -n "$USERNAME" ]]; then
                echo "Error: the password is no longer accepted as an argument (visible in \`ps\`)." >&2
                echo "Run without it to be prompted, or use CRYPTIRC_NEW_PASS / -g." >&2
                exit 1
            fi
            USERNAME="$1"; shift ;;
    esac
done

[[ -n "$USERNAME" ]] || usage

USERNAME=$(printf '%s' "$USERNAME" | tr '[:upper:]' '[:lower:]')

# Mirror src/auth.rs is_safe_username(): [a-z0-9_-], 3-32 chars (post-lowercase).
# Rejecting anything else is also what makes the path join below traversal-safe.
if [[ ! "$USERNAME" =~ ^[a-z0-9_-]{3,32}$ ]]; then
    echo "Error: invalid username (3-32 chars; letters, numbers, _ and - only)" >&2
    exit 1
fi

USER_FILE="$DATA_DIR/users/${USERNAME}.json"
if [[ ! -f "$USER_FILE" ]]; then
    echo "Error: user '$USERNAME' not found (no $USER_FILE)" >&2
    exit 1
fi

# ─── Obtain the new password ────────────────────────────────────────────────
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

# ─── Hash and atomically rewrite the user record ────────────────────────────
# Argon2id params MUST stay in lock-step with tuned_argon2() in src/auth.rs
# (m=65536 KiB, t=3, p=1, 32-byte hash, v=19). The login handler equalizes
# timing against a dummy hash computed with those same params, so drifting here
# re-opens a username-enumeration timing oracle — and lighter params weaken the
# stored hash. There is no rehash-on-login: whatever we write stays until the
# user's next password change.
_CRYPTIRC_PW="$PASSWORD" \
_F="$USER_FILE" \
python3 - <<'PY'
import json, os, sys, tempfile
from argon2 import PasswordHasher
from argon2.low_level import Type

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1,
                    hash_len=32, salt_len=16, type=Type.ID)
pw_hash = ph.hash(os.environ['_CRYPTIRC_PW'])

# Self-check: refuse to write anything but the expected tuned-params format.
if not pw_hash.startswith('$argon2id$v=19$m=65536,t=3,p=1$'):
    sys.exit(f"refusing to write hash with unexpected params: {pw_hash[:32]}...")

path = os.environ['_F']
with open(path) as f:
    user = json.load(f)
if not isinstance(user, dict) or 'password_hash' not in user:
    sys.exit(f"{path} does not look like a CryptIRC user record; aborting")
user['password_hash'] = pw_hash

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
PY

echo "Password reset for '$USERNAME'."
if [[ $GENERATE -eq 1 ]]; then
    echo "Generated password (shown once, stored nowhere else):"
    printf '  %s\n' "$PASSWORD"
fi
echo
echo "Note: sessions live in the web daemon's memory — anyone already logged in as"
echo "'$USERNAME' stays logged in until their session idles out or the service is"
echo "restarted (sudo systemctl restart cryptirc — that drops ALL users' sessions)."
