#!/usr/bin/env bash
# Add a CryptIRC user from the command line (pre-verified; email is optional)
# Usage: sudo CRYPTIRC_NEW_PASS=<password> bash adduser.sh <username> [email]
#   or:  sudo bash adduser.sh <username> <email> <password>   (email may be empty: "")
#
# Prefer the env form — a password passed as the 3rd argument is briefly visible
# to other local users via `ps` / /proc/<pid>/cmdline.
set -euo pipefail

DATA_DIR="${CRYPTIRC_DATA:-/var/lib/cryptirc}"
USERNAME="${1:-}"
EMAIL="${2:-}"
PASSWORD="${3:-${CRYPTIRC_NEW_PASS:-}}"

if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
    echo "Usage: sudo CRYPTIRC_NEW_PASS=<password> bash adduser.sh <username> [email]"
    echo "   or: sudo bash adduser.sh <username> <email> <password>   (email is optional — pass \"\" to skip)"
    echo "Example: sudo CRYPTIRC_NEW_PASS=MySecurePass123 bash adduser.sh gh0st"
    exit 1
fi

USERNAME=$(echo "$USERNAME" | tr '[:upper:]' '[:lower:]')

# Match the app's account rules (src/auth.rs register): 3-32 chars, [A-Za-z0-9_-].
# Skipping this would let us write an account the app can't manage — delete/disable/
# set-admin all reject it via is_safe_username() — i.e. an orphaned first admin.
if [[ ${#USERNAME} -lt 3 || ${#USERNAME} -gt 32 ]]; then
    echo "Error: Username must be 3-32 characters"
    exit 1
fi
if [[ ! "$USERNAME" =~ ^[a-z0-9_-]+$ ]]; then
    echo "Error: Username may only contain letters, numbers, underscore (_) and hyphen (-)"
    exit 1
fi
if [[ -n "$EMAIL" && ( "$EMAIL" != *"@"* || ${#EMAIL} -gt 254 || "$EMAIL" == *" "* ) ]]; then
    echo "Error: '$EMAIL' is not a valid email address (must contain @, no spaces) — or omit it to skip"
    exit 1
fi

USER_FILE="$DATA_DIR/users/${USERNAME}.json"

if [[ -f "$USER_FILE" ]]; then
    echo "Error: User '$USERNAME' already exists"
    exit 1
fi

if [[ ${#PASSWORD} -lt 10 ]]; then
    echo "Error: Password must be at least 10 characters"
    exit 1
fi

mkdir -p "$DATA_DIR/users"

# Hash password and write user JSON in one python call.
# All values passed via environment to avoid shell injection.
CREATED_AT=$(date +%s)
EMAIL_LOWER=$(echo "$EMAIL" | tr '[:upper:]' '[:lower:]')

_CRYPTIRC_PW="$PASSWORD" \
_U="$USERNAME" \
_E="$EMAIL_LOWER" \
_T="$CREATED_AT" \
_F="$USER_FILE" \
python3 -c "
import json, os
from argon2 import PasswordHasher
import argon2
# Params MUST match the app's Argon2::default() (m=19456 KiB, t=2, p=1, Argon2id).
# The login handler equalizes timing against a dummy hash computed with those same
# default params; heavier params here make these accounts verify measurably slower
# than the dummy, re-opening a username-enumeration timing oracle. Keep in lock-step
# with src/auth.rs and resetpass.sh.
ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, type=argon2.Type.ID)
pw_hash = ph.hash(os.environ['_CRYPTIRC_PW'])
data = {
    'username': os.environ['_U'],
    'email': os.environ['_E'],
    'password_hash': pw_hash,
    'verified': True,
    'created_at': int(os.environ['_T'])
}
with open(os.environ['_F'], 'w') as f:
    json.dump(data, f, indent=2)
"

chown cryptirc:cryptirc "$USER_FILE"
chmod 640 "$USER_FILE"

echo "User '$USERNAME' created and verified. They can log in immediately."
