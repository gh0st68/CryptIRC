#!/usr/bin/env bash
# Reset a CryptIRC user's password from the command line
# Usage: sudo bash resetpass.sh <username> <new_password>
set -euo pipefail

DATA_DIR="${CRYPTIRC_DATA:-/var/lib/cryptirc}"
USERNAME="${1:-}"
PASSWORD="${2:-}"

if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
    echo "Usage: sudo bash resetpass.sh <username> <new_password>"
    echo "Example: sudo bash resetpass.sh gh0st NewSecurePass123"
    exit 1
fi

USERNAME=$(echo "$USERNAME" | tr '[:upper:]' '[:lower:]')
USER_FILE="$DATA_DIR/users/${USERNAME}.json"

if [[ ! -f "$USER_FILE" ]]; then
    echo "Error: User '$USERNAME' not found"
    exit 1
fi

if [[ ${#PASSWORD} -lt 10 ]]; then
    echo "Error: Password must be at least 10 characters"
    exit 1
fi

# Hash password and update user JSON in one python call.
# All values passed via environment to avoid shell injection.
_CRYPTIRC_PW="$PASSWORD" \
_F="$USER_FILE" \
python3 -c "
import json, os
from argon2 import PasswordHasher
import argon2
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=argon2.Type.ID)
pw_hash = ph.hash(os.environ['_CRYPTIRC_PW'])
path = os.environ['_F']
with open(path, 'r') as f:
    user = json.load(f)
user['password_hash'] = pw_hash
with open(path, 'w') as f:
    json.dump(user, f, indent=2)
"

chown cryptirc:cryptirc "$USER_FILE"
chmod 640 "$USER_FILE"

echo "Password reset for '$USERNAME'. They can log in with the new password."
