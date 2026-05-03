#!/usr/bin/env bash
# Add a CryptIRC user from the command line (pre-verified, no email needed)
# Usage: sudo bash adduser.sh <username> <email> <password>
set -euo pipefail

DATA_DIR="${CRYPTIRC_DATA:-/var/lib/cryptirc}"
USERNAME="${1:-}"
EMAIL="${2:-}"
PASSWORD="${3:-}"

if [[ -z "$USERNAME" || -z "$EMAIL" || -z "$PASSWORD" ]]; then
    echo "Usage: sudo bash adduser.sh <username> <email> <password>"
    echo "Example: sudo bash adduser.sh gh0st gh0st@example.com MySecurePass123"
    exit 1
fi

USERNAME=$(echo "$USERNAME" | tr '[:upper:]' '[:lower:]')
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
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=argon2.Type.ID)
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
