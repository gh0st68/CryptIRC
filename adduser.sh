#!/usr/bin/env bash
# Add a CryptIRC user from the command line (pre-verified, no email needed)
# Usage: sudo bash adduser.sh <username> <email> <password>
set -euo pipefail

DATA_DIR="/var/lib/cryptirc"
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

# Hash password with Argon2id (same format as Rust argon2 crate)
HASH=$(python3 -c "
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=argon2.Type.ID)
print(ph.hash('$PASSWORD'))
")

CREATED_AT=$(date +%s)

cat > "$USER_FILE" << EOF
{
  "username": "$USERNAME",
  "email": "$(echo "$EMAIL" | tr '[:upper:]' '[:lower:]')",
  "password_hash": "$HASH",
  "verified": true,
  "created_at": $CREATED_AT
}
EOF

chown cryptirc:cryptirc "$USER_FILE"
chmod 640 "$USER_FILE"

echo "User '$USERNAME' created and verified. They can log in immediately."
