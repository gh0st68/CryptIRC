#!/usr/bin/env bash
# Exercise makeadmin.sh against a throwaway fixture data dir. Never touches
# a real install — every invocation sets CRYPTIRC_DATA to a temp directory.
#
# Run: bash scripts/test-makeadmin.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/makeadmin.sh"
ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT" "$OUTSIDE"' EXIT
OUTSIDE="$(mktemp)"
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n     %s\n' "$1" "${2:-}"; }
check(){ if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got [$2] want [$3]"; fi; }

mkuser() { # mkuser <name> <admin> [verified] [extra-json]
  local n=$1 a=$2 v=${3:-true} extra=${4:-}
  python3 - "$ROOT/users/$n.json" "$n" "$a" "$v" "$extra" <<'PY'
import json,sys
path,name,admin,verified,extra=sys.argv[1:6]
u={"username":name,"email":f"{name}@example.com",
   "password_hash":"$argon2id$v=19$m=65536,t=3,p=1$abcdefghijklmnop$0123456789abcdef",
   "verified":verified=="true","created_at":1700000000,
   "admin":admin=="true","can_upload":False,"last_login":0,
   "lastfm_user":"","lastfm_key":""}
if extra: u.update(json.loads(extra))
json.dump(u,open(path,'w'),indent=2)
PY
}
isadmin(){ python3 -c "import json;print(str(json.load(open('$ROOT/users/$1.json')).get('admin')).lower())" 2>/dev/null; }
reset()  { rm -rf "$ROOT"; mkdir -p "$ROOT/users"; }

run(){ CRYPTIRC_DATA="$ROOT" bash "$SCRIPT" "$@" 2>&1; }
rc(){  CRYPTIRC_DATA="$ROOT" bash "$SCRIPT" "$@" >/dev/null 2>&1; echo $?; }

echo "── grant / idempotency ──────────────────────────────────────────────"
reset; mkuser alice false
out=$(run alice); check "grant sets admin=true" "$(isadmin alice)" "true"
[[ "$out" == *"Granted admin to 'alice'"* ]] && ok "grant reports success" || bad "grant reports success" "$out"
out=$(run alice); check "second grant leaves it true" "$(isadmin alice)" "true"
[[ "$out" == *"already an admin"* ]] && ok "second grant is idempotent" || bad "second grant is idempotent" "$out"
check "idempotent grant exits 0" "$(rc alice)" "0"

echo "── every other field survives the rewrite ───────────────────────────"
reset; mkuser bob false true '{"can_upload":true,"lastfm_user":"bobby","custom_future_field":42}'
before=$(python3 -c "import json;d=json.load(open('$ROOT/users/bob.json'));d.pop('admin');print(json.dumps(d,sort_keys=True))")
run bob >/dev/null
after=$(python3 -c "import json;d=json.load(open('$ROOT/users/bob.json'));d.pop('admin');print(json.dumps(d,sort_keys=True))")
check "non-admin fields byte-identical" "$after" "$before"
check "unknown future field preserved" "$(python3 -c "import json;print(json.load(open('$ROOT/users/bob.json')).get('custom_future_field'))")" "42"

echo "── revoke + last-admin guard ────────────────────────────────────────"
reset; mkuser alice true; mkuser bob true
run --revoke alice >/dev/null; check "revoke with another admin present" "$(isadmin alice)" "false"
out=$(run --revoke bob); check "last admin NOT revoked" "$(isadmin bob)" "true"
[[ "$out" == *"Refusing to remove the last admin"* ]] && ok "last-admin refusal explains why" || bad "last-admin refusal" "$out"
check "refusal exits non-zero" "$(rc --revoke bob)" "1"
run --revoke bob --force >/dev/null; check "--force overrides the guard" "$(isadmin bob)" "false"
reset; mkuser solo false
check "revoking a non-admin is a no-op, exit 0" "$(rc --revoke solo)" "0"
# An admin whose file is uppercase can never log in (login lowercases), so it
# must not count as the remaining admin that keeps you out of a lockout.
reset; mkuser alice true; mkuser bob true; mv "$ROOT/users/bob.json" "$ROOT/users/BOB.json"
out=$(run --revoke alice)
check "uppercase admin file does not satisfy the guard" "$(isadmin alice)" "true"
[[ "$out" == *"Refusing to remove the last admin"* ]] && ok "guard ignores unreachable uppercase admin" || bad "guard vs uppercase admin" "$out"

echo "── guard only counts admins who could actually log in ───────────────"
# An unverified admin cannot log in (login returns the generic error), so it is
# not a safety net — and this script will happily create that situation.
reset; mkuser alice true; mkuser ghost true false
out=$(run --revoke alice)
check "unverified admin does not satisfy the guard" "$(isadmin alice)" "true"
[[ "$out" == *"Refusing to remove the last admin"* ]] && ok "guard ignores unverified admin" || bad "guard vs unverified admin" "$out"
# A filename that fails is_safe_username() is unreachable by login too.
reset; mkuser alice true; mkuser xy true 2>/dev/null || true
python3 -c "
import json,sys
json.dump({'username':'xy','email':'','password_hash':'x','verified':True,'created_at':1,'admin':True},
          open('$ROOT/users/xy.json','w'))"
out=$(run --revoke alice)
check "too-short-named admin does not satisfy the guard" "$(isadmin alice)" "true"
[[ "$out" == *"Refusing to remove the last admin"* ]] && ok "guard ignores unusable short name" || bad "guard vs short name" "$out"
# ...but a genuinely usable second admin still does.
reset; mkuser alice true; mkuser bob true
run --revoke alice >/dev/null; check "a real second admin does satisfy the guard" "$(isadmin alice)" "false"

echo "── stdout carries only the result ───────────────────────────────────"
reset; mkuser alice false
sout=$(CRYPTIRC_DATA="$ROOT" bash "$SCRIPT" alice 2>/dev/null)
check "grant prints nothing to stdout" "$sout" ""
reset; mkuser alice true; mkuser bob true
sout=$(CRYPTIRC_DATA="$ROOT" bash "$SCRIPT" --revoke alice 2>/dev/null)
check "revoke prints nothing to stdout" "$sout" ""
reset; mkuser alice true
sout=$(CRYPTIRC_DATA="$ROOT" bash "$SCRIPT" --list 2>/dev/null)
[[ "$sout" == *"alice"* ]] && ok "--list roster goes to stdout (it is the result)" || bad "--list stdout" "$sout"

echo "── exit codes ───────────────────────────────────────────────────────"
reset; mkuser alice false
check "grant exits 0"                       "$(rc alice)" "0"
check "re-running a grant still exits 0"    "$(rc alice)" "0"
reset; mkuser alice true; mkuser bob true
check "revoke exits 0"                      "$(rc --revoke alice)" "0"
# The trailing advice must match what actually happened.
reset; mkuser alice false
out=$(run alice)
[[ "$out" == *"needs to reload"* ]] && ok "grant tells them to reload" || bad "grant note" "$out"
reset; mkuser alice true; mkuser bob true
out=$(run --revoke alice)
[[ "$out" == *"every admin action is refused"* ]] && ok "revoke note is about losing access" || bad "revoke note" "$out"
reset; mkuser alice true
out=$(run alice)
[[ "$out" != *"needs to reload"* ]] && ok "no-op does not print reload advice" || bad "no-op note" "$out"

echo "── leading-hyphen usernames (legal per is_safe_username) ────────────"
reset
python3 -c "
import json
json.dump({'username':'-test','email':'','password_hash':'x','verified':True,'created_at':1,'admin':False},
          open('$ROOT/users/-test.json','w'))"
run -- -test >/dev/null
check "'-test' can be granted via --" "$(python3 -c "
import json;print(str(json.load(open('$ROOT/users/-test.json'))['admin']).lower())")" "true"
check "bare -test is still rejected as an option" "$(rc -test)" "1"

echo "── conflicting flags are refused, not silently obeyed ───────────────"
reset; mkuser alice true; mkuser bob true
check "--list --revoke is refused"  "$(rc --list --revoke alice)" "1"
check "  ...and performed nothing"  "$(isadmin alice)" "true"
check "--force without --revoke is refused" "$(rc --force alice)" "1"

echo "── username validation / traversal ──────────────────────────────────"
reset; mkuser alice false
echo '{"pwn":1}' > "$OUTSIDE"
# NOTE: assert on the message, not the exit code — exit 1 also means "user not
# found", which previously let a locale-dependent regex pass as if it rejected
# non-ASCII names when it actually accepted them.
for bad_name in "../..${OUTSIDE%.*}" "ab" "$(printf 'a%.0s' {1..33})" "al ice" "alice;rm" "al/ice" \
                "alícé" "ａｂｃ" "." ".." "$(printf 'a\tb')" "a\$(id)b"; do
  out=$(run -- "$bad_name")
  if [[ "$out" == *"invalid username"* ]]; then ok "rejects '$bad_name' as invalid"
  else bad "rejects '$bad_name' as invalid" "$out"; fi
done
check "outside file untouched by traversal attempt" "$(cat "$OUTSIDE")" '{"pwn":1}'
run ALICE >/dev/null; check "uppercase input is lowercased" "$(isadmin alice)" "true"

echo "── missing / malformed accounts ─────────────────────────────────────"
reset; mkuser alice false
out=$(run nosuchuser); check "missing user exits 1" "$(rc nosuchuser)" "1"
[[ "$out" == *"not found"* && "$out" == *"--list"* ]] && ok "missing user hints at --list" || bad "missing user hint" "$out"
reset; mkuser alice false; mv "$ROOT/users/alice.json" "$ROOT/users/Alice.json"
out=$(run alice)
[[ "$out" == *"case-mismatched"* ]] && ok "case-mismatched file is called out" || bad "case-mismatch hint" "$out"
reset; echo 'not json at all' > "$ROOT/users/broken.json"
check "corrupt JSON exits non-zero" "$(rc broken)" "1"
reset; echo '{"username":"x","note":"no password_hash"}' > "$ROOT/users/weird.json"
out=$(run weird)
[[ "$out" == *"does not look like a CryptIRC user record"* ]] && ok "non-user record refused" || bad "non-user record refused" "$out"
check "non-user record left unmodified" "$(cat "$ROOT/users/weird.json")" '{"username":"x","note":"no password_hash"}'

echo "── --list ───────────────────────────────────────────────────────────"
reset; mkuser alice true; mkuser bob false; mkuser carol false false
out=$(run --list)
[[ "$out" == *"alice"*"ADMIN"* ]] && ok "--list marks the admin" || bad "--list marks admin" "$out"
[[ "$out" == *"carol"*"UNVERIFIED"* ]] && ok "--list flags unverified accounts" || bad "--list unverified" "$out"
[[ "$out" == *"1 admin(s) of 3 account(s)"* ]] && ok "--list totals are right" || bad "--list totals" "$out"
reset
out=$(run --list); [[ "$out" == *"No accounts yet"* ]] && ok "--list handles an empty install" || bad "--list empty" "$out"
reset; mkuser bob false
out=$(run --list)
[[ "$out" == *"No admins"* ]] && ok "--list warns when there is no admin at all" || bad "--list no-admin warning" "$out"
check "--list with a username is rejected" "$(rc --list bob)" "1"

echo "── argument handling ────────────────────────────────────────────────"
reset; mkuser alice false; mkuser bob false
check "unknown option rejected" "$(rc --bogus alice)" "1"
check "two usernames rejected" "$(rc alice bob)" "1"
check "no arguments shows usage (exit 1)" "$(rc)" "1"
check "--help exits 0" "$(rc --help)" "0"
rm -rf "$ROOT"
check "missing data dir exits 1" "$(rc alice)" "1"

echo "── unverified warning + permissions ─────────────────────────────────"
reset; mkuser dave false false
out=$(run dave)
[[ "$out" == *"UNVERIFIED"* && "$out" == *"resetpass.sh --verify"* ]] && ok "warns that an unverified admin still can't log in" || bad "unverified warning" "$out"
reset; mkuser alice false
chmod 0600 "$ROOT/users/alice.json"
run alice >/dev/null
check "file mode preserved (0600)" "$(stat -c%a "$ROOT/users/alice.json")" "600"
check "no temp files left behind" "$(find "$ROOT/users" -name '.makeadmin-*' | wc -l)" "0"

echo "── terminal look (needs a pty: FANCY is false everywhere above) ─────"
if command -v script >/dev/null 2>&1; then
  reset; mkuser alice false
  # A pty makes [[ -t 2 ]] true, which is the ONLY way the banner/ghost run.
  pout=$(script -qec "CRYPTIRC_DATA='$ROOT' bash '$SCRIPT' alice" /dev/null 2>&1)
  [[ "$pout" == *"CryptIRC"* ]] && ok "banner renders on a terminal" || bad "banner on tty" "$(echo "$pout" | head -2)"
  [[ "$pout" == *"(o o)"* ]] && ok "ghost animates on a terminal" || bad "ghost on tty" "$(echo "$pout" | head -2)"
  printf '%s' "$pout" | grep -q $'\033\[?25h' && ok "cursor is restored before exit" || bad "cursor restore" ""
  check "grant still worked under a pty" "$(isadmin alice)" "true"

  reset; mkuser alice false
  pout=$(script -qec "CRYPTIRC_DATA='$ROOT' CRYPTIRC_NO_GHOST=1 bash '$SCRIPT' alice" /dev/null 2>&1)
  [[ "$pout" != *"(o o)"* ]] && ok "CRYPTIRC_NO_GHOST=1 skips the animation" || bad "no-ghost gate" ""
  [[ "$pout" == *"CryptIRC"* ]] && ok "  ...but keeps the banner" || bad "no-ghost banner" ""

  reset; mkuser alice false
  pout=$(script -qec "CRYPTIRC_DATA='$ROOT' NO_COLOR=1 bash '$SCRIPT' alice" /dev/null 2>&1)
  printf '%s' "$pout" | grep -q $'\033\[' && bad "NO_COLOR suppresses escapes" "escapes present" || ok "NO_COLOR suppresses all escapes"

  reset; mkuser alice false
  # Interrupting mid-animation must not leave a half-written record.
  script -qec "CRYPTIRC_DATA='$ROOT' bash '$SCRIPT' alice" /dev/null >/dev/null 2>&1 &
  _p=$!; sleep 0.25; kill -INT $_p 2>/dev/null; wait $_p 2>/dev/null
  python3 -c "import json;json.load(open('$ROOT/users/alice.json'))" 2>/dev/null \
    && ok "SIGINT mid-run leaves the record valid" || bad "SIGINT integrity" ""
  check "SIGINT leaves no temp file" "$(find "$ROOT/users" -name '.makeadmin-*' | wc -l)" "0"

  reset; mkuser alice false
  # TERM unset: tput fails and must fall back, not abort under set -e.
  pout=$(env -u TERM script -qec "CRYPTIRC_DATA='$ROOT' bash '$SCRIPT' alice" /dev/null 2>&1)
  check "works with TERM unset" "$(isadmin alice)" "true"
else
  echo "  (skipped: 'script' not available)"
fi

echo
if [[ $FAIL -eq 0 ]]; then echo "PASS — $PASS assertions, 0 failures"; else echo "FAIL — $PASS passed, $FAIL failed"; fi
exit $((FAIL > 0))
