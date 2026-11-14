# shellcheck shell=bash
# CryptIRC's 0.5.8 data floor — shared by deploy/update.sh and both installers (sourced from the
# same checkout; never run on its own) — and the pre-upgrade backup they make (_backup_data).
#
# DATA_FLOOR is the first release whose on-disk user data older releases can't read back. From
# 0.5.8 on, unlocking a vault moves that user's end-to-end keys to a new format (e2e2.…) and
# stores their channel keys / perform commands encrypted (enc:…). An older binary put back after
# that can't read the keys: its browser code makes NEW ones and overwrites the migrated ones
# (encrypted conversations and verified identities lost for good — rolling forward again doesn't
# bring them back), and it sends the enc:… values to IRC as they are. A new web serves users from
# the moment it starts, so during a health check someone may well unlock. So an AUTOMATIC
# rollback across the floor is allowed only if no user's data changed while the new version ran.
# Raise DATA_FLOOR when a later release adds such a migration.
DATA_FLOOR=0.5.8

# _ver_ge <a> <b>: version a >= version b (numeric major.minor.patch; a -suffix is ignored).
# rc 0 = yes, 1 = no, 2 = <a> is not a version (e.g. "unknown").
_ver_ge() {
    local a="${1%%[!0-9.]*}" b="${2%%[!0-9.]*}" i x y
    local -a A B
    [[ "$a" =~ ^[0-9]+(\.[0-9]+)*$ && "$b" =~ ^[0-9]+(\.[0-9]+)*$ ]] || return 2
    IFS=. read -ra A <<< "$a"; IFS=. read -ra B <<< "$b"
    for i in 0 1 2; do
        x=$(( 10#${A[i]:-0} )); y=$(( 10#${B[i]:-0} ))
        (( x > y )) && return 0
        (( x < y )) && return 1
    done
    return 0
}
# _floor_crossed <old version|unknown> <new version>: the step goes from below DATA_FLOOR (or an
# unknown version) to DATA_FLOOR or later, i.e. putting the old binary back could meet data it
# can't read.
_floor_crossed() {
    local r=0
    _ver_ge "$1" "$DATA_FLOOR" && return 1
    _ver_ge "$2" "$DATA_FLOOR" || r=$?
    (( r != 1 ))
}
# _user_data_snapshot <data dir>: a fingerprint of the per-user files a new version migrates when
# a user unlocks (or otherwise uses it): e2e/<user>/… (not the server-wide files directly in e2e/,
# e.g. network_names.json, which the server keeps up to date on its own), networks/… and
# vaults/… — every entry's type, size, mtime, inode and name, so a change, a new file and a
# deletion all show. Symlinks are followed (find -L), as the server follows them: a user directory
# moved to another disk behind a symlink (e2e/<user> → …) is fingerprinted by what it holds; a loop or
# an unreadable entry makes the snapshot unreadable. Prints "e2e=<hash> networks=<hash> vaults=<hash>"
# (a missing directory reads as an empty one); rc 1 = something could not be read. Take it while no
# cryptirc runs.
_user_data_snapshot() {
    local dd="$1" d h out="" rc=0
    for d in e2e networks vaults; do
        if [[ -e "$dd/$d" || -L "$dd/$d" ]]; then
            h=$(set -o pipefail; cd -- "$dd/$d" 2>/dev/null || exit 1
                if [[ "$d" == e2e ]]; then
                    find -L . -mindepth 1 \( -type d -o -path './*/*' \) -printf '%Y %s %T@ %i %P\0' 2>/dev/null
                else
                    find -L . -mindepth 1 -printf '%Y %s %T@ %i %P\0' 2>/dev/null
                fi | LC_ALL=C sort -z | sha256sum) || { rc=1; h="unreadable"; }
        else
            h=$(printf '' | sha256sum)
        fi
        out+="$d=${h%% *} "
    done
    printf '%s' "${out% }"
    return "$rc"
}
# _user_data_changed <snapshot taken before> <data dir>: the directories (e2e networks vaults)
# whose fingerprint differs now, space-separated; empty = nothing changed. A snapshot that could
# not be taken (before or now) counts as changed: the safe side is not to roll back.
_user_data_changed() {
    local now w d moved=""
    if [[ "$1" == "unknown" ]] || ! now=$(_user_data_snapshot "$2"); then
        printf '%s' "e2e networks vaults"; return 0
    fi
    for w in $now; do
        d="${w%%=*}"
        [[ " $1 " == *" $w "* ]] || moved+="$d "
    done
    printf '%s' "${moved% }"
}

# _backup_data <data dir, resolved> <archive> <message file>: archive the data dir (as update.sh and the
# installers back it up before an upgrade) into <archive>, written 0600 by root. A user's directory moved
# to another disk behind a symlink (e2e/<user> → …) is archived with what it holds (tar --dereference) —
# but the data dir belongs to the service account, which could plant links (and names) of its own, so:
#  - tar runs AS the data dir's owner (the service account, no_new_privs): a planted link (→ /etc/shadow,
#    /root/.ssh) reaches only what that account can read anyway. Files it can't read are left out (counted).
#    It writes only into a pipe; root writes the archive file (a service-UID process never holds an fd on it);
#  - first, as that account, everything the archive would reach is scanned (find -L): an entry that is —
#    or links to — a device, FIFO or socket (other than the daemon's own irc-core.sock), or a link that
#    resolves into /proc, /sys or /dev, stops the backup: /dev/zero, a FIFO or /proc would never end;
#  - a time limit (CRYPTIRC_BACKUP_TIMEOUT seconds, default 1800) ends a scan or archive that still doesn't;
#  - root then checks the archive's members: no absolute or ../ path, no setuid/setgid bit, no device, FIFO,
#    hard-link or symlink member — anything else is refused (a restore must not create such files).
# Messages go to <message file>, one per line, every name from the data dir cut down to printable ASCII
# without backslashes (_bk_clean: no C0/C1 control, no 0x9b or its UTF-8 form): print them with printf '%s',
# never echo -e. rc: tar's (0, or 1 = a file
# changed or vanished while being read: still complete), 3 = refused before archiving, 5 = the archive
# was refused, 124 = timed out, else a failure.
_bk_clean() { printf '%s' "$1" | LC_ALL=C tr -cd '\040-\133\135-\176'; }    # printable ASCII only, no backslash
_backup_data() {
    local src="$1" out="$2" msg="$3" owner kind p t bad="" lim="${CRYPTIRC_BACKUP_TIMEOUT:-1800}" rc=0 cntf n
    [[ "$lim" =~ ^[1-9][0-9]*$ ]] || lim=1800
    : > "$msg"
    owner=$(stat -c %U -- "$src" 2>/dev/null) || owner=""
    if [[ -z "$owner" || "$owner" == UNKNOWN ]] || ! id -u -- "$owner" >/dev/null 2>&1; then
        printf '%s\n' "the data directory's owner has no account name — it can't be archived as that account" >> "$msg"
        return 3
    fi
    while IFS= read -r -d '' p; do
        kind="${p%% *}"; p="${p#* }"
        if [[ "$kind" == S ]]; then bad="$p"; break; fi
        t=$(readlink -f -- "$p" 2>/dev/null) || continue
        case "$t" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*) bad="$p -> $t"; break ;; esac
    done < <(cd / && runuser -u "$owner" -- setpriv --no-new-privs timeout "$lim" find -L "$src" -mindepth 1 \
                 \( -xtype l -printf 'L %p\0' \) -o \
                 \( \( -type c -o -type b -o -type p -o -type s \) ! -path "$src/irc-core.sock" -printf 'S %p\0' \) 2>/dev/null)
    if [[ -n "$bad" ]]; then
        printf '%s\n' "it holds (or links to) a device, FIFO or socket, or a link into /proc, /sys or /dev: $(_bk_clean "$bad") — remove it, then retry" >> "$msg"
        return 3
    fi
    cntf=$(mktemp) || return 2
    ( cd / && umask 077
      runuser -u "$owner" -- setpriv --no-new-privs timeout --kill-after=10 "$lim" \
          tar czf - --dereference --hard-dereference --ignore-failed-read --exclude=irc-core.sock \
          -C "$(dirname -- "$src")" "$(basename -- "$src")" \
          2> >(LC_ALL=C grep -cE 'Cannot (open|read)' > "$cntf") | cat > "$out"
      r=("${PIPESTATUS[@]}"); wait $! 2>/dev/null
      (( r[1] == 0 )) || exit 2          # root couldn't write the archive (disk full…)
      exit "${r[0]}" ) || rc=$?
    n=$(cat "$cntf" 2>/dev/null); rm -f "$cntf"
    if (( rc == 124 || rc == 137 )); then
        printf '%s\n' "it didn't finish within ${lim}s (CRYPTIRC_BACKUP_TIMEOUT)" >> "$msg"; return 124
    fi
    (( rc <= 1 )) || return "$rc"
    [[ "$n" =~ ^[1-9][0-9]*$ ]] && printf '%s\n' "$n file(s) the service account ($(_bk_clean "$owner")) can't read were left out (the service can't read them either)" >> "$msg"
    # The members, as root (tar quotes unusual characters in names when it lists them).
    bad=$(tar tzf "$out" 2>/dev/null | LC_ALL=C grep -m1 -E '^/|(^|/)\.\.(/|$)') || true
    if [[ -z "$bad" ]]; then
        bad=$(tar tzvf "$out" 2>/dev/null | LC_ALL=C awk '{ t = substr($1, 1, 1); s = substr($1, 4, 1) substr($1, 7, 1) }
            t ~ /[cbphl]/ || s ~ /[sS]/ { print; exit }') || true
    fi
    if [[ -n "$bad" ]]; then
        printf '%s\n' "the archive holds a member a restore must not create (absolute or ../ path, setuid/setgid, device, FIFO, link): $(_bk_clean "$bad")" >> "$msg"
        return 5
    fi
    return "$rc"
}
