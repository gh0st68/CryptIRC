# shellcheck shell=bash
# How a systemd unit's settings are read from root-owned sources — shared by deploy/update.sh and
# both installers (sourced from the same checkout; never run on its own). Values come only from the
# unit files and drop-ins (`systemctl show`) and from EnvironmentFile=s that are root-owned and not
# group/world-writable; never from the service's own /proc/<pid>/environ (the unprivileged service
# account can rewrite that — _live_data_dir reads it only to cross-check). Moved here from update.sh
# (round 6), plus _unit_data_dir; round 7: wildcard EnvironmentFile= entries, the live cross-check,
# unit-file quoting and update.sh's stock irc-core.service hashes (for the installers too); round 11:
# the install directory, its binaries, markers and rollback copies made root's (_secure_install_dir).

# _safe_path <value>: a plain absolute path that may be written into a unit file: only
# [A-Za-z0-9._/-] — no newline or other control character, space, quote, `%` specifier or
# `$` — and no ".." segment.
_safe_path() { [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ && "$1/" != *"/../"* ]]; }
# _sane_path <value>: an absolute path this script may USE (archive, test, print) but never
# writes into a unit: no control character (newline…) and no ".." segment. Spaces and the
# like are fine here — only the pre-split migration, which writes the data dir into a new
# unit file, needs the strict _safe_path.
_sane_path() { [[ "$1" == /* && "$1" != *[[:cntrl:]]* && "$1/" != *"/../"* ]]; }
# _sysd_words <text>: split `systemctl show` output into its words, NUL-terminated, the way
# systemd quotes them: shell-style — a value with a space, quote, `$`… is printed in "double
# quotes" (\ escaping \ " ` $), and 'single quotes' are literal. (Splitting on whitespace alone
# read `"CRYPTIRC_DATA=/srv/c data"` as two words starting with a quote.)
_sysd_words() {
    local s="$1" n=${#1} i c q="" w="" have=false
    for (( i = 0; i < n; i++ )); do
        c="${s:i:1}"
        if [[ "$q" == "'" ]]; then
            if [[ "$c" == "'" ]]; then q=""; else w+="$c"; fi
        elif [[ "$q" == '"' ]]; then
            if [[ "$c" == '"' ]]; then q=""
            elif [[ "$c" == "\\" ]] && (( i + 1 < n )) && [[ "${s:i+1:1}" == [\\\"\`\$] ]]; then i=$(( i + 1 )); w+="${s:i:1}"
            else w+="$c"; fi
        elif [[ "$c" == [[:space:]] ]]; then
            if [[ "$have" == "true" ]]; then printf '%s\0' "$w"; w=""; have=false; fi
        elif [[ "$c" == "'" || "$c" == '"' ]]; then q="$c"; have=true
        elif [[ "$c" == "\\" ]] && (( i + 1 < n )); then i=$(( i + 1 )); w+="${s:i:1}"; have=true
        else w+="$c"; have=true
        fi
    done
    [[ "$have" == "true" ]] && printf '%s\0' "$w"
    return 0
}
# _dir_chain_protected <dir>: <dir> and every directory above it are root-owned and not
# writable by group/others (sticky directories allowed): nobody but root can rename, swap or
# re-point an entry in them.
_dir_chain_protected() {
    local d="$1" st m
    [[ "$d" == /* ]] || return 1
    while :; do
        st=$(stat -L -c '%u %a' -- "$d" 2>/dev/null) || return 1
        m=$(( 8#${st#* } ))
        [[ "${st%% *}" == 0 ]] && { (( (m & 8#022) == 0 )) || (( (m & 8#1000) != 0 )); } || return 1
        [[ "$d" == / ]] && return 0
        d=$(dirname -- "$d")
    done
}
# _envfile_trusted <file>: root-owned and not writable by group/others (stat follows a symlink).
# A symlink counts only where nobody but root can re-point it: the directories holding the
# link and those holding its target are all protected (else the service account could aim a
# link in its own data dir at any root-owned file).
_envfile_trusted() {
    local st real
    st=$(stat -L -c '%u %a' -- "$1" 2>/dev/null) || return 1
    [[ "${st%% *}" == 0 ]] && (( (8#${st#* } & 8#022) == 0 )) || return 1
    if [[ -L "$1" ]]; then
        real=$(readlink -f -- "$1" 2>/dev/null) || return 1
        _dir_chain_protected "$(dirname -- "$1")" && _dir_chain_protected "$(dirname -- "$real")" || return 1
    fi
    return 0
}
# _envfile_text <file>: the text of a TRUSTED EnvironmentFile in a directory only root can change
# (_dir_chain_protected): nothing can put another file at that name while it is read. One in a
# directory someone else can write is never read — not even a root-owned one: whoever can write
# the directory could swap in a file of their own for just the moment of the read (round 9).
# rc 1 = untrusted / unreadable.
_envfile_text() {
    _envfile_trusted "$1" || return 1
    _dir_chain_protected "$(dirname -- "$1")" || return 1
    [[ -f "$1" && -r "$1" ]] || return 1
    cat -- "$1" 2>/dev/null
}
# _envfile_get <text> <NAME>: NAME's value in the text of a systemd EnvironmentFile (the last
# assignment wins). KEY=VALUE lines, "double-quoted" values with backslash escapes,
# 'single-quoted' values, # and ; comments. rc 1 = not set.
_envfile_get() {
    local line k v val="" buf i c found=1 txt="$1"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == [\#\;]* || "$line" != *=* ]] && continue
        k="${line%%=*}"; k="${k%"${k##*[![:space:]]}"}"
        [[ "$k" == "$2" ]] || continue
        v="${line#*=}"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
        if [[ ${#v} -ge 2 && "$v" == \"*\" ]]; then
            v="${v:1:${#v}-2}"; buf=""
            for (( i = 0; i < ${#v}; i++ )); do
                c="${v:i:1}"
                if [[ "$c" == "\\" ]] && (( i + 1 < ${#v} )); then i=$(( i + 1 )); c="${v:i:1}"; fi
                buf+="$c"
            done
            v="$buf"
        elif [[ ${#v} -ge 2 && "$v" == \'*\' ]]; then
            v="${v:1:${#v}-2}"
        elif [[ "$v" == [\"\']* ]]; then
            # A quote that doesn't close on this line: systemd carries the value over the next
            # line(s), so what the service gets holds a newline. Say so (callers refuse values with
            # control characters) rather than handing back a fragment.
            v="$v"$'\n'"(continued on the next line)"
        fi
        val="$v"; found=0
    done <<< "$txt"
    (( found == 0 )) && printf '%s' "$val"
    return "$found"
}
# _unit_envfiles <unit>: the unit's EnvironmentFile= entries (drop-ins included), one per line —
# each a path or a wildcard pattern (see _envfile_paths).
_unit_envfiles() {
    local l
    while IFS= read -r l; do
        l="${l%% (ignore_errors=*}"; l="${l#-}"
        [[ -n "$l" ]] && printf '%s\n' "$l"
    done < <(systemctl show "$1" -p EnvironmentFiles --value 2>/dev/null)
    return 0
}
# _dir_closed <dir>: nobody but root can add, remove or rename an entry in <dir>: it is root-owned
# and not group/world-writable — sticky or not (in a sticky /tmp anyone can still ADD a file) — and
# the directories above it are protected.
_dir_closed() {
    local st
    st=$(stat -L -c '%u %a' -- "$1" 2>/dev/null) || return 1
    [[ "${st%% *}" == 0 ]] && (( (8#${st#* } & 8#022) == 0 )) && _dir_chain_protected "$1"
}
# _envfile_paths <entry>: the files one EnvironmentFile= entry makes systemd read, NUL-terminated,
# in the order it reads them. systemd runs every entry through glob(3): a pattern with * ? or [
# reads each match in sorted order (dot-files only when the pattern spells the dot; no match = no
# file), a plain path just that path. Expanded here the same way: no dot-files, no extglob or
# brace forms, sorted byte-wise (LC_ALL=C).
_envfile_paths() {
    if [[ "$1" != *[\*\?\[]* ]]; then printf '%s\0' "$1"; return 0; fi
    (
        shopt -s nullglob; shopt -u dotglob extglob nocaseglob failglob globstar 2>/dev/null
        unset GLOBIGNORE; set +f; LC_ALL=C; IFS=
        # shellcheck disable=SC2206   # pathname expansion is the point (IFS is empty: no splitting)
        m=( $1 )
        (( ${#m[@]} )) && printf '%s\0' "${m[@]}"
        exit 0
    )
}
# _envfile_glob_trusted <entry>: a wildcard entry's set of files can only change by root's hand.
# Wildcards are supported in the FILE NAME only (/etc/cryptirc/env.d/*.env). Its directory — or,
# while it doesn't exist, the nearest path component above that does (a dangling symlink counts:
# it is what systemd follows once its target appears) — resolved through every symlink, must be
# closed (_dir_closed): else someone else could add a matching file, setting anything, before the
# service's next start. The path as written must be protected too (_dir_chain_protected): a
# symlink on it then sits in a directory only root can change. A dangling symlink is refused.
# rc 0 = fine (a plain path always: the file itself is checked when it is read); rc 1 = open,
# or a dangling symlink; rc 2 = a wildcard in a directory part, which isn't supported (which
# directories it reads, now or later, can't be pinned down).
_envfile_glob_trusted() {
    local d r
    [[ "$1" == *[\*\?\[]* ]] || return 0
    d=$(dirname -- "$1")
    [[ "$d" == *[\*\?\[]* ]] && return 2
    while [[ ! -e "$d" && ! -L "$d" && "$d" != / ]]; do d=$(dirname -- "$d"); done
    r=$(readlink -e -- "$d") || return 1
    _dir_closed "$r" && _dir_chain_protected "$d" || return 1
    return 0
}
# _unit_env <unit> <NAME>: NAME as the unit's (root-owned) files set it. As in systemd, the
# last Environment= assignment wins and EnvironmentFile= values override Environment= ones (a
# wildcard entry's files in sorted order, later files winning).
# rc 1 = not set; rc 3 = an EnvironmentFile that is NOT root-owned / is group- or
# world-writable / sits in a directory others can write mentions NAME, so its value can't be
# trusted, or a wildcard EnvironmentFile reads a directory others can add files to; rc 5 = a wildcard EnvironmentFile with a wildcard
# in a directory part (not supported) (nothing is printed either way).
_unit_env() {
    local kv e f v txt val="" found=1 g
    while IFS= read -r -d '' kv; do
        [[ "$kv" == "$2="* ]] && { val="${kv#*=}"; found=0; }
    done < <(_sysd_words "$(systemctl show "$1" -p Environment --value 2>/dev/null)")
    while IFS= read -r e; do
        g=0; _envfile_glob_trusted "$e" || g=$?
        (( g == 2 )) && return 5
        (( g == 0 )) || return 3
        while IFS= read -r -d '' f; do
            [[ -e "$f" || -L "$f" ]] || continue            # an optional (-) file that isn't there
            if txt=$(_envfile_text "$f"); then
                if v=$(_envfile_get "$txt" "$2"); then val="$v"; found=0; fi
                continue
            fi
            # Untrusted (not root-owned, writable by others, a link others can re-point, or it
            # changed while being read): if it may set NAME, nothing can be built from it. Read
            # without blocking (a FIFO would hang); unreadable counts as "may set it".
            txt=$(dd if="$f" iflag=nonblock bs=1M count=1 status=none 2>/dev/null) || return 3
            grep -qE "^[[:space:]]*$2[[:space:]]*=" <<< "$txt" && return 3
        done < <(_envfile_paths "$e")
    done < <(_unit_envfiles "$1")
    (( found == 0 )) && printf '%s' "$val"
    return "$found"
}
# _unit_data_dir <unit>: the data directory that unit's service uses — CRYPTIRC_DATA as its
# root-owned settings set it (when unset or relative, the binary's ./data default resolves against
# the unit's WorkingDirectory), trailing slashes dropped. rc 3 = an EnvironmentFile that can't be
# trusted mentions CRYPTIRC_DATA; rc 4 = the result is not a usable absolute path (both print it, %q);
# rc 5 = an EnvironmentFile with a wildcard in a directory part (see _unit_env).
_unit_data_dir() {
    local v wd rc=0
    v=$(_unit_env "$1" CRYPTIRC_DATA) || rc=$?
    (( rc == 3 || rc == 5 )) && return "$rc"
    [[ -n "$v" ]] || v=./data
    if [[ "$v" != /* ]]; then
        wd=$(systemctl show -p WorkingDirectory --value "$1" 2>/dev/null || true)
        wd="${wd#[-!+]}"; [[ "$wd" == /* ]] || wd=/
        v="${wd%/}/${v#./}"
    fi
    while [[ "$v" == */ && "$v" != / ]]; do v="${v%/}"; done
    if ! _sane_path "$v"; then printf '%q' "$v"; return 4; fi
    printf '%s' "$v"
}
# _envfile_glob_unsupported <unit>: the unit's EnvironmentFile= entries with a wildcard in a directory
# part (for the message that stops a run), space-separated.
_envfile_glob_unsupported() {
    local e out=""
    while IFS= read -r e; do
        [[ "$(dirname -- "$e")" == *[\*\?\[]* ]] && out+="${out:+ }$e"
    done < <(_unit_envfiles "$1")
    printf '%s' "$out"
}
# _live_data_dir <pid>: the data directory the RUNNING service process uses — its CRYPTIRC_DATA (else
# the binary's ./data default), a relative value resolved against the process's working directory,
# trailing slashes dropped: the same rules as _unit_data_dir. It comes from /proc, i.e. from the
# service account's side, so it is only ever COMPARED with what the unit's root-owned settings give
# (a mismatch stops the run), never used. rc 2 = can't tell (no such process, unreadable, or still
# systemd's own child that hasn't exec'd the service yet).
_live_data_dir() {
    local kv v="" any=false exe cwd
    [[ "$1" =~ ^[1-9][0-9]*$ && -r "/proc/$1/environ" ]] || return 2
    exe=$(readlink "/proc/$1/exe" 2>/dev/null) || return 2
    exe="${exe% (deleted)}"
    [[ "${exe##*/}" == systemd || "${exe##*/}" == systemd-executor ]] && return 2
    { while IFS= read -r -d '' kv; do
          any=true
          if [[ "$kv" == CRYPTIRC_DATA=* ]]; then v="${kv#*=}"; break; fi
      done; } < "/proc/$1/environ" 2>/dev/null || return 2
    [[ "$any" == true ]] || return 2
    [[ -n "$v" ]] || v=./data
    if [[ "$v" != /* ]]; then
        cwd=$(readlink "/proc/$1/cwd" 2>/dev/null) || return 2
        v="${cwd%/}/${v#./}"
    fi
    while [[ "$v" == */ && "$v" != / ]]; do v="${v%/}"; done
    printf '%s' "$v"
}
# _same_dir <a> <b>: one directory — the same path, or two existing paths to the same inode (one is a
# symlink to the other, say).
_same_dir() { [[ "$1" == "$2" ]] || { [[ -e "$1" && -e "$2" && "$1" -ef "$2" ]]; }; }

# Writing a path into a unit file. A plain path (_safe_path) goes in as it is — what every earlier
# release wrote; anything else (a space, a %, …; never a control character: callers check
# _sane_path) in "double quotes" with \ and " escaped and every % doubled (systemd would expand it
# as a specifier).
_unit_quoted() { local v="$1"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//%/%%}"; printf '"%s"' "$v"; }
# _unit_env_line <NAME> <path>: the Environment= line that sets NAME to <path>.
_unit_env_line() {
    if _safe_path "$2"; then printf 'Environment=%s=%s\n' "$1" "$2"
    else printf 'Environment=%s\n' "$(_unit_quoted "$1=$2")"; fi
}
# _unit_rw_line <path> [-]: the ReadWritePaths= line for <path> ("-": a missing path doesn't stop the unit).
_unit_rw_line() {
    if _safe_path "$1"; then printf 'ReadWritePaths=%s%s\n' "${2:-}" "$1"
    else printf 'ReadWritePaths=%s\n' "$(_unit_quoted "${2:-}$1")"; fi
}

# ── irc-core.service: stock or customized? ─────────────────────────────────────────────────────
# (Moved here from update.sh in round 7, unchanged, so the installers can make the same call.)
# Comments, blank lines, trailing spaces and the since-removed LimitNPROC=64 line don't
# count: the installers wrote the unit without the repo file's comments, and the
# LimitNPROC line is migrated away on every run (see update.sh's _migrate_unit_lines).
_unit_body()  { grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$1" 2>/dev/null || true; }
_unit_norm_hash() {   # stdin → sha256 of the normalized unit text
    sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*#/d' -e '/^$/d' -e '/^LimitNPROC=64$/d' | sha256sum | cut -d' ' -f1
}
# Units earlier releases wrote with their default paths and user: deploy.sh / deploy-arch.sh
# (before they installed deploy/irc-core.service verbatim) and update.sh's pre-split
# migration. Every version of deploy/irc-core.service is added from this checkout's history.
STOCK_IRC_CORE_UNITS=(
    798b986d1dc757b6b010785c971142d9f12af41bfbabb1b0d3fbc229dc0e0ab2   # deploy.sh 10fd4e7..71f596c, deploy-arch.sh ..310a8ad
    69a0185c06ec230d7396a6403fea4f980bee3e03014877789a6ce51ce2b907a8   # deploy.sh 310a8ad..343fc82
    7935eca7a526454f62c23e2a322be44c9044719849ae7045f1c8cc287e6063eb   # irc-core.service 71f596c, update.sh 10fd4e7..f498159
    89aa18718a9f85e6b3c00fd789cb3c7e36e8d6a05144fda8f14b660305731a7f   # irc-core.service 343fc82, update.sh 343fc82..
    7b93958c63beb06ceaae84e654e85d91d4f1ff9ca5cd91c45d2deaba1a4c4746   # irc-core.service b47725e
)
# _stock_unit_hashes [<data dir> <socket>]: the normalized hashes of every stock unit. With a data
# dir (and a socket path, may be empty), also every version of deploy/irc-core.service as the
# installers write it for that data dir and socket (_irc_core_unit_subst) — a unit an installer
# generated for a moved data dir is theirs to refresh too. update.sh calls it without arguments.
_stock_unit_hashes() {
    local c
    printf '%s\n' "${STOCK_IRC_CORE_UNITS[@]}"
    _unit_norm_hash < "$SCRIPT_DIR/irc-core.service"
    for c in $(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" log --format=%H -- deploy/irc-core.service 2>/dev/null); do
        GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" show "$c:deploy/irc-core.service" 2>/dev/null | _unit_norm_hash
    done
    if (( $# >= 1 )); then
        _irc_core_unit_subst "$1" "${2:-}" < "$SCRIPT_DIR/irc-core.service" | _unit_norm_hash
        for c in $(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" log --format=%H -- deploy/irc-core.service 2>/dev/null); do
            GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" show "$c:deploy/irc-core.service" 2>/dev/null \
                | _irc_core_unit_subst "$1" "${2:-}" | _unit_norm_hash
        done
    fi
    return 0
}
# _irc_core_unit_subst <data dir> <socket>: stdin = deploy/irc-core.service (written for
# /var/lib/cryptirc), stdout = the same unit for that data dir — its CRYPTIRC_DATA and
# ReadWritePaths lines — and, with a socket path, a CRYPTIRC_IPC_SOCK line plus write access to
# the socket's directory when it lies outside the data dir (on /run: a RuntimeDirectory, as
# update.sh's pre-split migration writes it). /var/lib/cryptirc and no socket: unchanged.
_irc_core_unit_subst() {
    local data="$1" sock="$2" l sd rd
    while IFS= read -r l || [[ -n "$l" ]]; do
        case "$l" in
            "Environment=CRYPTIRC_DATA=/var/lib/cryptirc")
                _unit_env_line CRYPTIRC_DATA "$data"
                [[ -n "$sock" ]] && _unit_env_line CRYPTIRC_IPC_SOCK "$sock"
                ;;
            "ReadWritePaths=/var/lib/cryptirc")
                _unit_rw_line "$data"
                if [[ -n "$sock" ]]; then
                    sd=$(dirname -- "$sock")
                    if [[ "$sd/" != "${data%/}/"* ]]; then
                        rd=""
                        case "$sd" in /run/?*) rd=${sd#/run/} ;; /var/run/?*) rd=${sd#/var/run/} ;; esac
                        if [[ -n "$rd" ]] && _safe_path "/$rd"; then
                            printf '%s\n' "# The socket directory is on /run, emptied at every boot: systemd recreates it." \
                                "RuntimeDirectory=$rd" "RuntimeDirectoryMode=0700" "RuntimeDirectoryPreserve=yes"
                        fi
                        _unit_rw_line "$sd" -
                    fi
                fi
                ;;
            *) printf '%s\n' "$l" ;;
        esac
    done
    return 0
}

# ── The install directory belongs to root ──────────────────────────────────────────────────────
# /opt/cryptirc holds the binaries root's units start, the markers root rewrites (.version and the two
# irc-core source-hash files) and the rollback copies an update restores. The services never write
# there (ProtectSystem=strict; their ReadWritePaths are the data and log dirs). Whoever can write the
# directory or those files can swap what root starts or writes next.
# _secure_install_dir <dir> <service user> [dir…] makes exactly those root's — nothing recursive,
# nothing else. [dir…] = every directory the services write to (_sid_service_dirs).
#   1. Checks only — it stops with NOTHING changed when: <dir> is not written as its real path, or any
#      directory above it is a symlink, not root-owned, or writable by group/others (every component of
#      the written path is checked as itself, never through a link); one of [dir…] is <dir> itself or one
#      of the entries below; or one of those entries is a symlink, not a regular file (a directory for
#      .rollback / .rollback/units), has more than one link, or belongs to anyone but root or <service
#      user> (root never copies a file that may be someone else's — a hard link to /etc/shadow, say).
#   2. <dir>: root:root, no group/other write, no setuid/setgid; checked. From here on nobody else can
#      rename, replace or add entries in it.
#   3. .rollback and .rollback/units: root:root 0700 exactly (checked), FIRST — before anything else can
#      stop it; then their files.
#   4. cryptirc and irc_core (unless root:root 0755) and the markers (unless root:root without group/
#      other write or setuid/setgid), and the rollback files of 3 (binaries 0755, the rest 0600): REPLACED
#      by a root-owned copy — cp to a temp file next to it, chmod, mv over it — never chowned in place:
#      the new inode is out of reach of a writable descriptor someone kept open. Each is checked again
#      (as in 1) right before it is copied.
#   5. Everything else stays as it is; what belongs to another account or can be written by group/others
#      is listed — except an entry that is, or holds, one of [dir…].
#   6. LAST, only when all of that succeeded: group/other read+search on <dir> (the services run from it).
# Every chown/chmod/copy is checked and re-checked with stat; the first that fails stops it (what it
# fixed before stays fixed; <dir> is not opened). Numeric stat fields only (LC_ALL=C; no %F: translated).
# Output, one per line, names relative to <dir> in printable ASCII: "FIXED <name>", "OTHER <name>", and
# when it stops "REFUSE <reason>" with rc 1.
_sid_st() { LC_ALL=C stat -c '%u %g %a %h' -- "$1" 2>/dev/null; }
_sid_clean() { printf '%s' "$1" | LC_ALL=C tr -cd '\040-\133\135-\176'; }    # printable ASCII, no backslash
# _sid_entry_ok <path> <service uid>: a file root may copy — absent (rc 0, nothing printed), or a regular
# file (not a symlink) with one link, owned by root or the service account. Else prints the REFUSE line.
_sid_entry_ok() {
    local f="$1" st u g m h
    if [[ -L "$f" ]]; then
        printf 'REFUSE %s is a symbolic link; only a real file belongs there. Remove the link (sudo rm %s) and re-run.\n' \
            "$(_sid_clean "$f")" "$(_sid_clean "$f")"; return 1
    fi
    [[ -e "$f" ]] || return 0
    [[ -f "$f" ]] || { printf 'REFUSE %s is not a regular file. Move it away and re-run.\n' "$(_sid_clean "$f")"; return 1; }
    st=$(_sid_st "$f") || { printf 'REFUSE could not read the owner and mode of %s.\n' "$(_sid_clean "$f")"; return 1; }
    read -r u g m h <<< "$st"
    if (( h != 1 )); then
        printf 'REFUSE %s has %s links: another name shares its contents (find it: sudo find / -xdev -samefile %s). Remove the other name (or replace this one by a copy yourself), then re-run.\n' \
            "$(_sid_clean "$f")" "$h" "$(_sid_clean "$f")"; return 1
    fi
    if [[ "$u" != 0 && "$u" != "$2" ]]; then
        printf 'REFUSE %s belongs to uid %s, neither root nor the service account: not copying it. Check where it came from, remove it, then re-run.\n' \
            "$(_sid_clean "$f")" "$u"; return 1
    fi
    return 0
}
# _sid_file <dir> <name> <mode> <strict|loose> <top> <service uid>: one file of step 4 (absent: nothing
# to do); strict = exactly root:root <mode>, loose = root:root without group/other write or setuid/
# setgid. <top> = the install dir (names in the output are relative to it).
_sid_file() {
    local f="$1/$2" st u g m h t
    _sid_entry_ok "$f" "$6" || return 1
    [[ -e "$f" ]] || return 0
    st=$(_sid_st "$f") || { printf 'REFUSE could not read the owner and mode of %s.\n' "$(_sid_clean "$f")"; return 1; }
    read -r u g m h <<< "$st"
    if [[ "$4" == strict ]]; then
        [[ "$u $g $m" == "0 0 $3" ]] && return 0
    else
        [[ "$u $g" == "0 0" ]] && (( (8#$m & 8#6022) == 0 )) && return 0
    fi
    t=$(mktemp "$1/.cryptirc-secure.XXXXXX") \
        || { printf 'REFUSE could not create a file next to %s (disk full? read-only?).\n' "$(_sid_clean "$f")"; return 1; }
    if cp -- "$f" "$t" && chown root:root -- "$t" && chmod "$3" -- "$t" && mv -f -- "$t" "$f" \
       && [[ ! -L "$f" && "$(_sid_st "$f")" == "0 0 $3 1" ]]; then
        printf 'FIXED %s\n' "$(_sid_clean "${f#"$5"/}")"; return 0
    fi
    rm -f -- "$t"
    printf 'REFUSE could not replace %s with a root-owned copy.\n' "$(_sid_clean "$f")"; return 1
}
# _sid_rbdir_ok <dir>: .rollback or .rollback/units may be handled — absent, or a real directory.
_sid_rbdir_ok() {
    if [[ -L "$1" ]]; then
        printf 'REFUSE %s is a symbolic link; update.sh keeps its rollback copies in a real directory there. Remove the link (sudo rm %s) and re-run.\n' \
            "$(_sid_clean "$1")" "$(_sid_clean "$1")"; return 1
    fi
    [[ ! -e "$1" || -d "$1" ]] || { printf 'REFUSE %s is not a directory. Move it away and re-run.\n' "$(_sid_clean "$1")"; return 1; }
    return 0
}
# _sid_rbdir <dir> <top>: .rollback or .rollback/units (absent: nothing to do) → root:root 0700, exactly
# (symbolic chmod: a numeric one keeps a directory's setgid bit).
_sid_rbdir() {
    local r="$1" st
    _sid_rbdir_ok "$r" || return 1
    [[ -e "$r" ]] || return 0
    st=$(_sid_st "$r") || { printf 'REFUSE could not read the owner and mode of %s.\n' "$(_sid_clean "$r")"; return 1; }
    [[ "${st% *}" == "0 0 700" ]] && return 0
    if chown root:root -- "$r" && chmod u=rwx,go=,ug-s,-t -- "$r" && st=$(_sid_st "$r") && [[ "${st% *}" == "0 0 700" ]]; then
        printf 'FIXED %s\n' "$(_sid_clean "${r#"$2"/}")"; return 0
    fi
    printf 'REFUSE could not make %s root:root 0700 (chown/chmod failed or had no effect).\n' "$(_sid_clean "$r")"; return 1
}
# _sid_other <entry> <top> <skip…>: list <entry> (OTHER) when it belongs to another account or can be
# written by group/others — unless it is, or holds, one of the services' directories.
_sid_other() {
    local e="$1" top="$2" st u g m h s er
    shift 2
    er=$(readlink -m -- "$e" 2>/dev/null || true)
    for s in "$@"; do
        [[ "$s" == "$e" || "$s" == "$e"/* ]] && return 0
        [[ -n "$er" ]] && [[ "$s" == "$er" || "$s" == "$er"/* ]] && return 0
    done
    if [[ -L "$e" ]]; then
        [[ "$(LC_ALL=C stat -c '%u %g' -- "$e" 2>/dev/null)" == "0 0" ]] && return 0
    else
        st=$(_sid_st "$e") || return 0
        read -r u g m h <<< "$st"
        [[ "$u $g" == "0 0" ]] && (( (8#$m & 8#022) == 0 )) && return 0
    fi
    printf 'OTHER %s\n' "$(_sid_clean "${e#"$top"/}")"
}
# _sid_rbfiles <dir>: the files .rollback (or .rollback/units) holds, NUL-terminated, depth one
# (the units directory itself excepted).
_sid_rbfiles() {
    [[ -d "$1" && ! -L "$1" ]] || return 0
    find "$1" -mindepth 1 -maxdepth 1 ! -path "$1/units" -print0 2>/dev/null
}
_secure_install_dir() {
    local d="$1" su="$2" suid p st u g m h e n s rb pfx msg skip=()
    shift 2
    suid=$(id -u -- "$su" 2>/dev/null) || suid=""
    # 1. checks only: nothing is changed before all of them pass
    if [[ -L "$d" || ! -d "$d" ]]; then
        printf 'REFUSE %s is %s; it must be a real directory. Nothing was changed.\n' "$(_sid_clean "$d")" \
            "$([[ -L "$d" ]] && echo 'a symbolic link' || echo 'not a directory')"; return 1
    fi
    if ! _sane_path "$d" || [[ "$(readlink -e -- "$d" 2>/dev/null)" != "$d" ]]; then
        printf 'REFUSE %s is not written as its real path (a symlink, ., .. or // in it). Nothing was changed.\n' "$(_sid_clean "$d")"; return 1
    fi
    p=$d
    while [[ "$p" != / ]]; do
        p=$(dirname -- "$p")
        if [[ -L "$p" || ! -d "$p" ]] || ! st=$(LC_ALL=C stat -c '%u %a' -- "$p" 2>/dev/null) \
           || [[ "${st%% *}" != 0 ]] || (( (8#${st#* } & 8#022) != 0 )); then
            printf 'REFUSE %s must be reached through real directories that only root can change (no symlinks): %s %s. Nothing was changed.\n' \
                "$(_sid_clean "$d")" "$(_sid_clean "$p")" \
                "$(if [[ -L "$p" ]]; then echo 'is a symbolic link'; elif [[ ! -d "$p" ]]; then echo 'is not a directory'; else echo 'is not root-owned or is writable by group/others'; fi)"
            return 1
        fi
    done
    for s in "$@"; do
        [[ -n "$s" ]] || continue
        # Resolved (symlinks followed) only when the directory holding it is one only root can change;
        # else taken as written (normalized, no link followed): the service account can't steer it.
        if _dir_closed "$(dirname -- "$s")"; then s=$(readlink -m -- "$s" 2>/dev/null) || continue
        else s=$(realpath -s -m -- "$s" 2>/dev/null) || continue; fi
        case "$s" in
            "$d"|"$d/cryptirc"|"$d/irc_core"|"$d/.version"|"$d/.irc-core-srchash"|"$d/.irc_core.ondisk-srchash"|"$d/.rollback"|"$d/.rollback/"*)
                printf 'REFUSE the services write to %s (a data or socket directory), which is %s: making that root'"'"'s would lock them out. Move the data / socket elsewhere (e.g. /var/lib/cryptirc), then re-run. Nothing was changed.\n' \
                    "$(_sid_clean "$s")" "$([[ "$s" == "$d" ]] && echo 'the install directory itself' || echo 'one of the files the install directory keeps for root')"; return 1 ;;
        esac
        skip+=("$s")
    done
    rb="$d/.rollback"
    for e in "$rb" "$rb/units"; do
        msg=$(_sid_rbdir_ok "$e") || { printf '%s Nothing was changed.\n' "$msg"; return 1; }
    done
    for n in cryptirc irc_core .version .irc-core-srchash .irc_core.ondisk-srchash; do
        msg=$(_sid_entry_ok "$d/$n" "$suid") || { printf '%s Nothing was changed.\n' "$msg"; return 1; }
    done
    for pfx in "$rb" "$rb/units"; do
        while IFS= read -r -d '' e; do
            [[ -L "$e" || -f "$e" ]] || continue                      # a directory or special file: only listed
            msg=$(_sid_entry_ok "$e" "$suid") || { printf '%s Nothing was changed.\n' "$msg"; return 1; }
        done < <(_sid_rbfiles "$pfx")
    done
    # 2. the directory itself (not opened yet: step 6)
    st=$(_sid_st "$d") || { printf 'REFUSE could not read the owner and mode of %s. Nothing was changed.\n' "$(_sid_clean "$d")"; return 1; }
    read -r u g m h <<< "$st"
    if [[ "$u $g" != "0 0" ]] || (( (8#$m & 8#6022) != 0 )); then
        if ! { chown root:root -- "$d" && chmod go-w,ug-s -- "$d" && st=$(_sid_st "$d"); }; then
            printf 'REFUSE could not give %s to root (chown/chmod failed). Nothing else was changed.\n' "$(_sid_clean "$d")"; return 1
        fi
        read -r u g m h <<< "$st"
        if [[ "$u $g" != "0 0" ]] || (( (8#$m & 8#6022) != 0 )); then
            printf 'REFUSE %s still is not root-owned and closed to group/others after chown/chmod (a file system that ignores them, e.g. a root-squashed NFS export?). Nothing else was changed.\n' "$(_sid_clean "$d")"; return 1
        fi
        printf 'FIXED (the directory)\n'
    fi
    # 3. the rollback copies: private first
    _sid_rbdir "$rb" "$d" || return 1
    if [[ -d "$rb" ]]; then
        _sid_rbdir "$rb/units" "$d" || return 1
        while IFS= read -r -d '' e; do
            n=${e##*/}
            if [[ -L "$e" || -f "$e" ]]; then
                case "$n" in
                    cryptirc|irc_core) _sid_file "$rb" "$n" 755 strict "$d" "$suid" || return 1 ;;
                    *)                 _sid_file "$rb" "$n" 600 loose "$d" "$suid" || return 1 ;;
                esac
            else _sid_other "$e" "$d" "${skip[@]}"
            fi
        done < <(_sid_rbfiles "$rb")
        while IFS= read -r -d '' e; do
            if [[ -L "$e" || -f "$e" ]]; then _sid_file "$rb/units" "${e##*/}" 600 loose "$d" "$suid" || return 1
            else _sid_other "$e" "$d" "${skip[@]}"
            fi
        done < <(_sid_rbfiles "$rb/units")
    fi
    # 4. the binaries and the markers
    _sid_file "$d" cryptirc 755 strict "$d" "$suid" || return 1
    _sid_file "$d" irc_core 755 strict "$d" "$suid" || return 1
    for n in .version .irc-core-srchash .irc_core.ondisk-srchash; do _sid_file "$d" "$n" 644 loose "$d" "$suid" || return 1; done
    # 5. everything else: listed, never touched
    while IFS= read -r -d '' e; do
        case "${e##*/}" in cryptirc|irc_core|.version|.irc-core-srchash|.irc_core.ondisk-srchash|.rollback) continue ;; esac
        _sid_other "$e" "$d" "${skip[@]}"
    done < <(find "$d" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
    # 6. last: let the services in
    st=$(_sid_st "$d") || { printf 'REFUSE could not read the owner and mode of %s.\n' "$(_sid_clean "$d")"; return 1; }
    read -r u g m h <<< "$st"
    if (( (8#$m & 8#055) != 8#055 )); then
        chmod go+rx -- "$d" || { printf 'REFUSE could not let the services into %s (chmod go+rx failed).\n' "$(_sid_clean "$d")"; return 1; }
    fi
    return 0
}
# _sid_service_dirs <install dir> <web data dir> [web CRYPTIRC_IPC_SOCK]: the directories the services
# write to, for _secure_install_dir's [dir…], as "DIR <path>" lines:
#   - the web's data dir and irc-core's (its unit's CRYPTIRC_DATA, as _unit_data_dir reads it), each as written
#     AND fully resolved (realpath -e, when it exists): a data dir that is an alias of the install dir — even
#     through a directory the service account can change — must make _secure_install_dir refuse;
#   - the web's socket directory (its configured CRYPTIRC_IPC_SOCK, else <data dir>/irc-core.sock) and irc-core's,
#     resolved the way the daemon does (CRYPTIRC_IPC_SOCK, else CRYPTIRC_DATA/irc-core.sock, else
#     XDG_RUNTIME_DIR/irc-core.sock; a relative value against its unit's WorkingDirectory) — each directory as
#     written and fully resolved, the socket file's own link followed only from a root-only directory
#     (_sid_sock_dirs).
# "WARN <text>": a socket link the service account could have planted that points into <install dir> (ignored;
# the caller prints it). "REFUSE <text>" (rc 1): irc-core's settings can't be read safely (an untrusted or
# unsupported EnvironmentFile, a path that isn't usable, a relative path with no absolute WorkingDirectory, or
# no socket setting at all) — never a fallback to a default.
# _sid_sock_dirs <install dir> <socket path>: "DIR <its directory>", as written and fully resolved
# (_sid_data_dirs: a configured socket directory that is an alias of the install dir must refuse, like a data
# dir). The socket FILE: when its directory is one only root can change (_dir_closed) and the socket — or a
# link in its place — exists, also "DIR <where it really is>". A socket link in a directory the service
# account can change is never followed (it could aim it anywhere — into the install dir, to make every update
# refuse): if it points into <install dir> → WARN, ignored.
_sid_sock_dirs() {
    local s="$2" pd r
    if ! _sane_path "$s"; then
        printf 'REFUSE the IPC socket path %s is not a usable absolute path. Fix CRYPTIRC_IPC_SOCK / CRYPTIRC_DATA (systemctl cat cryptirc irc-core), then re-run. Nothing in the install directory was changed.\n' "$(_sid_clean "$s")"
        return 1
    fi
    pd=$(dirname -- "$s")
    _sid_data_dirs "$pd"     # the socket's directory as written and, when it is an alias, where it really is
    [[ -e "$s" || -L "$s" ]] || return 0
    if _dir_closed "$pd"; then
        r=$(readlink -e -- "$s" 2>/dev/null) && printf 'DIR %s\n' "$(dirname -- "$r")"
    elif [[ -L "$s" ]] && r=$(readlink -m -- "$s" 2>/dev/null); then
        case "$r" in
            "$1"|"$1"/*)
                printf 'WARN %s is a link to %s, in %s, which the service account can change: ignored (the services never need root'"'"'s files there; check who put it there).\n' \
                    "$(_sid_clean "$s")" "$(_sid_clean "$r")" "$(_sid_clean "$pd")" ;;
        esac
    fi
    return 0
}
# _sid_data_dirs <data dir>: "DIR <as written>" and, when it exists and resolves elsewhere, "DIR <resolved>".
_sid_data_dirs() {
    local r
    printf 'DIR %s\n' "$1"
    r=$(realpath -e -- "$1" 2>/dev/null) && [[ "$r" != "$1" ]] && printf 'DIR %s\n' "$r"
    return 0
}
# _sid_unit_abs <unit> <path>: <path> made absolute the way the unit's process sees it — a relative one against
# the unit's WorkingDirectory (unset: /, systemd's default). rc 1 when WorkingDirectory isn't an absolute path.
_sid_unit_abs() {
    local w
    if [[ "$2" == /* ]]; then printf '%s' "$2"; return 0; fi
    w=$(systemctl show -p WorkingDirectory --value "$1" 2>/dev/null) || return 1
    w="${w#[-!+]}"; [[ -n "$w" ]] || w=/
    [[ "$w" == /* ]] || return 1
    printf '%s' "${w%/}/${2#./}"
}
# _sid_why <rc>: what an rc of _unit_env / _unit_data_dir means, for a refusal.
_sid_why() {
    case "$1" in
        3) echo 'an EnvironmentFile that is not root-owned, is writable by others, or sits in a directory others can write sets it' ;;
        4) echo 'it is not a usable absolute path' ;;
        5) echo 'an EnvironmentFile with a wildcard in a directory part, which this script does not read' ;;
        *) echo "error $1" ;;
    esac
}
_sid_service_dirs() {
    local top="$1" wd="$2" wsock="${3:-${2%/}/irc-core.sock}" cdir csock v n rc
    _sid_data_dirs "$wd"
    _sid_sock_dirs "$top" "$wsock" || return 1
    systemctl cat irc-core.service >/dev/null 2>&1 || return 0
    rc=0; cdir=$(_unit_data_dir irc-core.service 2>/dev/null) || rc=$?
    if (( rc != 0 )); then
        printf 'REFUSE irc-core.service'"'"'s CRYPTIRC_DATA can'"'"'t be read safely (%s). Fix its settings (systemctl cat irc-core), then re-run. Nothing in the install directory was changed.\n' "$(_sid_why "$rc")"
        return 1
    fi
    _sid_data_dirs "$cdir"
    csock=""
    for n in CRYPTIRC_IPC_SOCK CRYPTIRC_DATA XDG_RUNTIME_DIR; do          # irc-core's own order
        rc=0; v=$(_unit_env irc-core.service "$n" 2>/dev/null) || rc=$?
        case "$rc" in
            0) [[ -n "$v" ]] || continue
               if [[ "$n" == CRYPTIRC_IPC_SOCK ]]; then csock=$v; else csock="${v%/}/irc-core.sock"; fi
               break ;;
            1) ;;
            *) printf 'REFUSE irc-core.service'"'"'s %s can'"'"'t be read safely (%s). Fix its settings (systemctl cat irc-core), then re-run. Nothing in the install directory was changed.\n' "$n" "$(_sid_why "$rc")"
               return 1 ;;
        esac
    done
    if [[ -z "$csock" ]]; then
        echo 'REFUSE irc-core.service sets none of CRYPTIRC_IPC_SOCK, CRYPTIRC_DATA, XDG_RUNTIME_DIR, so where its socket lives is unknown (the daemon refuses to start that way). Fix its settings (systemctl cat irc-core), then re-run. Nothing in the install directory was changed.'
        return 1
    fi
    if ! v=$(_sid_unit_abs irc-core.service "$csock"); then
        printf 'REFUSE irc-core.service'"'"'s socket path %s is relative and its WorkingDirectory is not an absolute path. Fix its settings (systemctl cat irc-core), then re-run. Nothing in the install directory was changed.\n' "$(_sid_clean "$csock")"
        return 1
    fi
    [[ "$v" == "$wsock" ]] || _sid_sock_dirs "$top" "$v" || return 1     # (the same socket: said once)
    return 0
}
# _sid_summary <output of _secure_install_dir>: one-line messages for the caller — SID_FIXED (what was
# made root's), SID_OTHER (what was left alone but belongs to another account or is writable by
# group/others; the first 8), SID_REFUSE (why it stopped). Empty = nothing to say.
# shellcheck disable=SC2034   # SID_* are read by the callers
_sid_summary() {
    local l f="" o="" no=0
    SID_FIXED=""; SID_OTHER=""; SID_REFUSE=""
    while IFS= read -r l; do
        case "$l" in
            "FIXED "*)  f+="${f:+, }${l#FIXED }" ;;
            "OTHER "*)  no=$((no + 1)); (( no <= 8 )) && o+="${o:+, }${l#OTHER }" ;;
            "REFUSE "*) SID_REFUSE="${l#REFUSE }" ;;
        esac
    done <<< "$1"
    (( no > 8 )) && o+=" and $((no - 8)) more"
    [[ -n "$f" ]] && SID_FIXED="handed back to root (the services only run from here; nothing in it needs their write access): $f"
    [[ -n "$o" ]] && SID_OTHER="left as they are, though they belong to another account or can be written by group/others (the services don't use them; check whether you still need them): $o"
    return 0
}
