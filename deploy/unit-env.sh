# shellcheck shell=bash
# How a systemd unit's settings are read from root-owned sources — shared by deploy/update.sh and
# both installers (sourced from the same checkout; never run on its own). Values come only from the
# unit files and drop-ins (`systemctl show`) and from EnvironmentFile=s that are root-owned and not
# group/world-writable; never from the service's own /proc/<pid>/environ (the unprivileged service
# account can rewrite that — _live_data_dir reads it only to cross-check). Moved here from update.sh
# (round 6), plus _unit_data_dir; round 7: wildcard EnvironmentFile= entries, the live cross-check,
# unit-file quoting and update.sh's stock irc-core.service hashes (for the installers too).

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
