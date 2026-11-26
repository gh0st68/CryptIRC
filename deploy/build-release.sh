#!/usr/bin/env bash
set -euo pipefail

available_memory_kib() {
    local proc_dir=$1 cgroup_root=$2 available=-1
    local field value controllers path directory root limit_file usage_file cache_field
    local limit usage cached remaining

    if [[ -r "$proc_dir/meminfo" ]]; then
        while read -r field value _; do
            if [[ "$field" == MemAvailable: && "$value" =~ ^[0-9]+$ ]]; then
                available=$((10#$value))
                break
            fi
        done < "$proc_dir/meminfo"
    fi

    if [[ -r "$proc_dir/self/cgroup" ]]; then
        while IFS=: read -r _ controllers path; do
            case ",$controllers," in
                ,,)
                    root=$cgroup_root
                    limit_file=memory.max
                    usage_file=memory.current
                    cache_field=inactive_file
                    ;;
                *,memory,*)
                    root=$cgroup_root/memory
                    limit_file=memory.limit_in_bytes
                    usage_file=memory.usage_in_bytes
                    cache_field=total_inactive_file
                    ;;
                *) continue ;;
            esac
            directory=$root${path%/}
            # An empty limit at this level can still inherit a limit from a parent.
            while :; do
                if [[ -r "$directory/$limit_file" && -r "$directory/$usage_file" ]]; then
                    read -r limit < "$directory/$limit_file" || limit=
                    read -r usage < "$directory/$usage_file" || usage=
                    if [[ "$limit" =~ ^[0-9]+$ && "$usage" =~ ^[0-9]+$ ]]; then
                        cached=0
                        if [[ -r "$directory/memory.stat" ]]; then
                            while read -r field value; do
                                if [[ "$field" == "$cache_field" && "$value" =~ ^[0-9]+$ ]]; then
                                    cached=$((10#$value))
                                    break
                                fi
                            done < "$directory/memory.stat"
                        fi
                        # Inactive file cache can be reclaimed under memory pressure.
                        (( cached <= 10#$usage )) || cached=$((10#$usage))
                        remaining=$(((10#$limit - 10#$usage + cached) / 1024))
                        (( remaining >= 0 )) || remaining=0
                        if (( available < 0 || remaining < available )); then
                            available=$remaining
                        fi
                    fi
                fi
                [[ "$directory" != "$root" ]] || break
                directory=${directory%/*}
            done
        done < "$proc_dir/self/cgroup"
    fi

    printf '%s\n' "$available"
}

build_release() {
    local mode=${CRYPTIRC_BUILD_MODE:-auto} available
    local -a options=()

    case "$mode" in
        auto|normal|low-memory) ;;
        *) printf 'Invalid CRYPTIRC_BUILD_MODE %q. Use auto, normal, or low-memory.\n' "$mode" >&2; return 2 ;;
    esac

    if [[ "$mode" == auto ]]; then
        available=$(available_memory_kib /proc /sys/fs/cgroup)
        if (( available >= 0 && available <= 2 * 1024 * 1024 )); then
            mode=low-memory
            printf 'Available build memory: %d MiB.\n' "$((available / 1024))"
        fi
    fi

    if [[ "$mode" == low-memory ]]; then
        printf 'Building CryptIRC in low-memory mode with one Cargo job.\n'
        # Disable optimization for this package only. Dependencies retain their
        # release settings, and both binaries still go into target/release.
        options=(--jobs 1 --config 'profile.release.package.cryptirc.opt-level=0')
    fi

    # Prevent build.rs's git status call from rewriting the owner's index as root.
    GIT_OPTIONAL_LOCKS=0 cargo build --release "${options[@]}" "$@" || return $?
    if [[ "$mode" == low-memory ]]; then
        printf 'Built CryptIRC in low-memory mode.\n'
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    build_release "$@"
fi
