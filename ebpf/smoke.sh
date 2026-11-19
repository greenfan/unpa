#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(id -u)" -ne 0 ]; then
    echo 'check-live needs root for a private network namespace and BPF' >&2
    exit 1
fi
exec unshare --net python3 "$root/ebpf/smoke.py" "$root/build/unpa"
