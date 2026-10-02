#!/bin/bash
# Guest smoke checks for the Windows 11 fixes branch.
# Usage: tests/guest-smoke.sh <windows-domain>
# Skips with exit 0 when libvirt is down or the domain cannot be attached.
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <windows-domain>" >&2
    exit 2
fi

DOM=$1

if [[ ! -S /var/run/libvirt/libvirt-sock ]]; then
    echo "skip: libvirt is not available; guest smoke not run"
    exit 0
fi

if ! virsh domstate "$DOM" >/dev/null 2>&1; then
    echo "skip: cannot attach to domain '$DOM'"
    exit 0
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${INTROVIRT_BIN:-$ROOT/build/tools}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# A short-lived process must return without aborting in ~RegisterGuard.
"$BIN/ivexec" -D "$DOM" -t 'C:\Windows\System32\cmd.exe' -a '/c exit' -e -T 90

# A drive letter that is not in \GLOBAL?? must warn and must not abort.
set +e
"$BIN/ivexec" -D "$DOM" -t 'Q:\introvirt-no-such.exe' -T 30 >"$tmp/out" 2>"$tmp/err"
rc=$?
set -e
cat "$tmp/err" >&2
if [[ $rc -gt 128 ]]; then
    echo "ivexec aborted while resolving a missing drive letter (status $rc)" >&2
    exit 1
fi
grep -q 'GLOBAL??' "$tmp/err"

"$BIN/ivbugcheck" -D "$DOM"
echo "win11 guest smoke passed"
