#!/bin/bash
# Guest smoke checks for the Linux additions branch.
# Usage: tests/guest-smoke.sh <linux-domain> [windows-domain]
# Skips with exit 0 when libvirt is down or the domain cannot be attached.
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <linux-domain> [windows-domain]" >&2
    exit 2
fi

LINUX_DOM=$1
WINDOWS_DOM=${2:-}

if [[ ! -S /var/run/libvirt/libvirt-sock ]]; then
    echo "skip: libvirt is not available; guest smoke not run"
    exit 0
fi

if ! virsh domstate "$LINUX_DOM" >/dev/null 2>&1; then
    echo "skip: cannot attach to domain '$LINUX_DOM'"
    exit 0
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${INTROVIRT_BIN:-$ROOT/build/tools}

out=$("$BIN/ivguestinfo" -D "$LINUX_DOM" -q)
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q "Detected Linux"

proc=$("$BIN/ivprocinfo" -D "$LINUX_DOM")
printf '%s\n' "$proc" | head -n 20
printf '%s\n' "$proc" | grep -q "PID "

if [[ -n "$WINDOWS_DOM" ]]; then
    if ! virsh domstate "$WINDOWS_DOM" >/dev/null 2>&1; then
        echo "skip: cannot attach to Windows domain '$WINDOWS_DOM'"
        exit 0
    fi
    win=$(env -u INTROVIRT_LINUX_PROFILE "$BIN/ivguestinfo" -D "$WINDOWS_DOM" -q)
    printf '%s\n' "$win"
    printf '%s\n' "$win" | grep -q "Detected Windows"
fi

echo "linux guest smoke passed"
