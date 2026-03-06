#!/usr/bin/env python3
"""@example ivfilemon.py

IntroVirt Python example: A simple example file monitoring tool.

Demonstrates monitoring file access by process/action and file handle tracking.

Usage:
  sudo python3 ivfilemon.py -d win10 -f "C:\\users\\user\\desktop\\test.txt"
"""
import sys
import json
import argparse
import traceback
from pyintrovirt import VMI, EventType, Event, OS, SystemCallIndex, WindowsSystemCall, nt_success

PRETTY_JSON = False
PRINT_JSON = False
MONITOR_FILE_PATHS = None
HANDLE_TRACKER = set()


def normalize_path(path: str) -> str:
    """Normalize a path."""
    path = path.replace("/", "\\").lower()
    if path.startswith("\\??\\"):
        path = path[4:]
    return path


def path_matches(user_normalized: str, obj_attr, kpcr) -> bool:
    """Check if a path matches."""
    if obj_attr is None:
        return False
    try:
        guest_path = obj_attr.FullPath(kpcr)
        if not guest_path:
            guest_path = obj_attr.ObjectName()
    except Exception:
        return False
    return normalize_path(guest_path) == user_normalized


def get_object_attributes(handler):
    """Return OBJECT_ATTRIBUTES struct available."""
    if handler is None:
        return None
    if not hasattr(handler, "ObjectAttributes"):
        return None
    return handler.ObjectAttributes()


def get_file_handle(handler) -> int:
    """Return file handle if available."""
    if handler is None:
        return 0
    if not hasattr(handler, "FileHandle"):
        return 0
    return handler.FileHandle()


def print_event_json(event: Event):
    """Print the event as JSON"""
    sys.stdout.write(json.dumps(event.to_dict(), indent=PRETTY_JSON) + "\n")


def emit(event: Event):
    """Log the event."""
    if PRINT_JSON:
        print_event_json(event)
    else:
        sys.stdout.write(str(event) + "\n")


def handle_sysret(vmi: VMI, event: Event):
    """Handle system call return."""
    handler: WindowsSystemCall = event.get_syscall_handler()
    handle: int = get_file_handle(handler)
    if handle == 0:
        return  # Nothing to do

    key = (event.pid, handle)
    if key in HANDLE_TRACKER:
        emit(event)
        return

    obj_attr = get_object_attributes(handler)
    if not obj_attr:
        return  # Nothing to do

    for path in MONITOR_FILE_PATHS:
        if path_matches(path, obj_attr, event.kpcr):
            HANDLE_TRACKER.add(key)
            emit(event)
            return


def handle_syscall(vmi: VMI, event: Event):
    """Handle a system call."""
    if event.will_return():
        event.hook_return(True)

    handler: WindowsSystemCall = event.get_syscall_handler()

    match event.syscall_index:
        case SystemCallIndex.NtClose:
            key = (event.pid, get_file_handle(handler))
            HANDLE_TRACKER.discard(key)
            emit(event)


def main():
    """Entry Point."""
    parser = argparse.ArgumentParser("ivfilemon", description="Monitor and track file access.")
    parser.add_argument("-d", "--domain", help="Attach to the target domain by name or PID", required=True)
    parser.add_argument("-f", "--file-path", type=str, action="append", help="Monitor accesses to this file (full-path and case insensitive) (can be specified multiple times)", dest="file_paths", required=True)
    parser.add_argument("--json", action="store_true", help="Print the events as JSON")
    parser.add_argument("--pretty-json", action="store_true", help="Pretty-print JSON output (Warning: LOUD)")
    args = parser.parse_args()

    global PRETTY_JSON
    global PRINT_JSON
    global MONITOR_FILE_PATHS
    PRINT_JSON = args.json
    PRETTY_JSON = args.pretty_json or None
    MONITOR_FILE_PATHS = []
    for path in args.file_paths:
        MONITOR_FILE_PATHS.append(normalize_path(path))
    rc = 1

    try:
        with VMI(args.domain) as vmi:
            if vmi.guest_os() != OS.Windows:
                print("Only Windows guests are supported for this tool.")
                return rc

            print(f"Guest: {vmi.guest_os().name}")

            vmi.filter_system_call_category("file")
            vmi.register_callback(EventType.EVENT_FAST_SYSCALL, handle_syscall)
            vmi.register_callback(EventType.EVENT_FAST_SYSCALL_RET, handle_sysret)
            vmi.intercept_system_calls(True)
            vmi.poll(blocking=True)  # Handles cntrl+c for you
    except Exception as exc:
        traceback.print_exc()
        return rc

    rc = 0
    return rc

if __name__ == "__main__":
    rc = main()