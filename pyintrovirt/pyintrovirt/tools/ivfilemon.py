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
import threading
import functools
import traceback
from pyintrovirt import VMI, EventType, Event, OS, SystemCallIndex, WindowsSystemCall

HANDLE_TRACKER: set[tuple[int, int]] = set()
PROCESS_TRACKER: set[int] = set()
TRACKER_LOCK = threading.Lock()


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
    except Exception:  # pylint: disable=broad-exception-caught
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


def normalize_dict(event: Event, event_source: str) -> dict:
    """Normalize the event dictionary."""
    obj = event.to_dict().get("event", {})
    result = {
        "source": event_source,
        "arguments": obj.get("syscall", {}).get("arguments", {}),
        "index": obj.get("syscall", {}).get("index", None),
        "result": obj.get("syscall", {}).get("result", {}),
        "pid": obj.get("task", {}).get("pid", None),
        "tid": obj.get("task", {}).get("tid", None),
        "process_name": obj.get("task", {}).get("process_name", None)
    }
    # Flatten the output JSON so it's not so nested
    return result


def emit_process_event(event: Event, *, print_json: bool, pretty_json: bool):
    """Log the event."""
    if print_json:
        obj = normalize_dict(event, "process_tracking")
        sys.stdout.write(json.dumps(obj, indent=2 if pretty_json else None) + "\n")
    else:
        sys.stdout.write(f"PROCESS TRACKING: {str(event)}\n")


def emit_file_event(event: Event, *, print_json: bool, pretty_json: bool):
    """Log the event."""
    if print_json:
        obj = normalize_dict(event, "file_handle_tracking")
        sys.stdout.write(json.dumps(obj, indent=2 if pretty_json else None) + "\n")
    else:
        sys.stdout.write(f"FILE HANDLE TRACKING: {str(event)}\n")


def handle_sysret(_vmi: VMI, event: Event, *, monitor_file_paths: list[str], print_json: bool, pretty_json: bool, follow_process: bool, ignore_processes: set[str]):
    """Handle system call return."""
    handler: WindowsSystemCall = event.get_syscall_handler()

    match event.syscall_index:
        case SystemCallIndex.NtTerminateProcess:
            if follow_process and handler.result().NT_SUCCESS():
                target = handler.target_pid()
                with TRACKER_LOCK:
                    if target in PROCESS_TRACKER:
                        emit_process_event(event, print_json=print_json, pretty_json=pretty_json)
                        PROCESS_TRACKER.discard(target)
                        return

    if follow_process:
        with TRACKER_LOCK:
            if event.pid in PROCESS_TRACKER:
                emit_process_event(event, print_json=print_json, pretty_json=pretty_json)

    handle: int = get_file_handle(handler)
    if handle == 0:
        return  # Nothing to do

    key = (event.pid, handle)
    with TRACKER_LOCK:
        if key in HANDLE_TRACKER:
            emit_file_event(event, print_json=print_json, pretty_json=pretty_json)
            return

    obj_attr = get_object_attributes(handler)
    if not obj_attr:
        return  # Nothing to do

    for path in monitor_file_paths:
        if path_matches(path, obj_attr, event.kpcr):
            with TRACKER_LOCK:
                HANDLE_TRACKER.add(key)
                if follow_process:
                    PROCESS_TRACKER.add(event.pid)
            emit_file_event(event, print_json=print_json, pretty_json=pretty_json)
            return


def handle_syscall(_vmi: VMI, event: Event, *, print_json: bool, pretty_json: bool, follow_process: bool, ignore_processes: set[str]):
    """Handle a system call."""
    if event.process_name.strip().lower() in ignore_processes:
        return

    if event.will_return():
        event.hook_return(True)

    handler: WindowsSystemCall = event.get_syscall_handler()

    match event.syscall_index:
        case SystemCallIndex.NtClose:
            key = (event.pid, get_file_handle(handler))
            with TRACKER_LOCK:
                if key in HANDLE_TRACKER:
                    HANDLE_TRACKER.discard(key)
                    emit_file_event(event, print_json=print_json, pretty_json=pretty_json)
        case SystemCallIndex.NtTerminateProcess:
            if not follow_process:
                return
            target = handler.target_pid()
            with TRACKER_LOCK:
                if target in PROCESS_TRACKER and (not event.will_return() or target == event.pid):
                    emit_process_event(event, print_json=print_json, pretty_json=pretty_json)
                    PROCESS_TRACKER.discard(target)
                    return
        case _:
            if not follow_process:
                return
            if not event.will_return():
                with TRACKER_LOCK:
                    if event.pid in PROCESS_TRACKER:
                        emit_process_event(event, print_json=print_json, pretty_json=pretty_json)



def main():
    """Entry Point."""
    parser = argparse.ArgumentParser("ivfilemon", description="Monitor and track file access.")
    parser.add_argument("-d", "--domain", help="Attach to the target domain by name or PID", required=True)
    parser.add_argument(
        "-f",
        "--file-path",
        type=str,
        action="append",
        help="Monitor accesses to this file (full-path and case insensitive) (can be specified multiple times)",
        dest="file_paths",
        required=True,
    )
    parser.add_argument("--follow-process", action="store_true", help="Follow the processes that access monitored files")
    parser.add_argument("--ignore-process", action="append", help="Ignore this process for file access and process tracking (can be specified multiple times)", dest="ignore_processes")
    parser.add_argument("--json", action="store_true", help="Print the events as JSON")
    parser.add_argument("--pretty-json", action="store_true", help="Pretty-print JSON output (Warning: LOUD)")
    args = parser.parse_args()

    print_json = bool(args.json)
    pretty_json = bool(args.pretty_json)
    follow_process = bool(args.follow_process)

    monitor_file_paths: list[str] = []
    for path in args.file_paths:
        monitor_file_paths.append(normalize_path(path))
    ignore_processes: set[str] = set()
    for process in args.ignore_processes:
        ignore_processes.add(process.strip().lower())
    rc = 1

    try:
        with VMI(args.domain) as vmi:
            if vmi.guest_os() != OS.Windows:
                print("Only Windows guests are supported for this tool.")
                return rc

            print(f"Guest: {vmi.guest_os().name}", file=sys.stderr)

            if not follow_process:
                vmi.filter_system_call_category("file")
            else:
                vmi.default_system_call_filter()

            syscall_handler = functools.partial(
                handle_syscall,
                print_json=print_json,
                pretty_json=pretty_json,
                follow_process=follow_process,
                ignore_processes=ignore_processes
            )
            sysret_handler = functools.partial(
                handle_sysret,
                monitor_file_paths=monitor_file_paths,
                print_json=print_json,
                pretty_json=pretty_json,
                follow_process=follow_process,
                ignore_processes=ignore_processes
            )
            vmi.register_callback(EventType.EVENT_FAST_SYSCALL, syscall_handler)
            vmi.register_callback(EventType.EVENT_FAST_SYSCALL_RET, sysret_handler)
            vmi.intercept_system_calls(True)
            vmi.poll(blocking=True)  # Handles cntrl+c for you
    except Exception:  # pylint: disable=broad-exception-caught
        traceback.print_exc()
        return rc

    rc = 0
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
