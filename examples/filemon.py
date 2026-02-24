#!/usr/bin/env python3
"""IntroVirt Python example: File monitor (ivfilemon clone).

Monitors a guest path: on NtCreateFile/NtOpenFile match, tracks the handle;
reports NtReadFile, NtWriteFile, NtQueryInformationFile, NtSetInformationFile,
NtDeviceIoControlFile, NtClose, NtDuplicateObject for tracked handles.

Usage:
  python3 filemon.py DOMAIN --path GUEST_PATH [--no-flush]

Example:
  python3 filemon.py myvm --path C:\\Windows\\System32\\config\\SAM

Requires root and IntroVirt-patched hypervisor.
"""
import argparse
import signal
import sys
import threading

import introvirt

_domain = None


def _interrupt_listener():
    signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGINT])
    while True:
        try:
            signal.sigwait([signal.SIGINT])
        except (ValueError, OSError):
            break
        d = _domain
        if d is not None:
            d.interrupt()


def normalize_path(path: str) -> str:
    path = path.replace("/", "\\").lower()
    if path.startswith("\\??\\"):
        path = path[4:]
    return path


def path_matches(user_normalized: str, obj_attr, kpcr) -> bool:
    if obj_attr is None:
        return False
    try:
        guest_path = obj_attr.FullPath(kpcr)
        if not guest_path:
            guest_path = obj_attr.ObjectName()
    except Exception:
        return False
    return normalize_path(guest_path) == user_normalized


def get_object_attributes(handler, index: int):
    """Return OBJECT_ATTRIBUTES for create/open/query/delete syscalls; handler from get_concrete_handler."""
    if handler is None:
        return None
    if index == introvirt.SystemCallIndex_NtCreateFile:
        return handler.ObjectAttributes() if isinstance(handler, introvirt.NtCreateFile) else None
    if index == introvirt.SystemCallIndex_NtOpenFile:
        return handler.ObjectAttributes() if isinstance(handler, introvirt.NtOpenFile) else None
    if index == introvirt.SystemCallIndex_NtQueryAttributesFile:
        return handler.ObjectAttributes() if isinstance(handler, introvirt.NtQueryAttributesFile) else None
    if index == introvirt.SystemCallIndex_NtQueryFullAttributesFile:
        return handler.ObjectAttributes() if isinstance(handler, introvirt.NtQueryFullAttributesFile) else None
    if index == introvirt.SystemCallIndex_NtDeleteFile:
        return handler.ObjectAttributes() if isinstance(handler, introvirt.NtDeleteFile) else None
    return None


def get_file_handle(handler, index: int) -> int:
    """Return file handle for read/write/query/set/ioctl or create/open return; handler from get_concrete_handler."""
    if handler is None:
        return 0
    if index == introvirt.SystemCallIndex_NtReadFile:
        return handler.FileHandle() if isinstance(handler, introvirt.NtReadFile) else 0
    if index == introvirt.SystemCallIndex_NtWriteFile:
        return handler.FileHandle() if isinstance(handler, introvirt.NtWriteFile) else 0
    if index == introvirt.SystemCallIndex_NtQueryInformationFile:
        return handler.FileHandle() if isinstance(handler, introvirt.NtQueryInformationFile) else 0
    if index == introvirt.SystemCallIndex_NtSetInformationFile:
        return handler.FileHandle() if isinstance(handler, introvirt.NtSetInformationFile) else 0
    if index == introvirt.SystemCallIndex_NtDeviceIoControlFile:
        return handler.FileHandle() if isinstance(handler, introvirt.NtDeviceIoControlFile) else 0
    if index == introvirt.SystemCallIndex_NtCreateFile:
        return handler.FileHandle() if isinstance(handler, introvirt.NtCreateFile) else 0
    if index == introvirt.SystemCallIndex_NtOpenFile:
        return handler.FileHandle() if isinstance(handler, introvirt.NtOpenFile) else 0
    return 0


class FileMonitor(introvirt.EventCallback):
    def __init__(self, target_path: str, flush: bool = True):
        super().__init__()
        self._path_norm = normalize_path(target_path)
        self._flush = flush
        self._handles = set()  # (pid, handle)
        self._lock = threading.Lock()
        self._out_lock = threading.Lock()

    def process_event(self, event):
        try:
            if event.os_type() != introvirt.OS_Windows:
                return
            wevent = introvirt.WindowsEvent_from_event(event)
            if wevent is None:
                print("WindowsEvent_from_event failed", file=sys.stderr)
                print(f"event: {event}", file=sys.stderr)
                return
            if event.type() == introvirt.EventType_EVENT_FAST_SYSCALL:
                self._handle_syscall(wevent)
            elif event.type() == introvirt.EventType_EVENT_FAST_SYSCALL_RET:
                self._handle_sysret(wevent)
        except Exception as e:
            print(f"process_event error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

    def _handle_syscall(self, wevent):
        handler = introvirt.get_concrete_handler(wevent)
        if handler is None or not handler.supported():
            return
        index = wevent.syscall().index()
        pid = wevent.task().pid()
        task = wevent.task()
        pcr = task.pcr()

        if index in (
            introvirt.SystemCallIndex_NtCreateFile,
            introvirt.SystemCallIndex_NtOpenFile,
        ):
            obj_attr = get_object_attributes(handler, index)
            if path_matches(self._path_norm, obj_attr, pcr):
                wevent.syscall().hook_return(True)
                self._emit(wevent)
            return
        if index in (
            introvirt.SystemCallIndex_NtQueryAttributesFile,
            introvirt.SystemCallIndex_NtQueryFullAttributesFile,
            introvirt.SystemCallIndex_NtDeleteFile,
        ):
            obj_attr = get_object_attributes(handler, index)
            if path_matches(self._path_norm, obj_attr, pcr):
                wevent.syscall().hook_return(True)
                self._emit(wevent)
            return
        if index == introvirt.SystemCallIndex_NtClose:
            h = handler.Handle() if isinstance(handler, introvirt.NtClose) else 0
            if h != 0:
                with self._lock:
                    key = (pid, h)
                    if key in self._handles:
                        self._handles.discard(key)
                        wevent.syscall().hook_return(True)
                        self._emit(wevent)
            return
        if index == introvirt.SystemCallIndex_NtDuplicateObject:
            wevent.syscall().hook_return(True)
            return
        if index in (
            introvirt.SystemCallIndex_NtReadFile,
            introvirt.SystemCallIndex_NtWriteFile,
            introvirt.SystemCallIndex_NtQueryInformationFile,
            introvirt.SystemCallIndex_NtSetInformationFile,
            introvirt.SystemCallIndex_NtDeviceIoControlFile,
        ):
            fh = get_file_handle(handler, index)
            with self._lock:
                if (pid, fh) in self._handles:
                    self._emit(wevent)

    def _handle_sysret(self, wevent):
        handler = introvirt.get_concrete_handler(wevent)
        if handler is None or not handler.supported():
            return
        ok, value = introvirt.get_windows_syscall_result_value(wevent)
        if not ok or not introvirt.nt_success(value):
            return
        index = wevent.syscall().index()
        pid = wevent.task().pid()
        task = wevent.task()
        pcr = task.pcr()

        if index == introvirt.SystemCallIndex_NtCreateFile and isinstance(handler, introvirt.NtCreateFile):
            obj_attr = handler.ObjectAttributes()
            if path_matches(self._path_norm, obj_attr, pcr):
                with self._lock:
                    self._handles.add((pid, handler.FileHandle()))
                self._emit(wevent)
            return
        if index == introvirt.SystemCallIndex_NtOpenFile and isinstance(handler, introvirt.NtOpenFile):
            obj_attr = handler.ObjectAttributes()
            if path_matches(self._path_norm, obj_attr, pcr):
                with self._lock:
                    self._handles.add((pid, handler.FileHandle()))
                self._emit(wevent)
            return
        if index == introvirt.SystemCallIndex_NtDuplicateObject and isinstance(handler, introvirt.NtDuplicateObject):
            src, tgt = handler.SourceHandle(), handler.TargetHandle()
            with self._lock:
                if (pid, src) in self._handles:
                    self._handles.add((pid, tgt))
                    self._emit(wevent)
            return
        if index in (
            introvirt.SystemCallIndex_NtQueryAttributesFile,
            introvirt.SystemCallIndex_NtQueryFullAttributesFile,
            introvirt.SystemCallIndex_NtDeleteFile,
        ):
            self._emit(wevent)

    def _emit(self, wevent):
        with self._out_lock:
            task = wevent.task()
            vcpu = wevent.vcpu()
            line = (
                f"Vcpu {vcpu.id()}: [{task.pid()}:{task.tid()}] {task.process_name()}\n"
                f"{wevent.syscall().name()}\n"
            )
            sys.stdout.write(line)
            if self._flush:
                sys.stdout.flush()


def main():
    global _domain
    parser = argparse.ArgumentParser(
        description="Monitor file access for a guest path (ivfilemon clone)."
    )
    parser.add_argument("domain", metavar="DOMAIN", help="Domain name or ID")
    parser.add_argument("--path", "-P", required=True, metavar="PATH", help="Guest path to monitor")
    parser.add_argument("--no-flush", action="store_true", help="Don't flush after each event")
    args = parser.parse_args()

    try:
        hypervisor = introvirt.Hypervisor.instance()
    except Exception as e:
        print(f"Failed to get hypervisor: {e}", file=sys.stderr)
        return 1
    try:
        _domain = hypervisor.attach_domain(args.domain)
    except Exception as e:
        print(f"Failed to attach: {e}", file=sys.stderr)
        return 1
    if not _domain.detect_guest():
        print("Failed to detect guest OS", file=sys.stderr)
        return 1

    guest = _domain.guest()
    if guest is None or guest.os() != introvirt.OS_Windows:
        print("Windows guest required", file=sys.stderr)
        return 1
    win_guest = introvirt.WindowsGuest_from_guest(guest)
    if win_guest is None:
        print("Windows guest required", file=sys.stderr)
        return 1

    # Match ivfilemon: enable at domain level, set which syscalls to trap at guest level only.
    # Do not call set_64/set_32 on the domain filter; the guest converts SystemCallIndex to native
    # indices and updates the filter. Otherwise we trap all syscalls and get unsupported ones.
    _domain.system_call_filter().enabled(True)
    for idx in (
        introvirt.SystemCallIndex_NtCreateFile,
        introvirt.SystemCallIndex_NtOpenFile,
        introvirt.SystemCallIndex_NtClose,
        introvirt.SystemCallIndex_NtReadFile,
        introvirt.SystemCallIndex_NtWriteFile,
        introvirt.SystemCallIndex_NtDuplicateObject,
        introvirt.SystemCallIndex_NtQueryInformationFile,
        introvirt.SystemCallIndex_NtSetInformationFile,
        introvirt.SystemCallIndex_NtDeviceIoControlFile,
        introvirt.SystemCallIndex_NtQueryAttributesFile,
        introvirt.SystemCallIndex_NtQueryFullAttributesFile,
        introvirt.SystemCallIndex_NtDeleteFile,
    ):
        win_guest.set_system_call_filter(_domain.system_call_filter(), idx, True)
    _domain.intercept_system_calls(True)

    monitor = FileMonitor(args.path, flush=not args.no_flush)
    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
    listener = threading.Thread(target=_interrupt_listener, daemon=True)
    listener.start()
    _domain.poll(monitor)
    return 0


if __name__ == "__main__":
    sys.exit(main())
