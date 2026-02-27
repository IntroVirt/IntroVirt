"""VMI Helpers for the IntroVirt Python Bindings."""

import signal
import functools
import threading
from contextlib import ContextDecorator
from typing import Optional, Union

import introvirt  # type: ignore[import-not-found]  # noqa: F401  # pylint: disable=import-error

from .domain import Domain, DomainInformation
from .event import CallbackEventHandler, EventCallback


def _require_attachment(func):
    """Helper decorator so we don't need to check self._domain at the beginning of VMI methods."""
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if getattr(self, "_domain") is None:
            raise RuntimeError(f"Must call 'attach()' before '{func.__name__}'")
        return func(self, *args, **kwargs)
    return wrapper


def _require_no_attachment(func):
    """Helper decorator so we don't need to check self._domain at the beginning of VMI methods."""
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if getattr(self, "_domain") is not None:
            raise RuntimeError(f"Must call 'attach()' before '{func.__name__}'")
        return func(self, *args, **kwargs)
    return wrapper


def _normalize_syscall(syscall: Union[introvirt.SystemCallIndex, str, int]) -> introvirt.SystemCallIndex:
    """Normalize a system call index value as an integer, SystemCallIndex enum, or string."""
    if isinstance(syscall, str):
        # Forst check if it's a string representation of a system call index integer
        try:
            return introvirt.SystemCallIndex(int(syscall))
        except ValueError:
            # Case-insensitive and supports 'Zw' (e.g NtCreateFile, ntcreatefile, and ZwCreateFile would all work).
            return introvirt.SystemCallIndex(introvirt.system_call_from_string(syscall))
    elif isinstance(syscall, int):
        return introvirt.SystemCallIndex(syscall)
    elif isinstance(syscall, introvirt.SystemCallIndex):
        return syscall
    else:
        raise ValueError("Invalid type for system call index. Must be a valid integer, string, or SystemCallIndex type.")


def _normalize_syscalls(syscalls: list[Union[introvirt.SystemCallIndex, str, int]]) -> list[introvirt.SystemCallIndex]:
    """Normalize a list of system call index values as integers, SystemCallIndex enums, or strings."""
    norm_syscalls = []
    for syscall in syscalls:
        norm_syscalls.append(_normalize_syscall(syscall))

    return norm_syscalls


class VMI(ContextDecorator):
    """The main class used for Virtial Machine Introspection of guest domains."""

    def __init__(self, domain_id: Optional[Union[int, str]] = None):
        """
        Initialize a VMI object which can be used to attach to running domains.

        Args:
            domain_id: The target domain to attach to. Can be an integer domain ID or a string domain name.
                       The domain ID is the Qemu process PID and the domain name is the name (e.g. "win10").
        """
        #: The hypervisor instance we're connected to
        self._hypervisor: introvirt.Hypervisor = None
        #: An event handler we'll use to register callbacks that will receive events
        self._event_handler: CallbackEventHandler = None
        #: Thread that runs _poll_thread or _interrupt_listener based on the blocking value in poll().
        self._thread: threading.Thread = None
        #: The domain we're introspecting.
        self._domain: Domain = None
        #: The list of system calls currently being filtered
        self._filtering_syscalls: set[introvirt.SystemCallIndex] = set()

        self._event_handler = CallbackEventHandler()
        self._hypervisor = introvirt.Hypervisor.instance()
        if domain_id:
            self.attach(domain_id)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.detach()

    def __del__(self):
        self.detach()

    def _interrupt_listener(self):
        """Interrupt listener (when blocking is True in the event poller)"""
        signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGINT])
        try:
            signal.sigwait([signal.SIGINT])
        except (ValueError, OSError):
            return
        self.detach()

    def _poll_thread(self):
        """Polling thread."""
        self._domain.poll(self._event_handler)

    @_require_no_attachment
    def attach(self, domain_id: Union[int, str]) -> None:
        """Attach to the target domain."""
        self._domain = Domain(domain_id, self._hypervisor)

    def detach(self) -> None:
        """Detach from the domain. Safe to call multiple times."""
        if not self._domain:
            return
        self._domain.detach()
        self._domain = None

    @_require_attachment
    def poll(self, blocking: bool = False):
        """Start the polling thread."""
        if not blocking:
            self._thread = threading.Thread(target=self._poll_thread)
            self._thread.start()
            return

        # Block SIGINT in main so a dedicated thread can sigwait() and call interrupt();
        # otherwise Ctrl+C is never seen while main is blocked in C++ poll().
        signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
        self._thread = threading.Thread(target=self._interrupt_listener, daemon=True)
        self._thread.start()
        self._domain.poll(self._event_handler)  # Blocking until self._domain.detach()

    def hypervisor_name(self) -> str:
        """Get the name of the hypervisor."""
        return self._hypervisor.hypervisor_name()

    def hypervisor_version(self) -> str:
        """Get the version of the hypervisor."""
        return self._hypervisor.hypervisor_version()

    def hypervisor_patch_version(self) -> str:
        """Get the patch version of the hypervisor."""
        return self._hypervisor.hypervisor_patch_version()

    def library_name(self) -> str:
        """Get the name of the library."""
        return self._hypervisor.library_name()

    def library_version(self) -> str:
        """Get the version of the library."""
        return self._hypervisor.library_version()

    def get_running_domains(self) -> list[DomainInformation]:
        """Get the running domains."""
        return [DomainInformation(domain_name=domain.domain_name, domain_id=domain.domain_id) for domain in self._hypervisor.get_running_domains()]

    @_require_attachment
    def guest_os(self) -> introvirt.OS:
        """Get the guest OS type."""
        return self._domain.os

    @_require_attachment
    def filter_system_calls(self, syscalls: list[Union[introvirt.SystemCallIndex, int, str]]):
        norm_syscalls: list[introvirt.SystemCallIndex] = _normalize_syscalls(syscalls)
        self._filtering_syscalls.update(norm_syscalls)
        for syscall in self._filtering_syscalls:
            self._domain.filter_system_call(syscall, True)
        should_filter = (len(self._filtering_syscalls) > 0)
        self._domain.filter_system_calls(should_filter)

    @_require_attachment
    def unfilter_system_calls(self, syscalls: list[Union[introvirt.SystemCallIndex, str, int]]):
        norm_syscalls: list[introvirt.SystemCallIndex] = _normalize_syscalls(syscalls)
        self._filtering_syscalls.difference_update(norm_syscalls)
        for syscall in set(norm_syscalls):
            self._domain.filter_system_call(syscall, False)
        should_filter = (len(self._filtering_syscalls) > 0)
        self._domain.filter_system_calls(should_filter)

    @_require_attachment
    def clear_system_call_filter(self):
        """Clear the system call filter if set."""
        self._filtering_syscalls.clear()
        self._domain.clear_system_call_filter()
        self._domain.filter_system_calls(False)

    @_require_attachment
    def intercept_system_calls(self, enabled: bool):
        """Toggle system call interception on/off. Required to received system call events at all regardless of filter."""
        self._domain.intercept_system_calls(enabled)

    @_require_attachment
    def intercept_cr_writes(self, cr: int, enabled: bool):
        """Intercept CR writes."""
        self._domain.intercept_cr_writes(cr, enabled)

    def set_global_callback(self, callback: EventCallback):
        """Set the global callback that gets called for any event type."""
        self._event_handler.set_global_event_callback(callback)

    def register_callback(self, event_type: introvirt.EventType, callback: EventCallback):
        """Register a callback for a given event type."""
        self._event_handler.register_event_callback(event_type, callback)
