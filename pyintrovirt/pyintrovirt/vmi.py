"""VMI Helpers for the IntroVirt Python Bindings."""

import signal
import threading
from contextlib import ContextDecorator
from typing import Callable, Optional, Union

import introvirt  # type: ignore[import-not-found]  # noqa: F401  # pylint: disable=import-error

from .event_type import EventType


class CallbackEventHandler(introvirt.EventCallback):
    """Event callback handler."""

    def __init__(self):
        super().__init__()  # required so SWIG director wrapper is created for poll()
        self.event_callbacks = {}
        self.global_event_callback = None

    def set_global_event_callback(self, callback: Callable):
        """Set a callback to be called with every event type."""
        self.global_event_callback = callback

    def register_event_callback(self, event_type: EventType, callback: Callable):
        """Set a callback to be called for a specific event type."""
        self.event_callbacks[event_type] = callback

    def process_event(self, event):
        """Called for each event received."""
        if not self.event_callbacks and not self.global_event_callback:
            return  # no callbacks to call
        if self.global_event_callback:
            self.global_event_callback(event)
        callback = self.event_callbacks.get(EventType(event.type()))
        if callback:
            callback(event)


class VMI(ContextDecorator):
    """The main class used for Virtial Machine Introspection of guest Virtual Machines."""

    def __init__(self, target_vm: Optional[Union[int, str]] = None):
        """
        Initialize a VMI object which can be used to attach to running VMs.

        Args:
            target_vm: The target VM (domain) to attach to. Can be an integer domain ID or a string domain name.
                       The domain ID is the Qemu process PID and the domain name is the domain/VM's name (e.g. "win10").
        """
        self.target = target_vm
        self.hypervisor = introvirt.Hypervisor.instance()
        self.event_handler = CallbackEventHandler()
        self.thread = None
        self.domain = None
        if self.target:
            self.attach(self.target)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.detach()

    def __del__(self):
        self.detach()

    def start_event_poller(self, blocking: bool = False):
        """Start the polling thread."""
        if not self.domain:
            raise RuntimeError("VMI must be attached to a VM/domain. Attach first.")
        if not blocking:
            self.thread = threading.Thread(target=self._poll_thread)
            self.thread.start()
        else:
            # Block SIGINT in main so a dedicated thread can sigwait() and call interrupt();
            # otherwise Ctrl+C is never seen while main is blocked in C++ poll().
            signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
            self.thread = threading.Thread(target=self._interrupt_listener, daemon=True)
            self.thread.start()
            self.domain.poll(self.event_handler)

    def _interrupt_listener(self):
        """Interrupt listener (when blocking is True in the event poller)"""
        signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGINT])
        while True:
            try:
                signal.sigwait([signal.SIGINT])
            except (ValueError, OSError):
                break
        self.detach()

    def _poll_thread(self):
        """Polling thread."""
        if not self.domain:
            return  # Nothing to do
        self.domain.poll(self.event_handler)

    def attach(self, target_vm: Union[int, str]) -> None:
        """Attach to the target VM (domain)."""
        if self.domain is not None:
            raise RuntimeError("VMI is already attached to a VM/domain. Detach first.")
        self.target = target_vm
        self.domain = self.hypervisor.attach_domain(self.target)
        if not self.domain.detect_guest():
            raise RuntimeError("Failed to detect guest OS")

    def detach(self) -> None:
        """Detach from the domain. Safe to call multiple times."""
        if self.domain is not None:
            self.domain.interrupt()
            if self.thread and self.thread.is_alive():
                self.thread.join()
            self.domain = None
            self.target = None
            self.thread = None

    def hypervisor_name(self) -> str:
        """Get the name of the hypervisor."""
        return self.hypervisor.hypervisor_name()

    def hypervisor_version(self) -> str:
        """Get the version of the hypervisor."""
        return self.hypervisor.hypervisor_version()

    def hypervisor_patch_version(self) -> str:
        """Get the patch version of the hypervisor."""
        return self.hypervisor.hypervisor_patch_version()

    def guest_os(self) -> str:
        """Get the guest OS name. Returns either "Windows", "Linux", or "Unknown"."""
        if not self.domain:
            raise RuntimeError("VMI must be attached to a VM/domain. Attach first.")
        guest = self.domain.guest()
        match guest.os():
            case introvirt.OS_Windows:
                return "Windows"
            case introvirt.OS_Linux:
                return "Linux"
            case _:
                return "Unknown"

    def intercept_system_calls(self, enabled: bool):
        """Toggle system call interception on/off."""
        if not self.domain:
            raise RuntimeError("VMI must be attached to a VM/domain. Attach first.")
        self.domain.intercept_system_calls(enabled)

    def intercept_cr_writes(self, cr: int, enabled: bool):
        """Intercept CR writes."""
        if not self.domain:
            raise RuntimeError("VMI must be attached to a VM/domain. Attach first.")
        self.domain.intercept_cr_writes(cr, enabled)

    def set_global_callback(self, callback: Callable):
        """Set the global callback that gets called for any event type."""
        self.event_handler.set_global_event_callback(callback)

    def register_callback(self, event_type: EventType, callback: Callable):
        """Register a callback for a given event type."""
        self.event_handler.register_event_callback(event_type, callback)
