"""Classes for dealing with a domain/VM being introspected."""
from contextlib import ContextDecorator
from typing import Union, NamedTuple

import introvirt


class DomainInformation(NamedTuple):
    """Domain information."""

    domain_name: str
    domain_id: int

    def __str__(self):
        return f"DomainInformation(domain_name={self.domain_name}, domain_id={self.domain_id})"


class Domain(ContextDecorator):
    """An introspection target (VM/domain) that we are attached to for introspecting."""

    def __init__(self, domain_id: Union[int, str], hypervisor: introvirt.Hypervisor):
        """
        Initialize an target domain to be introspected.

        Args:
            domain_id: The domain to attach to. Can be an integer domain ID or a string domain name.
            hypervisor: The hypervisor instance with the target domain to attach to.
        """
        #: The domain being attached
        self._domain: introvirt.Domain = None
        #: The guest OS for the attached domain
        self._guest: introvirt.Guest = None
        #: The guest OS type for the attached domain
        self._os: introvirt.OS = None

        self._domain: introvirt.Domain = hypervisor.attach_domain(domain_id)
        if not self._domain.detect_guest():
            raise RuntimeError("Failed to detect guest OS")
        self._guest: introvirt.Guest = self._domain.guest()
        self._os: introvirt.OS = introvirt.OS(self._guest.os())

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self.detach()

    def __del__(self):
        self.detach()

    @property
    def os(self) -> introvirt.OS:
        """Access the guest OS type enum."""
        return self._os

    def detach(self) -> None:
        """Detach from the domain. Safe to call multiple times."""
        if self._domain is None:
            return
        self._domain.interrupt()
        self._domain = None

    def poll(self, event_handler: introvirt.EventCallback):
        """Start the poller for events. No events will be recieved until this is started."""
        self._domain.poll(event_handler)

    def clear_system_call_filter(self):
        """Clear the system call filter if set."""
        self._domain.system_call_filter().clear()

    def filter_system_call(self, syscall: introvirt.SystemCallIndex, enabled: bool):
        """Toggle filtering of a specific system call."""
        if self.os == introvirt.OS.Windows:
            win_guest = introvirt.WindowsGuest_from_guest(self._guest)
            win_guest.set_system_call_filter(self._domain.system_call_filter(), syscall.value, enabled)
        else:
            raise NotImplementedError("Only implemented for Windows guests right now.")

    def filter_system_calls(self, enabled: bool):
        """Toggle system call filtering on/off. Required for the filter to take effect."""
        self._domain.system_call_filter().enabled(enabled)

    def intercept_system_calls(self, enabled: bool):
        """Toggle system call interception on/off. Required to received system call events at all."""
        self._domain.intercept_system_calls(enabled)

    def intercept_cr_writes(self, cr: int, enabled: bool):
        """Intercept CR writes."""
        self._domain.intercept_cr_writes(cr, enabled)
