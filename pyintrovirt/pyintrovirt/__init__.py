"""pyintrovirt: Python library for IntroVirt VM introspection.

Requires IntroVirt to be installed (e.g. `libintrovirt1` and `python3-pyintrovirt`).
"""

from __future__ import annotations

import os
import sys
import warnings
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from introvirt import (
        OS,
        BadPhysicalAddressException,
        CommandFailedException,
        DomainBusyException,
        EventType,
        GuestDetectionException,
        IntroVirtError,
        InvalidMethodException,
        InvalidVcpuException,
        NoSuchDomainException,
        NotImplementedException,
        PeException,
        SystemCallIndex,
        UnsupportedHypervisorException,
        VirtualAddressNotPresentException,
        WindowsSystemCall,
        nt_error,
        nt_success,
    )

    from .event import Event
    from .vmi import VMI
else:
    if sys.platform != "linux":
        raise RuntimeError("pyintrovirt only supports Linux")

    if os.getuid() != 0:
        warnings.warn(
            "pyintrovirt is typically run with elevated privileges (root/sudo) to interface with hypervisors/VMs; some functionality may fail without them.",
            RuntimeWarning,
            stacklevel=2,
        )

    try:
        from introvirt import (  # pylint: disable=import-error
            OS,
            BadPhysicalAddressException,
            CommandFailedException,
            DomainBusyException,
            EventType,
            GuestDetectionException,
            IntroVirtError,
            InvalidMethodException,
            InvalidVcpuException,
            NoSuchDomainException,
            NotImplementedException,
            PeException,
            SystemCallIndex,
            UnsupportedHypervisorException,
            VirtualAddressNotPresentException,
            WindowsSystemCall,
            nt_error,
            nt_success,
        )
    except ImportError:
        _BINDINGS_ERR = "IntroVirt Python bindings are not installed."

        def _missing(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError(_BINDINGS_ERR)

        OS = EventType = IntroVirtError = SystemCallIndex = _missing
        NoSuchDomainException = DomainBusyException = UnsupportedHypervisorException = _missing
        GuestDetectionException = InvalidMethodException = InvalidVcpuException = _missing
        NotImplementedException = CommandFailedException = BadPhysicalAddressException = _missing
        VirtualAddressNotPresentException = PeException = WindowsSystemCall = _missing
        nt_success = nt_error = _missing


def __getattr__(name: str) -> Any:
    # pylint: disable=import-outside-toplevel
    if name == "VMI":
        from .vmi import VMI as _VMI

        return _VMI
    if name == "Event":
        from .event import Event as _Event

        return _Event
    raise AttributeError(name)


__all__: list[str] = [
    "VMI",
    "OS",
    "Event",
    "EventType",
    "IntroVirtError",
    "SystemCallIndex",
    "NoSuchDomainException",
    "DomainBusyException",
    "UnsupportedHypervisorException",
    "GuestDetectionException",
    "InvalidMethodException",
    "InvalidVcpuException",
    "NotImplementedException",
    "CommandFailedException",
    "BadPhysicalAddressException",
    "VirtualAddressNotPresentException",
    "PeException",
    "WindowsSystemCall",
    "nt_success",
    "nt_error",
]
