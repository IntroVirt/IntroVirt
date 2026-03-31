"""pyintrovirt: Python library for IntroVirt VM introspection.

Requires IntroVirt to be installed (e.g. `libintrovirt1`).
The `introvirt` Python bindings are provided via the generated wheel rather than a system-wide package.
"""
from __future__ import annotations

import os
import sys
import warnings
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import introvirt as _introvirt  # pragma: no cover

if sys.platform != "linux":
    raise RuntimeError("pyintrovirt only supports Linux")

if os.getuid() != 0:
    warnings.warn(
        "pyintrovirt is typically run with elevated privileges (root/sudo) to interface with hypervisors/VMs; "
        "some functionality may fail without them.",
        RuntimeWarning,
        stacklevel=2,
    )

try:
    from introvirt import (  # type: ignore[import-not-found]  # pylint: disable=import-error
        OS,
        EventType,
        IntroVirtError,
        SystemCallIndex,
        NoSuchDomainException,
        DomainBusyException,
        UnsupportedHypervisorException,
        GuestDetectionException,
        InvalidMethodException,
        InvalidVcpuException,
        NotImplementedException,
        CommandFailedException,
        BadPhysicalAddressException,
        VirtualAddressNotPresentException,
        PeException,
        WindowsSystemCall,
        nt_success,
        nt_error,
    )
except ImportError:
    _BINDINGS_ERR = (
        "IntroVirt Python bindings are not installed. Install the generated "
        "IntroVirt Python wheel (which provides the `introvirt` module) "
        "before using this library."
    )

    def _missing(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError(_BINDINGS_ERR)

    OS = EventType = IntroVirtError = SystemCallIndex = _missing  # type: ignore[assignment]
    NoSuchDomainException = DomainBusyException = UnsupportedHypervisorException = _missing  # type: ignore[assignment]
    GuestDetectionException = InvalidMethodException = InvalidVcpuException = _missing  # type: ignore[assignment]
    NotImplementedException = CommandFailedException = BadPhysicalAddressException = _missing  # type: ignore[assignment]
    VirtualAddressNotPresentException = PeException = WindowsSystemCall = _missing  # type: ignore[assignment]
    nt_success = nt_error = _missing  # type: ignore[assignment]

if TYPE_CHECKING:
    from .event import Event
    from .vmi import VMI


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
