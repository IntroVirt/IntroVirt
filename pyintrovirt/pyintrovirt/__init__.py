"""pyintrovirt: Python library for IntroVirt VM introspection.

Requires IntroVirt to be installed (e.g. `libintrovirt1`).
The `introvirt` Python bindings are provided via the generated wheel rather than a system-wide package.
"""
import os
import sys

from .vmi import VMI
from .event import Event

if sys.platform != "linux":
    raise RuntimeError("pyintrovirt only supports Linux")

if os.getuid() != 0:
    raise RuntimeError("pyintrovirt must be run/used from an elevated shell to interface with VMs")

try:
    import introvirt  # type: ignore[import-not-found]  # noqa: F401
except ImportError as exc:
    raise RuntimeError(
        "IntroVirt Python bindings are not installed. Install the generated IntroVirt Python wheel (which provides the `introvirt` module) before using this library."
    ) from exc

from introvirt import (
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
    nt_error
)

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
    "nt_error"
]
