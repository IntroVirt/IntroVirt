"""pyintrovirt: Python library for IntroVirt VM introspection.

Requires IntroVirt .deb packages to be installed (libintrovirt1, python3-introvirt).
The IntroVirt Python bindings are not on PyPI; install them from the IntroVirt
build or from the generated .deb packages.
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
        "IntroVirt Python bindings are not installed. Install the IntroVirt .deb packages (libintrovirt1, python3-introvirt) before using this library."
    ) from exc

from introvirt import (
    OS,
    EventType,
    IntroVirtError,
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
    PeException
)

__all__: list[str] = [
    "VMI",
    "OS",
    "Event",
    "EventType",
    "IntroVirtError",
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
]
