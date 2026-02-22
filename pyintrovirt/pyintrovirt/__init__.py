"""pyintrovirt: Python library for IntroVirt VM introspection.

Requires IntroVirt .deb packages to be installed (libintrovirt1, python3-introvirt).
The IntroVirt Python bindings are not on PyPI; install them from the IntroVirt
build or from the generated .deb packages.
"""

import sys

if sys.platform != "linux":
    raise RuntimeError("pyintrovirt only supports Linux")

try:
    import introvirt  # type: ignore[import-not-found]  # noqa: F401
except ImportError as exc:
    raise RuntimeError(
        "IntroVirt Python bindings are not installed. Install the IntroVirt .deb packages (libintrovirt1, python3-introvirt) before using this library."
    ) from exc

from .vmi import VMIDomain

# Re-export IntroVirt exceptions (they live on _introvirt_py, not introvirt.py)
_introvirt = getattr(introvirt, "_introvirt_py", introvirt)
IntroVirtError = _introvirt.IntroVirtError
NoSuchDomainException = _introvirt.NoSuchDomainException
DomainBusyException = _introvirt.DomainBusyException
UnsupportedHypervisorException = _introvirt.UnsupportedHypervisorException
GuestDetectionException = _introvirt.GuestDetectionException
InvalidMethodException = _introvirt.InvalidMethodException
InvalidVcpuException = _introvirt.InvalidVcpuException
NotImplementedException = _introvirt.NotImplementedException
CommandFailedException = _introvirt.CommandFailedException
BadPhysicalAddressException = _introvirt.BadPhysicalAddressException
VirtualAddressNotPresentException = _introvirt.VirtualAddressNotPresentException

__all__: list[str] = [
    "VMIDomain",
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
]