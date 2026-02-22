"""Re-export IntroVirt exceptions (they live on _introvirt_py, not introvirt.py)"""

import introvirt  # type: ignore[import-not-found]  # noqa: F401 # pylint: disable=import-error

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
