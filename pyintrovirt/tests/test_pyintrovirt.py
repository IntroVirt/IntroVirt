"""Tests for the pyintrovirt layer (EventType, errors, etc.)."""

import pytest

introvirt = pytest.importorskip("introvirt")

# Import pyintrovirt after ensuring introvirt is available
import pyintrovirt  # noqa: E402
from pyintrovirt import (  # noqa: E402
    EventType,
    IntroVirtError,
    NoSuchDomainException,
)


def test_event_type_matches_introvirt_constants():
    """EventType enum values match introvirt constants."""
    assert EventType.EVENT_FAST_SYSCALL.value == introvirt.EventType_EVENT_FAST_SYSCALL
    assert EventType.EVENT_FAST_SYSCALL_RET.value == introvirt.EventType_EVENT_FAST_SYSCALL_RET
    assert EventType.EVENT_CR_WRITE.value == introvirt.EventType_EVENT_CR_WRITE


def test_exception_reexports():
    """Pyintrovirt exception re-exports inherit from IntroVirtError."""
    assert issubclass(NoSuchDomainException, IntroVirtError)
    assert issubclass(pyintrovirt.DomainBusyException, IntroVirtError)
    assert issubclass(pyintrovirt.InvalidMethodException, IntroVirtError)
