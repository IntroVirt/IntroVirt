"""Tests for the pyintrovirt layer (EventType, errors, etc.)."""

import pytest

introvirt = pytest.importorskip("introvirt")

# Import pyintrovirt after ensuring introvirt is available
import pyintrovirt  # noqa: E402
from pyintrovirt import (  # noqa: E402
    IntroVirtError,
    NoSuchDomainException,
)


def test_exception_reexports():
    """Pyintrovirt exception re-exports inherit from IntroVirtError."""
    assert issubclass(NoSuchDomainException, IntroVirtError)
    assert issubclass(pyintrovirt.DomainBusyException, IntroVirtError)
    assert issubclass(pyintrovirt.InvalidMethodException, IntroVirtError)
