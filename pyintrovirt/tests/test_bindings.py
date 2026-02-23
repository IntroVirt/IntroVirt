"""Tests for the IntroVirt Python bindings (introvirt module).

These tests exercise the bindings without a live VM. They require the
IntroVirt Python extension to be built and available (PYTHONPATH or installed).
"""

import pytest

introvirt = pytest.importorskip("introvirt")

# Exception classes are on the C extension module; the wrapper may not re-export them
_introvirt_c = getattr(introvirt, "_introvirt_py", introvirt)


def test_import():
    """Check that key symbols exist on the introvirt module."""
    assert hasattr(introvirt, "nt_success")
    assert hasattr(introvirt, "NTSTATUS")
    assert hasattr(introvirt, "SystemCallFilter")
    assert hasattr(introvirt, "system_call_from_string")
    assert hasattr(introvirt, "get_windows_syscall_result_value")
    assert hasattr(introvirt, "WindowsGuest_from_guest")
    assert hasattr(_introvirt_c, "IntroVirtError")
    assert hasattr(introvirt, "BreakpointCallback")
    assert hasattr(introvirt, "EventType_EVENT_FAST_SYSCALL")
    assert hasattr(introvirt, "OS_Windows")


def test_ntstatus():
    """NTSTATUS construction and methods."""
    ok = introvirt.NTSTATUS(0)
    assert ok.value() == 0
    assert ok.NT_SUCCESS() is True
    assert ok.NT_ERROR() is False
    assert ok.NT_WARNING() is False
    assert ok.NT_INFORMATION() is False
    assert ok.initialized() is True

    err = introvirt.NTSTATUS(0xC0000001)
    assert err.value() == 0xC0000001
    assert err.NT_SUCCESS() is False
    assert err.NT_ERROR() is True


def test_nt_helpers():
    """Standalone NT helper functions."""
    assert introvirt.nt_success(0) is True
    assert introvirt.nt_success(0xC0000001) is False
    assert introvirt.nt_error(0xC0000001) is True
    assert introvirt.nt_error(0) is False
    assert introvirt.nt_warning(0x80000001) is True
    assert introvirt.nt_information(0x40000001) is True

    s = introvirt.ntstatus_to_string(0)
    assert isinstance(s, str)


def test_system_call_from_string():
    """system_call_from_string returns an int for known names."""
    idx = introvirt.system_call_from_string("NtCreateFile")
    assert isinstance(idx, int)
    assert idx == introvirt.SystemCallIndex_NtCreateFile


def test_system_call_filter():
    """SystemCallFilter default construct and methods."""
    f = introvirt.SystemCallFilter()
    f.clear()
    f.mask(0)
    assert f.mask() == 0
    f.mask(1)
    assert f.mask() == 1
    f.set_32(0, True)
    f.set_64(introvirt.SystemCallIndex_NtCreateFile, True)
    f.enabled(True)
    assert f.enabled() is True


def test_domain_information():
    """DomainInformation default construct."""
    info = introvirt.DomainInformation()
    assert hasattr(info, "domain_name")
    assert hasattr(info, "domain_id")


def test_get_windows_syscall_result_value_no_event():
    """get_windows_syscall_result_value exists; with None C++ would return (False, 0).

    The SWIG binding exposes (Event*, bool&, uint32_t&) and does not accept Python None
    or literals for the output parameters, so we only verify the symbol is present.
    """
    assert callable(introvirt.get_windows_syscall_result_value)


def test_windows_guest_from_guest_none():
    """WindowsGuest_from_guest(None) returns None."""
    result = introvirt.WindowsGuest_from_guest(None)
    assert result is None


def test_exceptions():
    """Exception classes exist and inherit from IntroVirtError."""
    assert issubclass(_introvirt_c.NoSuchDomainException, _introvirt_c.IntroVirtError)
    assert issubclass(_introvirt_c.DomainBusyException, _introvirt_c.IntroVirtError)
    assert issubclass(_introvirt_c.InvalidMethodException, _introvirt_c.IntroVirtError)


def test_breakpoint_callback_director():
    """BreakpointCallback can be subclassed and instantiated."""

    class MyCallback(introvirt.BreakpointCallback):
        def breakpoint_hit(self, event):
            pass

    cb = MyCallback()
    assert cb is not None


def test_watchpoint_callback_director():
    """WatchpointCallback can be subclassed and instantiated."""

    class MyCallback(introvirt.WatchpointCallback):
        def watchpoint_hit(self, event):
            pass

    cb = MyCallback()
    assert cb is not None


def test_single_step_callback_director():
    """SingleStepCallback can be subclassed and instantiated."""

    class MyCallback(introvirt.SingleStepCallback):
        def single_step_hit(self, event):
            pass

    cb = MyCallback()
    assert cb is not None


def test_constants_are_integers():
    """EventType and OS constants are integers."""
    assert isinstance(introvirt.EventType_EVENT_FAST_SYSCALL, int)
    assert isinstance(introvirt.EventType_EVENT_FAST_SYSCALL_RET, int)
    assert isinstance(introvirt.OS_Windows, int)
    assert isinstance(introvirt.OS_Linux, int)
    assert isinstance(introvirt.SystemCallIndex_NtCreateFile, int)


@pytest.mark.requires_hypervisor
def test_hypervisor_instance():
    """Hypervisor.instance() returns an object or raises (environment-dependent)."""
    try:
        hv = introvirt.Hypervisor.instance()
        assert hv is not None
        assert hasattr(hv, "get_running_domains")
    except (_introvirt_c.UnsupportedHypervisorException, OSError):
        pytest.skip("No hypervisor available")
