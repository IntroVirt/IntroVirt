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
    assert hasattr(introvirt, "IntroVirtError")
    assert hasattr(_introvirt_c, "IntroVirtError")
    assert hasattr(introvirt, "BreakpointCallback")
    # Enums created by create_enum_from_swig (use Enum and a member)
    assert hasattr(introvirt, "EventType")
    assert hasattr(introvirt.EventType, "EVENT_FAST_SYSCALL")
    assert hasattr(introvirt, "OS")
    assert hasattr(introvirt.OS, "Windows")
    assert hasattr(introvirt, "SystemCallIndex")
    assert hasattr(introvirt.SystemCallIndex, "NtAcceptConnectPort")
    assert hasattr(introvirt, "Exception")
    assert hasattr(introvirt.Exception, "GP_FAULT")
    assert hasattr(introvirt.Exception, "INT3")
    assert hasattr(introvirt, "resolve_symbol_by_name")
    assert hasattr(introvirt, "pdb_rva_to_guest_address")
    assert hasattr(introvirt, "read_guest_bytes")
    assert hasattr(introvirt, "read_guest_uint32")
    assert hasattr(introvirt, "pe_export_by_name")
    assert hasattr(introvirt, "pe_export_names")
    assert hasattr(introvirt, "pe_from_address")


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
    assert idx == introvirt.SystemCallIndex.NtCreateFile.value


def test_system_call_filter():
    """SystemCallFilter default construct and methods."""
    f = introvirt.SystemCallFilter()
    f.clear()
    f.mask(0)
    assert f.mask() == 0
    f.mask(1)
    assert f.mask() == 1
    f.set_32(0, True)
    f.set_64(introvirt.SystemCallIndex.NtCreateFile.value, True)
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


def test_exceptions_reexported_on_wrapper():
    """introvirt re-exports exception classes from _introvirt_py (same objects)."""
    assert introvirt.IntroVirtError is _introvirt_c.IntroVirtError
    assert introvirt.NoSuchDomainException is _introvirt_c.NoSuchDomainException
    assert issubclass(introvirt.NoSuchDomainException, introvirt.IntroVirtError)


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
    """EventType, OS, and SystemCallIndex enum members have integer values."""
    assert isinstance(introvirt.EventType.EVENT_FAST_SYSCALL.value, int)
    assert isinstance(introvirt.EventType.EVENT_FAST_SYSCALL_RET.value, int)
    assert isinstance(introvirt.OS.Windows.value, int)
    assert isinstance(introvirt.OS.Linux.value, int)
    assert isinstance(introvirt.SystemCallIndex.NtCreateFile.value, int)
    assert isinstance(introvirt.Exception.GP_FAULT.value, int)
    assert isinstance(introvirt.Exception.INT3.value, int)


def test_enum_values():
    """Enum values are correct."""
    assert introvirt.EventType.EVENT_FAST_SYSCALL.value == 0
    assert introvirt.EventType.EVENT_FAST_SYSCALL_RET.value == 1
    assert introvirt.EventType.EVENT_UNKNOWN.value == -1
    assert introvirt.OS.Unknown.value == 0
    assert introvirt.OS.Windows.value == 1
    assert introvirt.OS.Linux.value == 2
    assert introvirt.SystemCallIndex.NtAcceptConnectPort.value == 0
    assert introvirt.Exception.GP_FAULT.value == 13
    assert introvirt.Exception.INT3.value == 3


def test_enums_created():
    """create_enum_from_swig produced proper Python Enums with expected members."""
    from enum import Enum as EnumType

    for name in ("SystemCallIndex", "EventType", "OS", "Exception"):
        enum_class = getattr(introvirt, name)
        assert isinstance(enum_class, type)
        assert issubclass(enum_class, EnumType), f"{name} is not an Enum"
        assert len(enum_class) > 0, f"{name} has no members"
    # Spot-check a few members and values
    assert introvirt.SystemCallIndex.NtCreateFile.name == "NtCreateFile"
    assert introvirt.EventType.EVENT_FAST_SYSCALL.name == "EVENT_FAST_SYSCALL"
    assert introvirt.OS.Windows.name == "Windows"
    assert introvirt.OS.Linux.name == "Linux"
    assert introvirt.SystemCallIndex.NtAcceptConnectPort.name == "NtAcceptConnectPort"
    assert introvirt.Exception.GP_FAULT.name == "GP_FAULT"
    assert introvirt.Exception.INT3.name == "INT3"


def test_stub_contains_enums_and_classes():
    """Generated introvirt.pyi should expose key enums and classes for type checkers.

    This is a smoke test that the generator sees the same public API that the tests
    exercise at runtime. It does not read the stub file directly, but instead relies
    on the introspected module view used by the generator.
    """
    # Enums
    assert hasattr(introvirt, "EventType")
    assert hasattr(introvirt, "SystemCallIndex")
    assert hasattr(introvirt, "OS")
    assert hasattr(introvirt, "Exception")

    # Representative classes
    for name in (
        "Domain",
        "Guest",
        "Vcpu",
        "Event",
        "WindowsGuest",
        "NtCreateFile",
        "NtOpenProcess",
    ):
        assert hasattr(introvirt, name), f"{name} missing from introvirt module"


@pytest.mark.requires_hypervisor
def test_hypervisor_instance():
    """Hypervisor.instance() returns an object or raises (environment-dependent)."""
    try:
        hv = introvirt.Hypervisor.instance()
        assert hv is not None
        assert hasattr(hv, "get_running_domains")
    except (_introvirt_c.UnsupportedHypervisorException, OSError):
        pytest.skip("No hypervisor available")


def test_pdb_rva_to_guest_address():
    """pdb_rva_to_guest_address is pure arithmetic: base + rva."""
    assert introvirt.pdb_rva_to_guest_address(0x1000, 0x100) == 0x1100
    assert introvirt.pdb_rva_to_guest_address(0x400000, 0) == 0x400000


def test_resolve_symbol_by_name_none():
    """resolve_symbol_by_name with None domain/vcpu or empty name returns None."""
    result = introvirt.resolve_symbol_by_name(None, None, 0, "")
    assert result is None


def test_guest_memory_helpers_callable():
    """read_guest_uint32 and read_guest_bytes exist and are callable."""
    assert callable(introvirt.read_guest_uint32)
    assert callable(introvirt.read_guest_bytes)


def test_pe_export_by_name_none():
    """pe_export_by_name(None, name) returns None."""
    assert introvirt.pe_export_by_name(None, "SomeExport") is None


def test_pe_export_names_none():
    """pe_export_names(None) does not raise (returns empty vector proxy)."""
    result = introvirt.pe_export_names(None)
    assert result is not None


def test_pe_base_address_none():
    """pe_base_address(None) returns 0."""
    assert introvirt.pe_base_address(None) == 0


def test_get_executable_mapped_modules_none():
    """get_executable_mapped_modules(None) returns empty list."""
    result = introvirt.get_executable_mapped_modules(None)
    assert result == []


def test_resolve_symbols_via_pdb_callable():
    """resolve_symbols_via_pdb exists and is callable."""
    assert callable(introvirt.resolve_symbols_via_pdb)
