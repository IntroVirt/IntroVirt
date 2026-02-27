/*
 * IntroVirt Python bindings - minimal API
 *
 * Exposes Hypervisor, Domain, DomainInformation, EventCallback (with directors),
 * Event, EventType, and Guest for basic VM introspection.
 */

/* Generate API documentation with Doxygen */
%feature("autodoc", "2");

/* Suppress SWIG 509: overloaded to_string/operator<< for OS, FastCallType shadowed by EventType.
 * 317: specialization of non-template GuestAllocation (OBJECT_ATTRIBUTES.hh).
 * 401: base class undefined when derived is parsed before base in generated syscall list.
 * 503: operator<< / conversion operators that cannot be wrapped as Python identifiers. */
%warnfilter(509, 317, 401, 503);
#pragma SWIG nowarn=317,401,503,509

%module(docstring="IntroVirt Python bindings for VM introspection", directors="1", threads="1") introvirt

%{
#include <introvirt/core/domain/Hypervisor.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Guest.hh>
#include <introvirt/core/event/EventCallback.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/event/EventType.hh>
#include <introvirt/core/event/EventTaskInformation.hh>
#include <introvirt/core/syscall/SystemCall.hh>
#include <introvirt/core/event/SystemCallEvent.hh>
#include <introvirt/core/filter/TaskFilter.hh>
#include <introvirt/core/syscall/SystemCallFilter.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/core/exception/NoSuchDomainException.hh>
#include <introvirt/core/exception/DomainBusyException.hh>
#include <introvirt/core/exception/UnsupportedHypervisorException.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/core/exception/InvalidVcpuException.hh>
#include <introvirt/core/exception/NotImplementedException.hh>
#include <introvirt/core/exception/CommandFailedException.hh>
#include <introvirt/core/exception/BadPhysicalAddressException.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/core/breakpoint/Breakpoint.hh>
#include <introvirt/core/breakpoint/Watchpoint.hh>
#include <introvirt/core/breakpoint/SingleStep.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>
#include <introvirt/windows/kernel/nt/syscall/types/OBJECT_ATTRIBUTES.hh>
#include <introvirt/windows/kernel/nt/syscall/NtCreateFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtOpenFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtClose.hh>
#include <introvirt/windows/kernel/nt/syscall/NtReadWriteFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtReadFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtWriteFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtDuplicateObject.hh>
#include <introvirt/windows/kernel/nt/syscall/NtQueryAttributesFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtQueryFullAttributesFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtDeleteFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtQueryInformationFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtSetInformationFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtDeviceIoControlFile.hh>
#include <introvirt/windows/kernel/nt/syscall/NtMapViewOfSection.hh>
#include <introvirt/windows/kernel/nt/syscall/NtTerminateProcess.hh>
#include <introvirt/windows/kernel/nt/syscall/NtOpenProcess.hh>
#include <introvirt/windows/event/WindowsSystemCallEvent.hh>
#include <introvirt/windows/kernel/nt/syscall/NtSystemCall.hh>
#include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>
#include <introvirt/windows/kernel/SystemCallIndex.hh>
#include <introvirt/windows/pe/const/MachineType.hh>
#include <introvirt/windows/pe/types/DOS_HEADER.hh>
#include <introvirt/windows/pe/types/IMAGE_SECTION_HEADER.hh>
#include <introvirt/windows/pe/types/IMAGE_FILE_HEADER.hh>
#include <introvirt/windows/pe/types/IMAGE_EXPORT_DIRECTORY.hh>
#include <introvirt/windows/pe/types/IMAGE_OPTIONAL_HEADER.hh>
#include <introvirt/windows/pe/PE.hh>
#include <introvirt/windows/pe/exception/PeException.hh>

using namespace introvirt;
using namespace introvirt::windows;

static PyObject* p_IntroVirtError;
static PyObject* p_NoSuchDomainException;
static PyObject* p_DomainBusyException;
static PyObject* p_UnsupportedHypervisorException;
static PyObject* p_GuestDetectionException;
static PyObject* p_InvalidMethodException;
static PyObject* p_InvalidVcpuException;
static PyObject* p_NotImplementedException;
static PyObject* p_CommandFailedException;
static PyObject* p_BadPhysicalAddressException;
static PyObject* p_VirtualAddressNotPresentException;
static PyObject* p_PeException;
%}

%include <std_string.i>
%include <std_vector.i>
%include <std_unique_ptr.i>
%include <std_shared_ptr.i>
%include <std_set.i>
%include <stdint.i>
%include <exception.i>

%init %{
  p_IntroVirtError = PyErr_NewException("introvirt.IntroVirtError", PyExc_RuntimeError, NULL);
  Py_INCREF(p_IntroVirtError);
  PyModule_AddObject(m, "IntroVirtError", p_IntroVirtError);

  p_NoSuchDomainException = PyErr_NewException("introvirt.NoSuchDomainException", p_IntroVirtError, NULL);
  Py_INCREF(p_NoSuchDomainException);
  PyModule_AddObject(m, "NoSuchDomainException", p_NoSuchDomainException);

  p_DomainBusyException = PyErr_NewException("introvirt.DomainBusyException", p_IntroVirtError, NULL);
  Py_INCREF(p_DomainBusyException);
  PyModule_AddObject(m, "DomainBusyException", p_DomainBusyException);

  p_UnsupportedHypervisorException = PyErr_NewException("introvirt.UnsupportedHypervisorException", p_IntroVirtError, NULL);
  Py_INCREF(p_UnsupportedHypervisorException);
  PyModule_AddObject(m, "UnsupportedHypervisorException", p_UnsupportedHypervisorException);

  p_GuestDetectionException = PyErr_NewException("introvirt.GuestDetectionException", p_IntroVirtError, NULL);
  Py_INCREF(p_GuestDetectionException);
  PyModule_AddObject(m, "GuestDetectionException", p_GuestDetectionException);

  p_InvalidMethodException = PyErr_NewException("introvirt.InvalidMethodException", p_IntroVirtError, NULL);
  Py_INCREF(p_InvalidMethodException);
  PyModule_AddObject(m, "InvalidMethodException", p_InvalidMethodException);

  p_InvalidVcpuException = PyErr_NewException("introvirt.InvalidVcpuException", p_IntroVirtError, NULL);
  Py_INCREF(p_InvalidVcpuException);
  PyModule_AddObject(m, "InvalidVcpuException", p_InvalidVcpuException);

  p_NotImplementedException = PyErr_NewException("introvirt.NotImplementedException", p_IntroVirtError, NULL);
  Py_INCREF(p_NotImplementedException);
  PyModule_AddObject(m, "NotImplementedException", p_NotImplementedException);

  p_CommandFailedException = PyErr_NewException("introvirt.CommandFailedException", p_IntroVirtError, NULL);
  Py_INCREF(p_CommandFailedException);
  PyModule_AddObject(m, "CommandFailedException", p_CommandFailedException);

  p_BadPhysicalAddressException = PyErr_NewException("introvirt.BadPhysicalAddressException", p_IntroVirtError, NULL);
  Py_INCREF(p_BadPhysicalAddressException);
  PyModule_AddObject(m, "BadPhysicalAddressException", p_BadPhysicalAddressException);

  p_VirtualAddressNotPresentException = PyErr_NewException("introvirt.VirtualAddressNotPresentException", p_IntroVirtError, NULL);
  Py_INCREF(p_VirtualAddressNotPresentException);
  PyModule_AddObject(m, "VirtualAddressNotPresentException", p_VirtualAddressNotPresentException);

  p_PeException = PyErr_NewException("introvirt.PeException", p_IntroVirtError, NULL);
  Py_INCREF(p_PeException);
  PyModule_AddObject(m, "PeException", p_PeException);
%}

%include "typemaps.i"
%include "exceptions.i"
%include "ignores_core.i"
%include "core/core.i"
%include "core/breakpoints.i"
%include "core/guest_memory.i"
%include "windows/windows.i"

%pythoncode %{
from enum import Enum

# Re-export exception classes from the C module into the wrapper so introvirt.IntroVirtError etc. work like introvirt.SystemCallIndex_*.
IntroVirtError = _introvirt_py.IntroVirtError
NoSuchDomainException = _introvirt_py.NoSuchDomainException
DomainBusyException = _introvirt_py.DomainBusyException
UnsupportedHypervisorException = _introvirt_py.UnsupportedHypervisorException
GuestDetectionException = _introvirt_py.GuestDetectionException
InvalidMethodException = _introvirt_py.InvalidMethodException
InvalidVcpuException = _introvirt_py.InvalidVcpuException
NotImplementedException = _introvirt_py.NotImplementedException
CommandFailedException = _introvirt_py.CommandFailedException
BadPhysicalAddressException = _introvirt_py.BadPhysicalAddressException
VirtualAddressNotPresentException = _introvirt_py.VirtualAddressNotPresentException
PeException = _introvirt_py.PeException

def create_enum_from_swig(prefix):
    """Dynamically creates a Python Enum from SWIG-wrapped integer constants."""
    # Read constants from the C extension module (they are always defined there)
    tmpD = {k: getattr(_introvirt_py, k) for k in dir(_introvirt_py) if k.startswith(prefix + '_')}
    if not tmpD:
        return
    # Build enum: suffix -> integer value (coerce in case SWIG returns a proxy)
    enum_members = {k[len(prefix) + 1:]: int(v) for k, v in tmpD.items()}
    globals()[prefix] = Enum(prefix, enum_members)
    # Remove the original constants from this modules globals to avoid duplication
    for k in tmpD:
        if k in globals():
            del globals()[k]

# Call the helper function for the enums we want to re-export
create_enum_from_swig('SystemCallIndex')
create_enum_from_swig('EventType')
create_enum_from_swig('FastCallType')
create_enum_from_swig('OS')
create_enum_from_swig('Exception')
create_enum_from_swig('MachineType')
create_enum_from_swig('ExportType')

# Clean up the helper function from the modules public interface
del create_enum_from_swig
%}