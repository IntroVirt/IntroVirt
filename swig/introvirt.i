/*
 * IntroVirt Python bindings - minimal API
 *
 * Exposes Hypervisor, Domain, DomainInformation, EventCallback (with directors),
 * Event, EventType, and Guest for basic VM introspection.
 */

/* Generate API documentation with Doxygen */
%feature("autodoc", "2");

/* Suppress SWIG 509: overloaded to_string/operator<< for OS, FastCallType shadowed by EventType */
%warnfilter(509);

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
#include <introvirt/windows/event/WindowsSystemCallEvent.hh>
#include <introvirt/windows/kernel/nt/syscall/NtSystemCall.hh>
#include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>
#include <introvirt/windows/kernel/SystemCallIndex.hh>

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
%}

/* Catch C++ exceptions and convert to Python exceptions (most specific first) */
%exception {
  try {
    $action
  }
  catch (introvirt::NoSuchDomainException& e) {
    PyErr_SetString(p_NoSuchDomainException, e.what());
    SWIG_fail;
  }
  catch (introvirt::DomainBusyException& e) {
    PyErr_SetString(p_DomainBusyException, e.what());
    SWIG_fail;
  }
  catch (introvirt::UnsupportedHypervisorException& e) {
    PyErr_SetString(p_UnsupportedHypervisorException, e.what());
    SWIG_fail;
  }
  catch (introvirt::GuestDetectionException& e) {
    PyErr_SetString(p_GuestDetectionException, e.what());
    SWIG_fail;
  }
  catch (introvirt::InvalidMethodException& e) {
    PyErr_SetString(p_InvalidMethodException, e.what());
    SWIG_fail;
  }
  catch (introvirt::InvalidVcpuException& e) {
    PyErr_SetString(p_InvalidVcpuException, e.what());
    SWIG_fail;
  }
  catch (introvirt::NotImplementedException& e) {
    PyErr_SetString(p_NotImplementedException, e.what());
    SWIG_fail;
  }
  catch (introvirt::CommandFailedException& e) {
    PyErr_SetString(p_CommandFailedException, e.what());
    SWIG_fail;
  }
  catch (introvirt::BadPhysicalAddressException& e) {
    PyErr_SetString(p_BadPhysicalAddressException, e.what());
    SWIG_fail;
  }
  catch (introvirt::VirtualAddressNotPresentException& e) {
    PyErr_SetString(p_VirtualAddressNotPresentException, e.what());
    SWIG_fail;
  }
  catch (introvirt::TraceableException& e) {
    PyErr_SetString(p_IntroVirtError, e.what());
    SWIG_fail;
  }
  SWIG_CATCH_STDEXCEPT
  catch (...) {
    SWIG_exception(SWIG_UnknownError, "unknown exception");
  }
}

/* Return uint32_t as Python int to avoid SWIG wrapping as uint32_t* (leak + wrong repr) */
%typemap(out) uint32_t {
  $result = PyLong_FromUnsignedLong($1);
}

/* Return OS enum by value to avoid "memory leak of type OS*" (Guest::os(), Event::os_type()) */
%typemap(out) introvirt::OS {
  $result = PyLong_FromLong(static_cast<long>($1));
}
%typemap(out) OS {
  $result = PyLong_FromLong(static_cast<long>($1));
}

/* Return SystemCallIndex as Python int (like OS) */
%typemap(out) introvirt::windows::SystemCallIndex {
  $result = PyLong_FromUnsignedLong(static_cast<unsigned long>($1));
}
%typemap(out) SystemCallIndex {
  $result = PyLong_FromUnsignedLong(static_cast<unsigned long>($1));
}

/* Accept EventCallback& from Python so director subclasses pass (poll(callback)).
 * argp is the C++ object pointer; SWIG passes the ref as a pointer, so assign argp. */
%typemap(in) introvirt::EventCallback & (void *argp = 0, int res = 0) {
  res = SWIG_ConvertPtr($input, &argp, $descriptor(introvirt::EventCallback *), 0);
  if (!SWIG_IsOK(res)) {
    SWIG_exception_fail(SWIG_ArgError(res), "in method, argument of type \"introvirt::EventCallback &\"");
  }
  if (!argp) {
    SWIG_exception_fail(SWIG_ValueError, "invalid null reference");
  }
  $1 = reinterpret_cast<introvirt::EventCallback *>(argp);
}
%typemap(in) EventCallback & (void *argp = 0, int res = 0) {
  res = SWIG_ConvertPtr($input, &argp, $descriptor(introvirt::EventCallback *), 0);
  if (!SWIG_IsOK(res)) {
    SWIG_exception_fail(SWIG_ArgError(res), "in method, argument of type \"EventCallback &\"");
  }
  if (!argp) {
    SWIG_exception_fail(SWIG_ValueError, "invalid null reference");
  }
  $1 = reinterpret_cast<introvirt::EventCallback *>(argp);
}

/* Typemaps for unique_ptr - ownership transfers to Python */
%unique_ptr(introvirt::Domain);
%unique_ptr(introvirt::Hypervisor);

%template(DomainInformationVector) std::vector<introvirt::DomainInformation>;
%template(StringSet) std::set<std::string>;

%feature("director") EventCallback;
%feature("director") BreakpointCallback;
%feature("director") DomainMonitor;
%feature("director") SingleStepCallback;

/*
 * Director callbacks (e.g. EventCallback::process_event) can be invoked from
 * C++ worker threads. We must hold the Python GIL for the whole upcall.
 * Acquire in directorin for Event& (process_event's only arg), release in
 * directorout for void; use a thread-local flag so only this path releases.
 */
%{
static thread_local bool swig_director_gil_acquired = false;
%}
%typemap(directorin) introvirt::Event & %{
  swig_director_gil_acquired = true;
  SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  $input = SWIG_NewPointerObj(SWIG_as_voidptr(&$1), $descriptor, 0);
%}
%typemap(directorout) void %{
  if (swig_director_gil_acquired) {
    swig_director_gil_acquired = false;
    SWIG_PYTHON_THREAD_END_BLOCK;
  }
%}

/* Ignore Domain methods that use std::function, guest_ptr, or complex types */
%ignore introvirt::Domain::create_breakpoint;
%ignore introvirt::Domain::create_watchpoint;
%ignore introvirt::Domain::single_step;
%ignore introvirt::Domain::map_pfns;
%ignore introvirt::Domain::page_directory;
%ignore introvirt::Domain::hypervisor;
%ignore introvirt::Domain::suspend_event;
%ignore introvirt::Domain::suspend_event_step;
%ignore introvirt::Domain::thread_local_domain;

/* Ignore Guest methods that use guest_ptr */
%ignore introvirt::Guest::allocate;
%ignore introvirt::Guest::guest_free;
%ignore introvirt::Guest::page_in;
%ignore introvirt::Guest::impl;

/* Ignore overloaded functions that shadow each other */
%ignore introvirt::to_string(introvirt::OS);
%ignore introvirt::operator<<(std::ostream&, introvirt::OS);
%ignore introvirt::to_string(introvirt::FastCallType);
%ignore introvirt::operator<<(std::ostream&, introvirt::FastCallType);
/* to_string/operator<< for SystemCallIndex and NTSTATUS are renamed below before their includes to avoid clash with introvirt::to_string (EventType, FastCallType, OS). */

/* SystemCall: expose only name(), supported(), will_return(); no JSON/ostream/data/handle_return */
%ignore introvirt::SystemCall::write;
%ignore introvirt::SystemCall::json;
%ignore introvirt::SystemCall::data;
%ignore introvirt::SystemCall::handle_return_event;

/* SystemCallEvent: internal impl only */
%ignore introvirt::SystemCallEvent::impl;

/* SystemCallFilter::matches(Event&) is exposed so Python can check filter against event */
/* (no longer ignored) */

/* WindowsGuest: expose category/filter APIs and set_system_call_filter; ignore kernel, syscalls, domain */
%ignore introvirt::windows::WindowsGuest::syscalls;
%ignore introvirt::windows::WindowsGuest::kernel;
%ignore introvirt::windows::WindowsGuest::domain;

/* Vcpu: expose id(), registers(), intercept_cr_writes(); ignore domain, inject_*, etc. */
%ignore introvirt::Vcpu::long_mode;
%ignore introvirt::Vcpu::long_compatibility_mode;
%ignore introvirt::Vcpu::pause;
%ignore introvirt::Vcpu::resume;
%ignore introvirt::Vcpu::intercept_system_calls;
%ignore introvirt::Vcpu::inject_exception;
%ignore introvirt::Vcpu::inject_syscall;
%ignore introvirt::Vcpu::inject_sysenter;
%ignore introvirt::Vcpu::clone;
%ignore introvirt::Vcpu::handling_event;
%ignore introvirt::Vcpu::system_call_filter;
%ignore introvirt::Vcpu::domain;
%ignore introvirt::Vcpu::segment;
%ignore introvirt::Vcpu::global_descriptor_table;
%ignore introvirt::Vcpu::local_descriptor_table;
%ignore introvirt::Vcpu::interrupt_descriptor_table;
%ignore introvirt::Vcpu::task_state_segment;
%ignore introvirt::Vcpu::os_data;

/* Ignore Event methods that require complex subclasses (msr, etc.) for minimal API */
/* We keep type(), vcpu(), domain(), task(), syscall(), cr() - task() returns EventTaskInformation */
%ignore introvirt::Event::msr;
%ignore introvirt::Event::exception;
%ignore introvirt::Event::mem_access;
%ignore introvirt::Event::json;
%ignore introvirt::Event::impl;

/* EventTaskInformation is returned by reference from Event::task(); Python does not own it.
   Suppress default destructor to avoid delete on abstract base (non-virtual dtor warning). */
%nodefaultdtor introvirt::EventTaskInformation;

/* Parse headers - order matters for dependencies */
%include <introvirt/core/event/EventType.hh>
%include <introvirt/core/event/EventTaskInformation.hh>
%include <introvirt/core/syscall/SystemCall.hh>
%include <introvirt/core/event/SystemCallEvent.hh>
%include <introvirt/core/syscall/SystemCallFilter.hh>
%include <introvirt/core/domain/Guest.hh>
/* TaskFilter and Event (and deps) must be included before Domain so task_filter() return type is wrapped correctly */
/* Registers: expose only simple uint64_t accessors (rax, rsp, rip, etc.); ignore methods that return/take Flags, Efer, Msr, Segment, Cr0, Cr4 */
%ignore introvirt::x86::Registers::rflags;
%ignore introvirt::x86::Registers::efer;
%ignore introvirt::x86::Registers::msr;
%ignore introvirt::x86::Registers::cs;
%ignore introvirt::x86::Registers::ds;
%ignore introvirt::x86::Registers::es;
%ignore introvirt::x86::Registers::fs;
%ignore introvirt::x86::Registers::gs;
%ignore introvirt::x86::Registers::ss;
%ignore introvirt::x86::Registers::tr;
%ignore introvirt::x86::Registers::ldt;
%ignore introvirt::x86::Registers::cr0;
%ignore introvirt::x86::Registers::cr4;
%include <introvirt/core/arch/x86/Registers.hh>
%include <introvirt/core/domain/Vcpu.hh>
%include <introvirt/core/event/ControlRegisterEvent.hh>
%include <introvirt/core/event/Event.hh>
%include <introvirt/core/event/EventCallback.hh>
%include <introvirt/core/filter/TaskFilter.hh>
%include <introvirt/core/domain/Domain.hh>
%include <introvirt/core/domain/Hypervisor.hh>

/* Breakpoint: expose class for create_breakpoint return; ignore callback (std::function) and data (shared_ptr<void>) */
%ignore introvirt::Breakpoint::callback;
%ignore introvirt::Breakpoint::data;
%include <introvirt/core/breakpoint/Breakpoint.hh>
%shared_ptr(introvirt::Breakpoint);

/* Director for breakpoint callback: Python subclass overrides breakpoint_hit(Event&). create_breakpoint builds guest_ptr internally. */
%feature("director") introvirt::BreakpointCallback;
%inline %{
namespace introvirt {
struct BreakpointCallback {
    virtual void breakpoint_hit(Event& e) = 0;
    virtual ~BreakpointCallback() = default;
};
std::shared_ptr<Breakpoint> create_breakpoint(Domain* domain, Vcpu* vcpu, uint64_t address, BreakpointCallback* callback) {
    if (!domain || !vcpu || !callback) return nullptr;
    guest_ptr<void> ptr(*vcpu, address);
    return domain->create_breakpoint(ptr, [callback](Event& e) { callback->breakpoint_hit(e); });
}
} /* namespace introvirt */
%}

/* Watchpoint and SingleStep: expose classes; ignore callback (std::function). Bridge via directors. */
%ignore introvirt::Watchpoint::callback;
%include <introvirt/core/breakpoint/Watchpoint.hh>
%ignore introvirt::SingleStep::callback;
%include <introvirt/core/breakpoint/SingleStep.hh>

%feature("director") introvirt::WatchpointCallback;
%feature("director") introvirt::SingleStepCallback;
%inline %{
namespace introvirt {
struct WatchpointCallback {
    virtual void watchpoint_hit(Event& e) = 0;
    virtual ~WatchpointCallback() = default;
};
struct SingleStepCallback {
    virtual void single_step_hit(Event& e) = 0;
    virtual ~SingleStepCallback() = default;
};
std::unique_ptr<Watchpoint> create_watchpoint(Domain* domain, Vcpu* vcpu, uint64_t address, uint64_t length, bool read, bool write, bool execute, WatchpointCallback* callback) {
    if (!domain || !vcpu || !callback) return nullptr;
    guest_ptr<void> ptr(*vcpu, address);
    return domain->create_watchpoint(ptr, length, read, write, execute, [callback](Event& e) { callback->watchpoint_hit(e); });
}
std::unique_ptr<SingleStep> single_step(Domain* domain, Vcpu* vcpu, SingleStepCallback* callback) {
    if (!domain || !vcpu || !callback) return nullptr;
    return domain->single_step(*vcpu, [callback](Event& e) { callback->single_step_hit(e); });
}
} /* namespace introvirt */
%}

/* SystemCallIndex and NTSTATUS before WindowsGuest (set_system_call_filter uses SystemCallIndex). */
%rename("$ignore") introvirt::windows::to_string;
%rename("$ignore") introvirt::windows::operator<<;
%include <introvirt/windows/kernel/SystemCallIndex.hh>

/* NTSTATUS: ignore Json and NTSTATUS_CODE-using members; expose value(), NT_SUCCESS(), etc. */
%ignore introvirt::windows::nt::NTSTATUS::json() const;
%ignore introvirt::windows::nt::NTSTATUS::operator Json::Value() const;
%ignore introvirt::windows::nt::NTSTATUS::code() const;
%ignore introvirt::windows::nt::NTSTATUS::operator NTSTATUS_CODE() const;
%ignore introvirt::windows::nt::NTSTATUS::operator bool() const;
%ignore introvirt::windows::nt::NTSTATUS::NT_SUCCESS(NTSTATUS_CODE);
%ignore introvirt::windows::nt::NTSTATUS::NT_INFORMATION(NTSTATUS_CODE);
%ignore introvirt::windows::nt::NTSTATUS::NT_WARNING(NTSTATUS_CODE);
%ignore introvirt::windows::nt::NTSTATUS::NT_ERROR(NTSTATUS_CODE);
%ignore introvirt::windows::nt::NTSTATUS::NTSTATUS(NTSTATUS_CODE);
%rename("$ignore") introvirt::windows::nt::to_string;
%rename("$ignore") introvirt::windows::nt::operator<<;
%include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>

%include <introvirt/windows/WindowsGuest.hh>

/* Windows event hierarchy: WindowsSystemCall -> WindowsSystemCallEvent; KPCR -> WindowsEventTaskInformation -> WindowsEvent */
%include <introvirt/windows/kernel/WindowsSystemCall.hh>
%include <introvirt/windows/event/WindowsSystemCallEvent.hh>
%ignore introvirt::windows::nt::KPCR::CurrentThread;
%include <introvirt/windows/kernel/nt/types/KPCR.hh>
%nodefaultdtor introvirt::windows::WindowsEventTaskInformation;
%include <introvirt/windows/event/WindowsEventTaskInformation.hh>
%include <introvirt/windows/event/WindowsEvent.hh>

/* OBJECT_ATTRIBUTES: expose FullPath(KPCR), ObjectName, Length, RootDirectory, Attributes, isInheritable; ignore write, json, guest_ptr */
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::write;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::json;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::ObjectNamePtr;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::SecurityQualityOfServicePtr;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::ptr;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::make_unique;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::SecurityDescriptor;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::SecurityQualityOfService;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::Attributes;
%include <introvirt/windows/kernel/nt/syscall/types/OBJECT_ATTRIBUTES.hh>

/* NtSystemCall: expose result() getter; ignore result(NTSTATUS_CODE) setter */
%ignore introvirt::windows::nt::NtSystemCall::result(NTSTATUS_CODE);
%include <introvirt/windows/kernel/nt/syscall/NtSystemCall.hh>

/* Nt* handlers: expose only ObjectAttributes(), FileHandle(), result(); ignore Ptr getters and complex return types (FILE_ACCESS_MASK, IO_STATUS_BLOCK, etc.). */
%ignore introvirt::windows::nt::NtCreateFile::FileHandlePtr;
%ignore introvirt::windows::nt::NtCreateFile::ObjectAttributesPtr;
%ignore introvirt::windows::nt::NtCreateFile::IoStatusBlockPtr;
%ignore introvirt::windows::nt::NtCreateFile::AllocationSizePtr;
%ignore introvirt::windows::nt::NtCreateFile::EaBufferPtr;
%ignore introvirt::windows::nt::NtCreateFile::DesiredAccess;
%ignore introvirt::windows::nt::NtCreateFile::FileAttributes;
%ignore introvirt::windows::nt::NtCreateFile::ShareAccess;
%ignore introvirt::windows::nt::NtCreateFile::CreateDisposition;
%ignore introvirt::windows::nt::NtCreateFile::CreateOptions;
%ignore introvirt::windows::nt::NtCreateFile::IoStatusBlock;
%ignore introvirt::windows::nt::NtCreateFile::IoStatusResult;
%ignore introvirt::windows::nt::NtCreateFile::AllocationSize;
%ignore introvirt::windows::nt::NtCreateFile::inject;
%include <introvirt/windows/kernel/nt/syscall/NtCreateFile.hh>
%ignore introvirt::windows::nt::NtOpenFile::FileHandlePtr;
%ignore introvirt::windows::nt::NtOpenFile::ObjectAttributesPtr;
%ignore introvirt::windows::nt::NtOpenFile::IoStatusBlockPtr;
%ignore introvirt::windows::nt::NtOpenFile::DesiredAccess;
%ignore introvirt::windows::nt::NtOpenFile::ShareAccess;
%ignore introvirt::windows::nt::NtOpenFile::OpenOptions;
%ignore introvirt::windows::nt::NtOpenFile::IoStatusBlock;
%ignore introvirt::windows::nt::NtOpenFile::IoStatusResult;
%ignore introvirt::windows::nt::NtOpenFile::inject;
%include <introvirt/windows/kernel/nt/syscall/NtOpenFile.hh>
%ignore introvirt::windows::nt::NtClose::inject;
%include <introvirt/windows/kernel/nt/syscall/NtClose.hh>
%ignore introvirt::windows::nt::NtReadWriteFile::ApcRoutinePtr;
%ignore introvirt::windows::nt::NtReadWriteFile::ApcContextPtr;
%ignore introvirt::windows::nt::NtReadWriteFile::IoStatusBlockPtr;
%ignore introvirt::windows::nt::NtReadWriteFile::BufferPtr;
%ignore introvirt::windows::nt::NtReadWriteFile::ByteOffsetPtr;
%ignore introvirt::windows::nt::NtReadWriteFile::KeyPtr;
%ignore introvirt::windows::nt::NtReadWriteFile::IoStatusBlock;
%include <introvirt/windows/kernel/nt/syscall/NtReadWriteFile.hh>
%ignore introvirt::windows::nt::NtReadFile::inject;
%include <introvirt/windows/kernel/nt/syscall/NtReadFile.hh>
%ignore introvirt::windows::nt::NtWriteFile::inject;
%include <introvirt/windows/kernel/nt/syscall/NtWriteFile.hh>
%ignore introvirt::windows::nt::NtDuplicateObject::TargetHandlePtr;
%ignore introvirt::windows::nt::NtDuplicateObject::inject;
%ignore introvirt::windows::nt::NtDuplicateObject::DesiredAccess;
%ignore introvirt::windows::nt::NtDuplicateObject::HandleAttributes;
%ignore introvirt::windows::nt::NtDuplicateObject::Options;
%include <introvirt/windows/kernel/nt/syscall/NtDuplicateObject.hh>
%ignore introvirt::windows::nt::NtQueryAttributesFile::ObjectAttributesPtr;
%ignore introvirt::windows::nt::NtQueryAttributesFile::FileInformation;
%ignore introvirt::windows::nt::NtQueryAttributesFile::inject;
%include <introvirt/windows/kernel/nt/syscall/NtQueryAttributesFile.hh>
%ignore introvirt::windows::nt::NtQueryFullAttributesFile::ObjectAttributesPtr;
%ignore introvirt::windows::nt::NtQueryFullAttributesFile::FileInformation;
%ignore introvirt::windows::nt::NtQueryFullAttributesFile::inject;
%include <introvirt/windows/kernel/nt/syscall/NtQueryFullAttributesFile.hh>
%ignore introvirt::windows::nt::NtDeleteFile::ObjectAttributesPtr;
%include <introvirt/windows/kernel/nt/syscall/NtDeleteFile.hh>
%ignore introvirt::windows::nt::NtQueryInformationFile::FileInformationPtr;
%ignore introvirt::windows::nt::NtQueryInformationFile::IoStatusBlock;
%ignore introvirt::windows::nt::NtQueryInformationFile::inject;
%ignore introvirt::windows::nt::NtQueryInformationFile::FileInformationClass;
%ignore introvirt::windows::nt::NtQueryInformationFile::FileInformation;
%include <introvirt/windows/kernel/nt/syscall/NtQueryInformationFile.hh>
%ignore introvirt::windows::nt::NtSetInformationFile::FileInformationPtr;
%ignore introvirt::windows::nt::NtSetInformationFile::IoStatusBlock;
%ignore introvirt::windows::nt::NtSetInformationFile::inject;
%ignore introvirt::windows::nt::NtSetInformationFile::FileInformationClass;
%ignore introvirt::windows::nt::NtSetInformationFile::FileInformation;
%include <introvirt/windows/kernel/nt/syscall/NtSetInformationFile.hh>
%ignore introvirt::windows::nt::NtDeviceIoControlFile::InputBufferPtr;
%ignore introvirt::windows::nt::NtDeviceIoControlFile::OutputBufferPtr;
%ignore introvirt::windows::nt::NtDeviceIoControlFile::IoStatusBlock;
%ignore introvirt::windows::nt::NtDeviceIoControlFile::inject;
%include <introvirt/windows/kernel/nt/syscall/NtDeviceIoControlFile.hh>
%ignore introvirt::windows::nt::NtMapViewOfSection::BaseAddressPtr;
%ignore introvirt::windows::nt::NtMapViewOfSection::inject;
%ignore introvirt::windows::nt::NtMapViewOfSection::InheritDisposition;
%ignore introvirt::windows::nt::NtMapViewOfSection::AllocationType;
%ignore introvirt::windows::nt::NtMapViewOfSection::Win32Protect;
%include <introvirt/windows/kernel/nt/syscall/NtMapViewOfSection.hh>

/* Helper: cast Guest* to WindowsGuest* (returns None if not Windows guest) */
%inline %{
namespace introvirt { namespace windows {
introvirt::windows::WindowsGuest* WindowsGuest_from_guest(introvirt::Guest* g) {
    return dynamic_cast<introvirt::windows::WindowsGuest*>(g);
}
}} /* namespace introvirt::windows */
%}

/* NT status helper: true if raw status code indicates success (no NTSTATUS_CODE enum in Python) */
%inline %{
namespace introvirt { namespace windows { namespace nt {
bool nt_success(uint32_t code) {
    return NTSTATUS(code).NT_SUCCESS();
}
bool nt_error(uint32_t code) {
    return NTSTATUS(code).NT_ERROR();
}
bool nt_warning(uint32_t code) {
    return NTSTATUS(code).NT_WARNING();
}
bool nt_information(uint32_t code) {
    return NTSTATUS(code).NT_INFORMATION();
}
std::string ntstatus_to_string(uint32_t code) {
    return introvirt::windows::nt::to_string(NTSTATUS(code));
}
}}} /* namespace introvirt::windows::nt */
%}

/* Windows-only: get the NT return value (NTSTATUS) from a Windows syscall *return* event.
 * Returns (ok, value): ok is true only when the event is a Windows NT syscall return with a
 * parsed handler; value is the raw uint32_t status. Use nt_success(value), nt_error(value), etc.
 * For non-Windows or non-return events, returns (false, 0). */
%inline %{
void get_windows_syscall_result_value(const introvirt::Event* e, bool& ok, uint32_t& value) {
    ok = false;
    value = 0;
    if (!e) return;
    auto* wevent = dynamic_cast<const introvirt::windows::WindowsEvent*>(e);
    if (!wevent) return;
    auto* handler = wevent->syscall().handler();
    if (!handler) return;
    auto* nt_call = dynamic_cast<const introvirt::windows::nt::NtSystemCall*>(handler);
    if (!nt_call) return;
    ok = true;
    value = nt_call->result().value();
}
%}

/* Pass DomainInformation::domain_id by value to avoid SWIG wrapping as uint32_t* (leak + wrong repr) */
%naturalvar introvirt::DomainInformation::domain_id;