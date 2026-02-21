/*
 * IntroVirt Python bindings - minimal API
 *
 * Exposes Hypervisor, Domain, DomainInformation, EventCallback (with directors),
 * Event, EventType, and Guest for basic VM introspection.
 */

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

using namespace introvirt;
using namespace introvirt::windows;
%}

%include <std_string.i>
%include <std_vector.i>
%include <std_unique_ptr.i>
%include <std_set.i>
%include <stdint.i>

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
%ignore introvirt::Domain::vcpu;

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

/* SystemCall: expose only name(), supported(), will_return(); no JSON/ostream/data/handle_return */
%ignore introvirt::SystemCall::write;
%ignore introvirt::SystemCall::json;
%ignore introvirt::SystemCall::data;
%ignore introvirt::SystemCall::handle_return_event;

/* SystemCallEvent: internal impl only */
%ignore introvirt::SystemCallEvent::impl;

/* SystemCallFilter::matches(Event&) would require Event; ignore so we can include filter before Domain */
%ignore introvirt::SystemCallFilter::matches;

/* WindowsGuest: expose only category/filter APIs; ignore kernel, syscalls, domain, set_system_call_filter */
%ignore introvirt::windows::WindowsGuest::syscalls;
%ignore introvirt::windows::WindowsGuest::kernel;
%ignore introvirt::windows::WindowsGuest::domain;
%ignore introvirt::windows::WindowsGuest::set_system_call_filter;

/* Vcpu: expose only id() for event.vcpu().id(); ignore registers, domain, intercept_*, inject_*, etc. */
%ignore introvirt::Vcpu::registers;
%ignore introvirt::Vcpu::long_mode;
%ignore introvirt::Vcpu::long_compatibility_mode;
%ignore introvirt::Vcpu::pause;
%ignore introvirt::Vcpu::resume;
%ignore introvirt::Vcpu::intercept_system_calls;
%ignore introvirt::Vcpu::intercept_cr_writes;
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

/* Ignore Event methods that require complex subclasses (cr, msr, etc.) for minimal API */
/* We keep type(), vcpu(), domain(), task(), syscall() - task() returns EventTaskInformation */
%ignore introvirt::Event::cr;
%ignore introvirt::Event::msr;
%ignore introvirt::Event::exception;
%ignore introvirt::Event::mem_access;
%ignore introvirt::Event::json;
%ignore introvirt::Event::impl;

/* Parse headers - order matters for dependencies */
%include <introvirt/core/event/EventType.hh>
%include <introvirt/core/event/EventTaskInformation.hh>
%include <introvirt/core/syscall/SystemCall.hh>
%include <introvirt/core/event/SystemCallEvent.hh>
%include <introvirt/core/syscall/SystemCallFilter.hh>
%include <introvirt/core/domain/Guest.hh>
%include <introvirt/core/domain/Domain.hh>
%include <introvirt/core/domain/Vcpu.hh>
%include <introvirt/core/event/Event.hh>
%include <introvirt/core/event/EventCallback.hh>
%include <introvirt/core/filter/TaskFilter.hh>
%include <introvirt/core/domain/Hypervisor.hh>
%include <introvirt/windows/WindowsGuest.hh>

/* Helper: cast Guest* to WindowsGuest* (returns None if not Windows guest) */
%inline %{
namespace introvirt { namespace windows {
introvirt::windows::WindowsGuest* WindowsGuest_from_guest(introvirt::Guest* g) {
    return dynamic_cast<introvirt::windows::WindowsGuest*>(g);
}
}} /* namespace introvirt::windows */
%}

/* Pass DomainInformation::domain_id by value to avoid SWIG wrapping as uint32_t* (leak + wrong repr) */
%naturalvar introvirt::DomainInformation::domain_id;