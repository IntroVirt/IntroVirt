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
