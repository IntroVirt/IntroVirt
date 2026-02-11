/*
 * IntroVirt Python bindings - minimal API
 *
 * Exposes Hypervisor, Domain, DomainInformation, EventCallback (with directors),
 * Event, EventType, and Guest for basic VM introspection.
 */

%module(docstring="IntroVirt Python bindings for VM introspection") introvirt

%{
#include <introvirt/core/domain/Hypervisor.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Guest.hh>
#include <introvirt/core/event/EventCallback.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/event/EventType.hh>
#include <introvirt/core/event/EventTaskInformation.hh>

using namespace introvirt;
%}

%include <std_string.i>
%include <std_vector.i>
%include <std_unique_ptr.i>

/* Typemaps for unique_ptr - ownership transfers to Python */
%unique_ptr(introvirt::Domain);
%unique_ptr(introvirt::Hypervisor);

%template(DomainInformationVector) std::vector<introvirt::DomainInformation>;

/* Enable directors for EventCallback so Python can override process_event() */
%feature("director") introvirt::EventCallback;

/* Ignore Domain methods that use std::function, guest_ptr, or complex types */
%ignore introvirt::Domain::create_breakpoint;
%ignore introvirt::Domain::create_watchpoint;
%ignore introvirt::Domain::single_step;
%ignore introvirt::Domain::map_pfns;
%ignore introvirt::Domain::page_directory;
%ignore introvirt::Domain::task_filter;
%ignore introvirt::Domain::system_call_filter;
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

/* Ignore Event methods that require complex subclasses (syscall, cr, msr, etc.) for minimal API */
/* We keep type(), vcpu(), domain(), task() - task() returns EventTaskInformation */
%ignore introvirt::Event::syscall;
%ignore introvirt::Event::cr;
%ignore introvirt::Event::msr;
%ignore introvirt::Event::exception;
%ignore introvirt::Event::mem_access;
%ignore introvirt::Event::json;
%ignore introvirt::Event::impl;

/* Parse headers - order matters for dependencies */
%include <introvirt/core/event/EventType.hh>
%include <introvirt/core/event/EventTaskInformation.hh>
%include <introvirt/core/event/Event.hh>
%include <introvirt/core/event/EventCallback.hh>
%include <introvirt/core/domain/Guest.hh>
%include <introvirt/core/domain/Domain.hh>
%include <introvirt/core/domain/Hypervisor.hh>
