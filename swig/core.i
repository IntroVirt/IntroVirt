/* Parse headers - order matters for dependencies */
%include <introvirt/core/event/EventType.hh>
%include <introvirt/core/event/EventTaskInformation.hh>
%include <introvirt/core/syscall/SystemCall.hh>
%include <introvirt/core/event/SystemCallEvent.hh>
%include <introvirt/core/syscall/SystemCallFilter.hh>
%include <introvirt/core/domain/Guest.hh>
/* TaskFilter and Event (and deps) must be included before Domain so task_filter() return type is wrapped correctly */
%include <introvirt/core/arch/x86/Registers.hh>
%include <introvirt/core/domain/Vcpu.hh>
%include <introvirt/core/event/ControlRegisterEvent.hh>
%include <introvirt/core/event/Event.hh>
%include <introvirt/core/event/EventCallback.hh>
%include <introvirt/core/filter/TaskFilter.hh>
%include <introvirt/core/domain/Domain.hh>
%include <introvirt/core/domain/Hypervisor.hh>
