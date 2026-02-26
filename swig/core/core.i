/* Parse headers - order matters for dependencies */
%include <introvirt/core/event/EventType.hh>
%include <introvirt/core/event/EventTaskInformation.hh>
%include <introvirt/core/syscall/SystemCall.hh>
%include <introvirt/core/event/SystemCallEvent.hh>
%include <introvirt/core/syscall/SystemCallFilter.hh>
%include <introvirt/core/domain/Guest.hh>
/* TaskFilter and Event (and deps) must be included before Domain so task_filter() return type is wrapped correctly */
%include <introvirt/core/arch/x86/Registers.hh>
/* Helper to set RAX from Python (overloaded rax(val) can fail dispatch with one arg) */
%inline %{
namespace introvirt { namespace x86 {
void set_register_rax(Registers* r, uint64_t val) { if (r) r->rax(val); }
}}
%}
%rename("$ignore") introvirt::x86::to_string;
%rename("$ignore") introvirt::x86::operator<<;
%include <introvirt/core/arch/x86/Exception.hh>
%include <introvirt/core/domain/Vcpu.hh>
%include <introvirt/core/event/ControlRegisterEvent.hh>
/* MemAccessEvent: include explicitly so SWIG generates full proxy (write_violation, read_violation, etc.).
   Ignore physical_address() (returns guest_phys_ptr); add physical_address_value() for Python. */
%ignore introvirt::MemAccessEvent::physical_address;
%include <introvirt/core/event/MemAccessEvent.hh>
%extend introvirt::MemAccessEvent {
    uint64_t physical_address_value() const { return $self->physical_address().address(); }
}
%include <introvirt/core/event/Event.hh>
%include <introvirt/core/event/EventCallback.hh>
%include <introvirt/core/filter/TaskFilter.hh>
%include <introvirt/core/domain/Domain.hh>
%include <introvirt/core/domain/Hypervisor.hh>
