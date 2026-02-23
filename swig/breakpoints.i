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
