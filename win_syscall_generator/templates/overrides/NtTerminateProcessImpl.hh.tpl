{%- extends 'NtSystemCallImpl.hh.tpl' %}

{%- block includes %}
#include "windows/kernel/nt/types/HANDLE_TABLE_IMPL.hh"

#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
{{ super() }}
{%- endblock %}

{%- block helper_variables %}
{{ super() }}
    mutable uint64_t cached_target_handle_;
    mutable uint64_t cached_target_pid_ = 0xFFFFFFFFFFFFFFFFLL;
{%- endblock %}

{%- block write %}
{{ super() }}
    os << '\t' << "Target PID: " << std::dec << target_pid() << '\n';
{%- endblock %}

{%- block overrides %}
{{ super() }}

bool will_return() const override {
   /*
     * NtTerminateProcess is called by an application twice to terminate itself.
     * The first time it's called with a 0 argument, the next with -1.
     *
     * The -1 will not return, the application will be terminated.
     *
     * If another process calls NtTerminateProcess to kill a different process,
     * the handle will look normal and the call will return.
     */
    if (!IS_SELF_HANDLE<PtrType>(ProcessHandle()) && ProcessHandle() != 0) {
        // This is one program terminating another
        return true;
    }

    /* TODO (pape): A 0 ProcessHandle will kill all threads in the process, except the caller.
     *              Should we handle that somehow?
     */
    // This is a program terminating itself. It will only return if the handle is 0.
    return (ProcessHandle() == 0);
}
{%- endblock %}
{%- block helpers %}
{{ super() }}
uint64_t target_pid() const override {
    if (cached_target_pid_ == 0xFFFFFFFFFFFFFFFFLL || cached_target_handle_ != ProcessHandle()) {
        // We don't have this PID cached
        if (IS_SELF_HANDLE<PtrType>(ProcessHandle()) || ProcessHandle() == 0) {
            // The thread is terminating itself, easy!
            cached_target_handle_ = ProcessHandle();
            cached_target_pid_ = this->CurrentThread().Cid().UniqueProcess();
        } else {
            // It's targeting another process, look it up in the handle table.
            const THREAD& thread = this->CurrentThread();
            const PROCESS& proc = thread.Process();
            auto table = proc.ObjectTable();
            if (unlikely(!table))
                return -1;

            auto target = table->ProcessObject(ProcessHandle());
            if (!target)
                return -1;

            cached_target_handle_ = ProcessHandle();
            cached_target_pid_ = target->UniqueProcessId();
        }               
    }
    return cached_target_pid_;
}
{%- endblock %}
    