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
    mutable uint64_t cached_target_tid_ =  0xFFFFFFFFFFFFFFFFLL;
{%- endblock %}

{%- block write %}
{{ super() }}
    os << '\t' << "Target TID: " << std::dec << target_tid() << '\n';
{%- endblock %}

{%- block overrides %}
{{ super() }}
bool will_return() const override {
    // 0 means terminate the current thread
    return (ThreadHandle() != 0);
}
{%- endblock %}
{%- block helpers %}
{{ super() }}
uint64_t target_tid() const override {
    if (cached_target_tid_ == 0xFFFFFFFFFFFFFFFFLL || cached_target_handle_ != ThreadHandle()) {
        // We don't have this PID cached
        
        if (IS_SELF_HANDLE<PtrType>(ThreadHandle()) || ThreadHandle() == 0) {
            // The thread is terminating itself, easy!
            cached_target_handle_ = ThreadHandle();
            cached_target_tid_ = this->CurrentThread().Cid().UniqueThread();
        } else {
            // It's targeting another thread, look it up in the handle table.
            const THREAD& thread = this->CurrentThread();
            const PROCESS& proc = thread.Process();
            auto ObjectTable = proc.ObjectTable();
            if (!ObjectTable)
                return -1;
            auto target = ObjectTable->ThreadObject(ThreadHandle());
            if (!target)
                return -1;

            cached_target_handle_ = ThreadHandle();    
            cached_target_tid_ = target->Cid().UniqueThread();
        }
    }
    return cached_target_tid_;
}
{%- endblock %}