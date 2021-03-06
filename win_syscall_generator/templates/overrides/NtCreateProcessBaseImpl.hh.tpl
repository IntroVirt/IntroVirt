{%- extends 'NtSystemCallImpl.hh.tpl' %}

{%- block includes %}
#include "windows/kernel/nt/types/HANDLE_TABLE_IMPL.hh"
{{ super() }}
{%- endblock %}

{%- block helper_variables %}
{{ super() }}
    mutable std::shared_ptr<PROCESS> new_process_;
{%- endblock %}

{%- block helpers %}
{{ super() }}
const std::shared_ptr<PROCESS> get_new_process() const override {
    return const_cast<{{ className }}Impl<PtrType, ArgumentCount, _BaseClass>*>(this)->get_new_process();
}

std::shared_ptr<PROCESS> get_new_process() override {
    // Make sure we're not being called before the call has returned
    if (unlikely(!this->has_returned())) {
        // get_new_process() not available before {{ className }} returns
        throw InvalidMethodException();
    }

    if ((new_process_ == nullptr) && (ProcessHandle() != 0u)) {
        auto& thread = this->CurrentThread();
        PROCESS& proc = thread.Process();
        auto table = proc.ObjectTable();
        if (unlikely(!table))
            return nullptr;        

        new_process_ = table->ProcessObject(ProcessHandle());
    }

    return new_process_;
}
{%- endblock %}