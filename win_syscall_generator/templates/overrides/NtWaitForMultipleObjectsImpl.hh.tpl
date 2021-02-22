{%- extends 'NtSystemCallImpl.hh.tpl' %}


{%- block includes %}
{{ super() }}
#include <algorithm>
{%- endblock includes %}

{%- block helper_variables %}
{{ super() }}
    mutable std::vector<uint64_t> handles_;
{%- endblock helper_variables %}

{%- block helpers %}
{{ super() }}

const std::vector<uint64_t>& Handles() const override {
    if (unlikely(handles_.empty())) {
        guest_ptr<PtrType[]> buffer(pHandleArray_, HandleCount_);
        handles_.reserve(HandleCount_);
        std::copy(buffer.get(), buffer.get() + HandleCount_, std::back_inserter(handles_));
    }
    return handles_;
}

uint64_t CompletedHandle() const override {
    if (this->result().NT_SUCCESS() && WaitType() == OBJECT_WAIT_TYPE::WaitAnyObject) {
        // Find the index to the handle that satisfied the wait
        uint64_t signalIndex = this->result().value();
        return handles_[signalIndex];
    } else {
        return -1;
    }
}

{%- endblock helpers %}

{%- block write %}
{{ super() }}
    os << '\t' << "Handles:\n";
    os << std::hex;
    for(const auto& handle : Handles()) {
        os << "\t\t" << "0x" << handle << '\n';
    }
{%- endblock write %}

{%- block constructor %}
{{ super() }}

    /* Map in the handles. They're input-only, so we can do it here. */
    /* This helps for an issue where the memory is no longer paged in when the call eventually returns */
    try {
        guest_ptr<PtrType[]> buffer(pHandleArray_, HandleCount_);
        handles_.reserve(HandleCount_);
        std::copy(buffer.get(), buffer.get() + HandleCount_, std::back_inserter(handles_));
    } catch (TraceableException& ex) {}

    /* Map in the Timeout for the same reason */
    /* TODO: This probably isn't safe, we'll see an invalid value if the memory has been swapped */
    /*       We should probably copy the value out. */
    if (this->TimeoutPtr())
        this->Timeout();
{%- endblock constructor %}