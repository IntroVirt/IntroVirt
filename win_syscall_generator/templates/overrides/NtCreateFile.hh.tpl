{%- extends 'NtSystemCall.hh.tpl' %}

{%- block includes %}
#include <introvirt/windows/kernel/nt/const/IO_STATUS_RESULT.hh>
{{ super() }}
{%- endblock %}

{%- block helpers %}
{{ super() }}
    /**
     * @returns the IoStatusResult field from the IoStatusBlock
     */
    virtual IO_STATUS_RESULT IoStatusResult() const = 0;

    /**
     * @brief Sets the IoStatusResult field in the IoStatusBlock
     */
    virtual void IoStatusResult(IO_STATUS_RESULT IoStatusResult) = 0;
{%- endblock %}
