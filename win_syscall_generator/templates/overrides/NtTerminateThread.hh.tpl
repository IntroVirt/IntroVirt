{%- extends 'NtSystemCall.hh.tpl' %}
{%- block helpers %}
{{ super() }}
    /**
     * @returns The TID of the target process
     */
    virtual uint64_t target_tid() const = 0;
{%- endblock %}
