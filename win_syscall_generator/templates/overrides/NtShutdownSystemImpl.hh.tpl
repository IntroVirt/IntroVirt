{%- extends 'NtSystemCallImpl.hh.tpl' %}

{%- block overrides %}
{{ super() }}
bool will_return() const override {
    /* TODO: Not sure exactly how to tell for sure this call won't return */
    /* Assume it won't for now. */
    return false;
}
{%- endblock %}
