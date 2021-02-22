{%- extends 'NtSystemCallImpl.hh.tpl' %}

{%- block overrides %}
{{ super() }}

bool will_return() const override {
    /* Not strictly true, it will return on error. Not sure how to check for that yet. */
    /* We may need a "might return" path. */
    return false;
}

{%- endblock %}