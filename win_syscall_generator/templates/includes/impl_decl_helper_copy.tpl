mutable bool has{{ arg['name'] }}_ = false;
{%- if arg['helper']['rawType'] == 'size_t' %}
    mutable uint64_t {{ arg['name'] }}_;
{%- else %}
    mutable {{ arg['helper']['rawType'] }} {{ arg['name'] }}_;
{%- endif -%}