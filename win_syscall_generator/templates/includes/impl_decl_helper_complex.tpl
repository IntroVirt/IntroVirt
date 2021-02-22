{%- if 'impl_type' in arg %}
mutable std::optional<{{ arg['impl_type'] }}> {{ arg['name'] }}_;
{%- else %}
mutable std::unique_ptr<{{ arg['helper']['rawType'] }}> {{ arg['name'] }}_;
{% endif %}