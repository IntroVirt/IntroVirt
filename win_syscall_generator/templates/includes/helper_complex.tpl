const {{arg['helper']['type']}}* {{arg['name']}}() const override {{ 'final ' if has_children }} {
    if (!{{arg['name']}}_ && {{arg['functionName']}}()) {
        {% if arg['require_success'] -%}
        if (!this->result().NT_SUCCESS() {%- if arg['allow_partial'] %} && result().code() != NTSTATUS::STATUS_BUFFER_OVERFLOW {%- endif -%})
            return nullptr;

        {% endif -%}
        // The {{arg['type']}} hasn't been created yet
                {%- if 'creator' in arg['helper'] %}
        {{arg['name']}}_ = {{ arg['helper']['creator']['name'] }}({%- for helper_arg in arg['helper']['arguments']%}{{helper_arg}}{{ ', ' if not loop.last }}{% endfor %});
                {%- else %}
                {%- if not 'impl_type' in arg %}
        {{arg['name']}}_ = std::make_unique<{{arg['helper']['type']}}>({{ arg['helper']['argumentWrapper'] + '(' if 'argumentWrapper' in arg['helper']}}{%- for helper_arg in arg['helper']['arguments']%}{{helper_arg}}{{ ', ' if not loop.last }}{% endfor %}{{ ')' if 'argumentWrapper' in arg['helper']}});
                {% else %}
                {{arg['name']}}_.emplace({{ arg['helper']['argumentWrapper'] + '(' if 'argumentWrapper' in arg['helper']}}{%- for helper_arg in arg['helper']['arguments']%}{{helper_arg}}{{ ', ' if not loop.last }}{% endfor %}{{ ')' if 'argumentWrapper' in arg['helper']}});
                {% endif %}
                {%- endif %}
    }
    {%- if not 'impl_type' in arg %}
    return {{arg['name']}}_.get();
    {%- else %}
    if ({{arg['name']}}_)
        return &(*{{arg['name']}}_);
    return nullptr;
    {%- endif %}
}
{{arg['helper']['type']}}* {{arg['name']}}() override {
    const auto* const_this = const_cast<const {{ className }}Impl<PtrType, _BaseClass>*>(this);
    return const_cast<{{arg['helper']['type']}}*>(const_this->{{arg['name']}}());
}