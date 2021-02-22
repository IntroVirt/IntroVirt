    switch(this->index()) {
    {%- for cond in conditional_indexes %}
        case SystemCallIndex::{{ cond }}:
            {%- for name in conditional_indexes %}
            {%- if cond == name %}
                {%- for arg in arguments %}
                    {%- if 'conditional_indexes' in arg %}
            {{ arg['indexVar'] }} = {{ arg['indexes'][name] }};
                    {%- endif %}
                {%- endfor %}
            {%- endif -%}
            {%- endfor %}
            break;
    {%- endfor %}
        default:
            throw InvalidSystemCallConfiguration("Unspecified argument number for {{className}}");
            break;
    }