{{arg['helper']['type']}} {{arg['name']}}() const override {
    // Check that the address is valid
    if (unlikely(!{{arg['functionName']}}())) {
        throw NullAddressException("Parameter {{ className }}::{{arg['name']}} is a null pointer");
    }

    // Make sure the guest_ptr is mapped in
                    {%- if arg['helper']['rawType'] == 'size_t' %}
    
    if (!{{arg['name']}}_)
        {{arg['name']}}_.reset({{arg['functionName']}}());
        {%- if arg['original_type'] == 'HANDLE' %}
    if (!IS_SELF_HANDLE<PtrType>(*({{arg['name']}}_)))
        return *({{arg['name']}}_) & HANDLE_MASK;      
        {%- endif %}              
    return static_cast<{{arg['helper']['type']}}>(*({{arg['name']}}_));

                    {%- else %}
    if (!{{arg['name']}}_)
        {{arg['name']}}_.reset({{arg['functionName']}}());

                        {%- if arg['rawType'] == arg['type'] %}
    return *({{arg['name']}}_);

                        {%- elif 'creator' in arg['helper'] %}
    return {{ arg['helper']['creator']['name'] }}({%- for helper_arg in arg['helper']['arguments']%}{{helper_arg}}{{ ', ' if not loop.last }}{% endfor %});                
                        {%- else %}
    return static_cast<{{arg['type']}}>(*({{arg['name']}}_));
                        {%- endif %}
                    {%- endif %}
}
void {{arg['name']}}({{arg['helper']['type']}} {{arg['name']}}) override {{ 'final ' if has_children }} {
    // Check that the address is valid
    if (unlikely(!{{arg['functionName']}}())) {
        throw NullAddressException("Parameter {{ className }}::{{arg['name']}} is a null pointer");
    }

    // Make sure the guest_ptr is mapped in
                {%- if arg['helper']['rawType'] == 'size_t' %}
        if (!{{arg['name']}}_)
            {{arg['name']}}_.reset({{arg['functionName']}}());
        *({{arg['name']}}_) = static_cast<PtrType>({{arg['name']}});
                {%- else %}
    if (!{{arg['name']}}_)
        {{arg['name']}}_.reset({{arg['functionName']}}());

                    {%- if arg['rawType'] == arg['type'] %}
    *({{arg['name']}}_) = {{arg['name']}};
                    {%- else %}
    *({{arg['name']}}_) = static_cast<{{arg['rawType']}}>({{arg['name']}});
                    {%- endif %}
                {%- endif %}
}