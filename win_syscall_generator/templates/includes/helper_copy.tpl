{{arg['helper']['type']}} {{arg['name']}}() const override {{ 'final ' if has_children }} {
    if (!has{{ arg['name'] }}_) {
{%- if arg['helper']['rawType'] == 'size_t' %}
        {{arg['name']}}_ = *guest_ptr<PtrType>({{arg['functionName']}}());        
{%- else %}
        {{arg['name']}}_ = *guest_ptr<{{arg['rawType']}}>({{arg['functionName']}}());
{%- endif %}
        has{{ arg['name'] }}_ = true;
    }
    {%- if arg['rawType'] == arg['type'] %}
    return {{arg['name']}}_;
    {%- else %}
    return static_cast<{{arg['type']}}>({{arg['name']}}_);
    {%- endif %}
}
void {{arg['name']}}({{arg['helper']['type']}} {{arg['name']}}) override {
{%- if arg['helper']['rawType'] == 'size_t' %}
    *guest_ptr<PtrType>({{arg['functionName']}}()) = {{arg['name']}};    
{%- else %}
    {%- if arg['rawType'] == arg['type'] %}
    *guest_ptr<{{arg['rawType']}}>({{arg['functionName']}}()) = {{arg['name']}};
    {%- else %}
    *guest_ptr<{{arg['rawType']}}>({{arg['functionName']}}()) = static_cast<{{arg['rawType']}}>({{arg['name']}});
    {%- endif %}
{%- endif %}
    {{arg['name']}}_ = {{arg['name']}};
    has{{ arg['name'] }}_ = true;
}