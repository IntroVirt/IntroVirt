{%- if arg['helper']['rawType'] == 'size_t' -%}
    mutable guest_ptr<PtrType> {{ arg['name'] }}_;
{%- else -%}
    mutable guest_ptr<{{ arg['helper']['rawType'] }}> {{ arg['name'] }}_;
{%- endif -%}