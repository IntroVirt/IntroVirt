{%- extends 'NtSystemCallImpl.hh.tpl' %}

{%- block helpers %}
{{ super() }}
IO_STATUS_RESULT IoStatusResult() const override {
    if (likely(this->has_returned() && IoStatusBlock()))
        return static_cast<IO_STATUS_RESULT>(IoStatusBlock()->Information());
    else
        return IO_STATUS_RESULT::FILE_RESULT_UNAVAILABLE;
}
void IoStatusResult(IO_STATUS_RESULT IoStatusResult) override {
    IoStatusBlock()->Information(static_cast<uint64_t>(IoStatusResult));
}
{%- endblock %}

{%- block write %}
{{ super() }}
    if (this->has_returned())
        os << '\t' << "IoStatusResult: " << to_string(IoStatusResult()) << '\n';
{%- endblock %}