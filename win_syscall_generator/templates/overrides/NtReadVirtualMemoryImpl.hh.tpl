{%- extends 'NtSystemCallImpl.hh.tpl' %}

{%- block prepare_inject %}
    //const uint8_t previous_mode = thread.PreviousMode();
    // Testing code for making system calls appear to come from the kernel
    // Only seemed to work on x64
    //thread.PreviousMode(0);

{{ super() }}
{%- endblock prepare_inject %}

{%- block cleanup %}
    // Reset the protections
    //thread.PreviousMode(previous_mode);

{{ super() }}
{%- endblock cleanup %}

