{%- extends 'NtSystemCallImpl.hh.tpl' %}

{%- block includes %}
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
{{ super() }}
{%- endblock %}


{%- block prepare_inject %}
        // Get the current memory protections
        auto& thread = event.task().pcr().CurrentThread();
        auto& proc = thread.Process();
        const bool DisableDynamicCodeOptOut = thread.DisableDynamicCodeOptOut();
        const bool DisableDynamicCodeAllowOptOut = proc.DisableDynamicCodeAllowOptOut();
        const bool DisableDynamicCode = proc.DisableDynamicCode();

        // Try to disable memory protections
        thread.DisableDynamicCodeOptOut(true);
        proc.DisableDynamicCodeAllowOptOut(true);
        if (!proc.DisableDynamicCodeAllowOptOut()) {
            // Older builds don't support this, so it remains false.
            // Use the heavier-handed approach instead, where we allow
            // dynamic code for the entire process
            proc.DisableDynamicCode(false);
        }
{{ super() }}
{%- endblock prepare_inject %}

{%- block cleanup %}

        // Reset memory protections
        thread.DisableDynamicCodeOptOut(DisableDynamicCodeOptOut);
        proc.DisableDynamicCode(DisableDynamicCode);
        proc.DisableDynamicCodeAllowOptOut(DisableDynamicCodeAllowOptOut);

{{ super() }}
{%- endblock cleanup %}

