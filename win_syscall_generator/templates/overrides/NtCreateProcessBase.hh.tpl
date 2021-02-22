{%- extends 'NtSystemCall.hh.tpl' %}
{%- block includes %}
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
{{ super() }}
{%- endblock %}

{%- block helpers %}
{{ super() }}
    /**
     * @brief Get the newly created PROCESS object
     * 
     * @return The newly created process, or nullptr on error
     * @throw InvalidMethodException if the system call has not returned
     */
    virtual std::shared_ptr<PROCESS> get_new_process() = 0;

    /**
     * @copydoc {{ className }}::get_new_thread()
     */
    virtual const std::shared_ptr<PROCESS> get_new_process() const = 0;
{%- endblock %}
