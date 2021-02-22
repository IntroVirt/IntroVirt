{%- extends 'NtSystemCall.hh.tpl' %}
{%- block includes %}
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
{{ super() }}
{%- endblock %}

{%- block helpers %}
{{ super() }}
    /**
     * @brief Get the newly created THREAD object
     * 
     * @return The newly created thread, or nullptr on error
     * @throw InvalidMethodException if the system call has not returned
     */
    virtual std::shared_ptr<THREAD> get_new_thread() = 0;

    /**
     * @copydoc {{ className }}::get_new_thread()
     */
    virtual const std::shared_ptr<THREAD> get_new_thread() const = 0;
{%- endblock %}
