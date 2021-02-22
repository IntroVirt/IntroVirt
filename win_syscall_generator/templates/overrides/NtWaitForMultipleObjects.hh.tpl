{%- extends 'NtSystemCall.hh.tpl' %}
{%- block helpers %}
{{ super() }}
    /**
     * @brief Get the handles that are being waited on
     */
    virtual const std::vector<uint64_t>& Handles() const = 0;
  
    /**
     * If WaitType is WaitAnyObject, this will return the handle that completed the wait.
     *
     * @returns The handle for the dispatcher object that was signaled. NULL if WaitType is WaitAllObjects.
     */
    virtual uint64_t CompletedHandle() const = 0;
{%- endblock %}
