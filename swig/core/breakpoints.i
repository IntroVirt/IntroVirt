/* Breakpoint: expose class for create_breakpoint return; ignore callback (std::function) and data (shared_ptr<void>) */
%ignore introvirt::Breakpoint::callback;
%ignore introvirt::Breakpoint::data;
%include <introvirt/core/breakpoint/Breakpoint.hh>
%shared_ptr(introvirt::Breakpoint);

/* Holder so Python proxy has a real destructor (avoids "no destructor found" for shared_ptr*).
 * Holds optional py_callback so we Py_DECREF when the holder is destroyed (breakpoint path that uses PyObject*). */
%inline %{
#include <Python.h>
namespace introvirt {
struct BreakpointHolder {
    std::shared_ptr<Breakpoint>* ptr;
    PyObject* py_callback;  /* NULL if created from C++ path; otherwise DECREF in destructor */
    explicit BreakpointHolder(std::shared_ptr<Breakpoint>* p, PyObject* py = nullptr)
        : ptr(p), py_callback(py) {}
    ~BreakpointHolder() {
        delete ptr;
        Py_XDECREF(py_callback);
    }
    std::shared_ptr<Breakpoint>& get() { return *ptr; }
    const std::shared_ptr<Breakpoint>& get() const { return *ptr; }
};
}
%}
%ignore introvirt::BreakpointHolder::ptr;
%ignore introvirt::BreakpointHolder::py_callback;

/* Director still used for type hierarchy; breakpoint creation uses PyObject* path below to avoid
 * director from worker thread (segfault when director memory is in a region that can be overwritten). */
%feature("director") introvirt::BreakpointCallback;
%inline %{
namespace introvirt {
struct BreakpointCallback {
    virtual void breakpoint_hit(Event& e) = 0;
    virtual ~BreakpointCallback() = default;
};
std::shared_ptr<Breakpoint> create_breakpoint(Domain* domain, Vcpu* vcpu, uint64_t address, BreakpointCallback* callback) {
    if (!domain || !vcpu || !callback) return nullptr;
    guest_ptr<void> ptr(*vcpu, address);
    return domain->create_breakpoint(ptr, [callback](Event& e) { callback->breakpoint_hit(e); });
}

/* Python breakpoint path: capture PyObject* and call Python from lambda (with GIL). No director used. */
static void call_python_breakpoint_hit(PyObject* handler, introvirt::Event& e) {
    PyGILState_STATE state = PyGILState_Ensure();
    PyObject* event_obj = SWIG_NewPointerObj(SWIG_as_voidptr(&e), SWIGTYPE_p_introvirt__Event, 0);
    PyObject* method = PyUnicode_FromString("breakpoint_hit");
    PyObject* result = method ? PyObject_CallMethodObjArgs(handler, method, event_obj, NULL) : NULL;
    Py_XDECREF(method);
    Py_XDECREF(event_obj);
    Py_XDECREF(result);
    if (PyErr_Occurred())
        PyErr_Print();
    PyGILState_Release(state);
}

BreakpointHolder* create_breakpoint_holder(Domain* domain, Vcpu* vcpu, uint64_t address, PyObject* py_breakpoint_callback) {
    if (!domain || !vcpu || !py_breakpoint_callback) return nullptr;
    Py_INCREF(py_breakpoint_callback);
    guest_ptr<void> ptr(*vcpu, address);
    std::shared_ptr<Breakpoint> sp = domain->create_breakpoint(ptr, [py_breakpoint_callback](introvirt::Event& e) {
        call_python_breakpoint_hit(py_breakpoint_callback, e);
    });
    if (!sp) {
        Py_DECREF(py_breakpoint_callback);
        return nullptr;
    }
    return new BreakpointHolder(new std::shared_ptr<Breakpoint>(std::move(sp)), py_breakpoint_callback);
}
} /* namespace introvirt */
%}

/* Watchpoint and SingleStep: expose classes; ignore callback (std::function). Bridge via directors. */
%ignore introvirt::Watchpoint::callback;
%include <introvirt/core/breakpoint/Watchpoint.hh>
%ignore introvirt::SingleStep::callback;
%include <introvirt/core/breakpoint/SingleStep.hh>

%feature("director") introvirt::WatchpointCallback;
%feature("director") introvirt::SingleStepCallback;
%inline %{
namespace introvirt {
struct WatchpointCallback {
    virtual void watchpoint_hit(Event& e) = 0;
    virtual ~WatchpointCallback() = default;
};
struct SingleStepCallback {
    virtual void single_step_hit(Event& e) = 0;
    virtual ~SingleStepCallback() = default;
};
std::unique_ptr<Watchpoint> create_watchpoint(Domain* domain, Vcpu* vcpu, uint64_t address, uint64_t length, bool read, bool write, bool execute, WatchpointCallback* callback) {
    if (!domain || !vcpu || !callback) return nullptr;
    guest_ptr<void> ptr(*vcpu, address);
    return domain->create_watchpoint(ptr, length, read, write, execute, [callback](Event& e) { callback->watchpoint_hit(e); });
}
std::unique_ptr<SingleStep> single_step(Domain* domain, Vcpu* vcpu, SingleStepCallback* callback) {
    if (!domain || !vcpu || !callback) return nullptr;
    return domain->single_step(*vcpu, [callback](Event& e) { callback->single_step_hit(e); });
}
} /* namespace introvirt */
%}
