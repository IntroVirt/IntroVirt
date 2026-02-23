/* Return uint32_t as Python int to avoid SWIG wrapping as uint32_t* (leak + wrong repr) */
%typemap(out) uint32_t {
  $result = PyLong_FromUnsignedLong($1);
}

/* Return OS enum by value to avoid "memory leak of type OS*" (Guest::os(), Event::os_type()) */
%typemap(out) introvirt::OS {
  $result = PyLong_FromLong(static_cast<long>($1));
}
%typemap(out) OS {
  $result = PyLong_FromLong(static_cast<long>($1));
}

/* Return SystemCallIndex as Python int (like OS) */
%typemap(out) introvirt::windows::SystemCallIndex {
  $result = PyLong_FromUnsignedLong(static_cast<unsigned long>($1));
}
%typemap(out) SystemCallIndex {
  $result = PyLong_FromUnsignedLong(static_cast<unsigned long>($1));
}

/* Accept EventCallback& from Python so director subclasses pass (poll(callback)).
 * argp is the C++ object pointer; SWIG passes the ref as a pointer, so assign argp. */
%typemap(in) introvirt::EventCallback & (void *argp = 0, int res = 0) {
  res = SWIG_ConvertPtr($input, &argp, $descriptor(introvirt::EventCallback *), 0);
  if (!SWIG_IsOK(res)) {
    SWIG_exception_fail(SWIG_ArgError(res), "in method, argument of type \"introvirt::EventCallback &\"");
  }
  if (!argp) {
    SWIG_exception_fail(SWIG_ValueError, "invalid null reference");
  }
  $1 = reinterpret_cast<introvirt::EventCallback *>(argp);
}
%typemap(in) EventCallback & (void *argp = 0, int res = 0) {
  res = SWIG_ConvertPtr($input, &argp, $descriptor(introvirt::EventCallback *), 0);
  if (!SWIG_IsOK(res)) {
    SWIG_exception_fail(SWIG_ArgError(res), "in method, argument of type \"EventCallback &\"");
  }
  if (!argp) {
    SWIG_exception_fail(SWIG_ValueError, "invalid null reference");
  }
  $1 = reinterpret_cast<introvirt::EventCallback *>(argp);
}

/* Typemaps for unique_ptr - ownership transfers to Python */
%unique_ptr(introvirt::Domain);
%unique_ptr(introvirt::Hypervisor);

%template(DomainInformationVector) std::vector<introvirt::DomainInformation>;
%template(StringSet) std::set<std::string>;

%feature("director") EventCallback;
%feature("director") BreakpointCallback;
%feature("director") DomainMonitor;
%feature("director") SingleStepCallback;

/*
 * Director callbacks (e.g. EventCallback::process_event) can be invoked from
 * C++ worker threads. We must hold the Python GIL for the whole upcall.
 * Acquire in directorin for Event& (process_event's only arg), release in
 * directorout for void; use a thread-local flag so only this path releases.
 */
%{
static thread_local bool swig_director_gil_acquired = false;
%}
%typemap(directorin) introvirt::Event & %{
  swig_director_gil_acquired = true;
  SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  $input = SWIG_NewPointerObj(SWIG_as_voidptr(&$1), $descriptor, 0);
%}
%typemap(directorout) void %{
  if (swig_director_gil_acquired) {
    swig_director_gil_acquired = false;
    SWIG_PYTHON_THREAD_END_BLOCK;
  }
%}
