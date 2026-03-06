/*
 * Guest memory helpers for Python: read/write guest memory without exposing guest_ptr.
 * Used by callmon (return breakpoint), filemon, and vmcall_interface (string reverse).
 */
/* Python bytes -> (const char* data, size_t size): one Python arg fills both; must be before the function */
%typemap(in) (const char* data, size_t size) (Py_ssize_t size = 0) {
  if (PyBytes_Check($input)) {
    $1 = PyBytes_AsString($input);
    $2 = PyBytes_Size($input);
    if ($1 == NULL) SWIG_fail;
  } else {
    SWIG_exception_fail(SWIG_TypeError, "expected bytes");
  }
}

%inline %{
#include <Python.h>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/core/memory/guest_size_t_ptr.hh>

namespace introvirt {

/** Read 8 bytes (64-bit) or 4 bytes (32-bit guest) at guest virtual address as uint64_t. */
inline uint64_t read_guest_uint64(Domain* domain, Vcpu* vcpu, uint64_t vaddr) {
    if (!domain || !vcpu) return 0;
    guest_ptr<guest_size_t> ptr(*vcpu, vaddr);
    return static_cast<uint64_t>(ptr.get());
}

/** Read 4 bytes at guest virtual address as uint32_t (low 32 bits). */
inline uint32_t read_guest_uint32(Domain* domain, Vcpu* vcpu, uint64_t vaddr) {
    if (!domain || !vcpu) return 0;
    guest_ptr<guest_size_t> ptr(*vcpu, vaddr);
    return static_cast<uint32_t>(ptr.get());
}

/** Read a null-terminated C string from guest memory (max 0xFFFF bytes). */
inline std::string read_guest_cstring(Domain* domain, Vcpu* vcpu, uint64_t vaddr) {
    if (!domain || !vcpu) return std::string();
    guest_ptr<void> p(*vcpu, vaddr);
    auto cstr = map_guest_cstring(p);
    const char* cp = cstr.get();
    return cp ? std::string(cp) : std::string();
}

/** Write raw bytes to guest virtual address. */
inline void write_guest_bytes(Domain* domain, Vcpu* vcpu, uint64_t vaddr,
                              const char* data, size_t size) {
    if (!domain || !vcpu || !data) return;
    if (size == 0) return;
    guest_ptr<uint8_t[]> ptr(*vcpu, vaddr, size);
    for (size_t i = 0; i < size; ++i)
        ptr.set(i, static_cast<uint8_t>(data[i]));
}

/** Read raw bytes from guest virtual address into a Python bytes object (size is capped). */
inline PyObject* read_guest_bytes(Domain* domain, Vcpu* vcpu, uint64_t vaddr, size_t size) {
    if (!domain || !vcpu || size == 0) {
        return PyBytes_FromStringAndSize("", 0);
    }
    const size_t kMaxSize = 0x100000; /* 1 MiB safety cap */
    if (size > kMaxSize)
        size = kMaxSize;
    guest_ptr<uint8_t[]> ptr(*vcpu, vaddr, size);
    PyObject* result = PyBytes_FromStringAndSize(nullptr, static_cast<Py_ssize_t>(size));
    if (!result)
        return nullptr;
    char* buf = PyBytes_AsString(result);
    if (!buf) {
        Py_DECREF(result);
        return nullptr;
    }
    auto base = ptr.get();
    for (size_t i = 0; i < size; ++i)
        buf[i] = static_cast<char>(base[i]);
    return result;
}

} /* namespace introvirt */
%}
