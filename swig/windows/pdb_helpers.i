/*
 * PDB helpers: VAD walk and PDB symbol resolution for any tool that needs to
 * resolve symbols from a PDB (e.g. get executable-mapped modules, resolve symbols by pattern).
 * Implementation is in pdb_helpers_impl.h (included only in C++ section) so SWIG
 * never parses vector<pair<uint64_t,string>>. We expose opaque struct return types and
 * convert to list of (address, str) in typemaps.
 */

%{
#include "pdb_helpers_impl.h"
%}

/* Opaque return types - SWIG only sees these, not the vector<pair<>> or pair<uint64_t,string> inside */
struct pdb_module_result { void* p; };
struct pdb_symbol_result { void* p; };
struct pdb_symbol_single_result { void* p; };

/* Convert opaque result to Python list of (int, str) / single (int, str) and free the C++ storage (must be before function decls) */
%typemap(out) pdb_module_result {
    $result = pdb_module_list_to_py($1);
    if (!$result) SWIG_fail;
}
%typemap(out) pdb_symbol_result {
    $result = pdb_symbol_list_to_py($1);
    if (!$result) SWIG_fail;
}
%typemap(out) pdb_symbol_single_result {
    $result = pdb_symbol_single_to_py($1);
    if (!$result) SWIG_fail;
}

/* Accept Python list of str for patterns (const std::vector<std::string>&) */
%typemap(in) const std::vector<std::string>& (std::vector<std::string> temp) {
  if (!PyList_Check($input)) {
    SWIG_exception_fail(SWIG_TypeError, "list of strings expected for patterns");
  }
  temp.clear();
  for (Py_ssize_t i = 0; i < PyList_GET_SIZE($input); i++) {
    PyObject* o = PyList_GET_ITEM($input, i);
    if (!PyUnicode_Check(o)) {
      SWIG_exception_fail(SWIG_TypeError, "patterns list must contain strings");
    }
    Py_ssize_t size;
    const char* s = PyUnicode_AsUTF8AndSize(o, &size);
    if (!s) SWIG_fail;
    temp.push_back(std::string(s, size));
  }
  $1 = &temp;
}

pdb_module_result get_executable_mapped_modules(introvirt::Event* event);
pdb_symbol_result resolve_symbols_via_pdb(
    introvirt::Domain* domain, introvirt::Vcpu* vcpu, uint64_t base_address, const std::vector<std::string>& patterns);
pdb_symbol_single_result resolve_symbol_by_name(
    introvirt::Domain* domain, introvirt::Vcpu* vcpu, uint64_t base_address, const std::string& symbol_name);

%inline %{
uint64_t pdb_rva_to_guest_address(uint64_t base_address, uint32_t rva) {
    return base_address + static_cast<uint64_t>(rva);
}
%}
