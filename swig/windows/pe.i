/*
 * PE (Portable Executable) Python bindings.
 * Exposes PE, headers, sections, and export directory. pdb() and ptr() are
 * ignored; use pe_from_address() and pe_base_address() instead.
 */

%include <std_map.i>
%include <std_unordered_map.i>

/* Do not wrap MachineType to_string/operator<< (avoids C symbol redefinition with nt::to_string/operator<<).
 * Use namespace-wide ignore so SWIG does not generate any wrapper for these. */
%ignore introvirt::windows::pe::to_string;
%ignore introvirt::windows::pe::operator<<;

/* MachineType enum (before headers that use it) */
%include <introvirt/windows/pe/const/MachineType.hh>

/* PE exception - include after TraceableException is known */
%include <introvirt/windows/pe/exception/PeException.hh>

/* DOS_HEADER: abstract interface has no methods in public header */
%include <introvirt/windows/pe/types/DOS_HEADER.hh>

/* IMAGE_SECTION_HEADER: ignore VirtualAddress (guest_ptr); use inline helper for address as uint64_t */
%ignore introvirt::windows::pe::IMAGE_SECTION_HEADER::VirtualAddress() const;
%include <introvirt/windows/pe/types/IMAGE_SECTION_HEADER.hh>

/* IMAGE_FILE_HEADER: all methods return primitives or MachineType */
%include <introvirt/windows/pe/types/IMAGE_FILE_HEADER.hh>

/* IMAGE_EXPORT_DIRECTORY and Export: ignore guest_ptr in Export; ignore AddressToExportMap (guest_ptr as key); use inline helper for address */
%ignore introvirt::windows::pe::Export::address;
%ignore introvirt::windows::pe::IMAGE_EXPORT_DIRECTORY::AddressToExportMap() const;
%include <introvirt/windows/pe/types/IMAGE_EXPORT_DIRECTORY.hh>

/* IMAGE_OPTIONAL_HEADER: ignore guest_ptr-returning and directory methods */
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::AddressOfEntryPoint() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::BaseOfCode() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::BaseOfData() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::ptr() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::basereloc_directory() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::debug_directory() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::exception_directory() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::export_directory() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::resource_directory() const;
%ignore introvirt::windows::pe::IMAGE_OPTIONAL_HEADER::import_directory() const;
%include <introvirt/windows/pe/types/IMAGE_OPTIONAL_HEADER.hh>

/* PE: ignore pdb() (mspdb::PDB), ptr() (guest_ptr), and static make_unique(guest_ptr) */
%ignore introvirt::windows::pe::PE::pdb() const;
%ignore introvirt::windows::pe::PE::ptr() const;
%ignore introvirt::windows::pe::PE::make_unique(const guest_ptr<void>&);
%include <introvirt/windows/pe/PE.hh>

%template(PEUniquePtr) std::unique_ptr<introvirt::windows::pe::PE>;

/* Return raw PE* so SWIG does not copy unique_ptr; Python takes ownership. */
%newobject pe_from_address;

/* Factory and helpers: build guest_ptr from Domain+Vcpu+address; base/section/export address as uint64_t.
 * Include full PE headers so inline code sees complete types (wrap.cxx may emit this before PE includes). */
%inline %{
#include <Python.h>
#include <introvirt/windows/pe/types/IMAGE_SECTION_HEADER.hh>
#include <introvirt/windows/pe/types/IMAGE_EXPORT_DIRECTORY.hh>
namespace introvirt { namespace windows { namespace pe {

PE* pe_from_address(introvirt::Domain* domain, introvirt::Vcpu* vcpu, uint64_t base_address) {
    if (!domain || !vcpu) return nullptr;
    guest_ptr<void> ptr(*vcpu, base_address);
    std::unique_ptr<PE> pe = PE::make_unique(ptr);
    return pe.release();
}

uint64_t pe_base_address(const PE* pe) {
    if (!pe) return 0;
    return pe->ptr().address();
}

uint64_t pe_section_virtual_address(const IMAGE_SECTION_HEADER* section) {
    if (!section) return 0;
    return section->VirtualAddress().address();
}

uint64_t pe_export_address_value(const Export* exp) {
    if (!exp) return 0;
    return exp->address.address();
}

PyObject* pe_export_by_name(const PE* pe, const std::string& name) {
    if (!pe) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    const IMAGE_EXPORT_DIRECTORY* dir = pe->export_directory();
    if (!dir) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    const Export* exp = dir->find(name);
    if (!exp) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    PyObject* t = PyTuple_Pack(2,
        PyLong_FromUnsignedLongLong(static_cast<unsigned long long>(pe_export_address_value(exp))),
        PyUnicode_FromString(exp->name.c_str()));
    if (!t) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    return t;
}

std::vector<std::string> pe_export_names(const PE* pe) {
    std::vector<std::string> out;
    if (!pe)
        return out;
    const IMAGE_EXPORT_DIRECTORY* dir = pe->export_directory();
    if (!dir)
        return out;
    const auto& by_name = dir->NameToExportMap();
    out.reserve(by_name.size());
    for (const auto& kv : by_name) {
        out.push_back(kv.first);
    }
    return out;
}

}}} /* namespace introvirt::windows::pe */
%}
