/*
 * PDB helpers implementation - only included in C++ section of SWIG wrap,
 * so SWIG never parses vector<pair<uint64_t,string>> and does not generate
 * conflicting conversion code.
 */
#ifndef INTROVIRT_SWIG_PDB_HELPERS_IMPL_H
#define INTROVIRT_SWIG_PDB_HELPERS_IMPL_H

#include <introvirt/introvirt.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/windows/pe/exception/PeException.hh>

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>
#include <vector>

#include <Python.h>

using namespace introvirt;
using namespace introvirt::windows;

namespace {

static bool wildcard_match(const char* pp, const char* ss) {
    if (*pp == '\0')
        return *ss == '\0';
    if (*pp == '*')
        return wildcard_match(pp + 1, ss) || (*ss != '\0' && wildcard_match(pp, ss + 1));
    if (*pp == '?' && *ss != '\0')
        return wildcard_match(pp + 1, ss + 1);
    return (std::tolower(static_cast<unsigned char>(*pp)) == std::tolower(static_cast<unsigned char>(*ss))) && *ss != '\0' && wildcard_match(pp + 1, ss + 1);
}

static bool symbol_matches_pattern(const std::string& pattern, const std::string& symbol) {
    return wildcard_match(pattern.c_str(), symbol.c_str());
}

}  // namespace

typedef std::vector<std::pair<uint64_t, std::string>> PdbListImpl;

static inline PdbListImpl* get_executable_mapped_modules_impl(WindowsEvent* wevent) {
    auto* result = new PdbListImpl();
    if (!wevent)
        return result;
    try {
        nt::PROCESS& process = wevent->task().pcr().CurrentThread().Process();
        auto vadroot = process.VadRoot();
        if (!vadroot)
            return result;
        for (auto entry : vadroot->VadTreeInOrder()) {
            if (!entry->Protection().isExecutable())
                continue;
            const nt::FILE_OBJECT* file_object = entry->FileObject();
            if (!file_object)
                continue;
            try {
                result->emplace_back(entry->StartingAddress(), file_object->FileName());
            } catch (VirtualAddressNotPresentException&) {
                /* skip */
            }
        }
    } catch (VirtualAddressNotPresentException&) {
        /* empty */
    }
    return result;
}

static inline PdbListImpl* resolve_symbols_via_pdb_impl(
    Domain* domain, Vcpu* vcpu, uint64_t base_address, const std::vector<std::string>& patterns) {
    auto* result = new PdbListImpl();
    if (!domain || !vcpu || patterns.empty())
        return result;
    try {
        guest_ptr<void> ptr(*vcpu, base_address);
        std::unique_ptr<pe::PE> lib = pe::PE::make_unique(ptr);
        const mspdb::PDB& pdb = lib->pdb();
        for (const auto& symbol : pdb.global_symbols()) {
            if (!symbol->function() && !symbol->code())
                continue;
            bool matched = false;
            for (const auto& pattern : patterns) {
                if (symbol_matches_pattern(pattern, symbol->name())) {
                    matched = true;
                    break;
                }
            }
            if (!matched)
                continue;
            try {
                uint64_t addr = base_address + symbol->image_offset();
                result->emplace_back(addr, symbol->name());
            } catch (VirtualAddressNotPresentException&) {
                /* skip */
            }
        }
    } catch (VirtualAddressNotPresentException&) {
        /* empty */
    } catch (pe::PeException&) {
        /* empty */
    }
    return result;
}

/* Opaque handle type for SWIG - struct so we can have two distinct typemaps */
struct pdb_module_result { void* p; };
struct pdb_symbol_result { void* p; };

static inline pdb_module_result get_executable_mapped_modules(WindowsEvent* wevent) {
    pdb_module_result h;
    h.p = get_executable_mapped_modules_impl(wevent);
    return h;
}

/* Overload for Event* so Python can pass the callback event (SWIG accepts Event* proxy) */
static inline pdb_module_result get_executable_mapped_modules(Event* event) {
    pdb_module_result h;
    h.p = get_executable_mapped_modules_impl(dynamic_cast<WindowsEvent*>(event));
    return h;
}

static inline pdb_symbol_result resolve_symbols_via_pdb(
    Domain* domain, Vcpu* vcpu, uint64_t base_address, const std::vector<std::string>& patterns) {
    pdb_symbol_result h;
    h.p = resolve_symbols_via_pdb_impl(domain, vcpu, base_address, patterns);
    return h;
}

static inline PyObject* pdb_module_list_to_py(pdb_module_result h) {
    auto* L = static_cast<PdbListImpl*>(h.p);
    if (!L) return PyList_New(0);
    PyObject* result = PyList_New(L->size());
    if (result) {
        for (size_t i = 0; i < L->size(); ++i) {
            PyObject* t = PyTuple_Pack(2,
                PyLong_FromUnsignedLongLong(static_cast<unsigned long long>((*L)[i].first)),
                PyUnicode_FromString((*L)[i].second.c_str()));
            if (!t) { Py_DECREF(result); result = NULL; break; }
            PyList_SET_ITEM(result, i, t);
        }
    }
    delete L;
    return result ? result : PyList_New(0);
}

static inline PyObject* pdb_symbol_list_to_py(pdb_symbol_result h) {
    auto* L = static_cast<PdbListImpl*>(h.p);
    if (!L) return PyList_New(0);
    PyObject* result = PyList_New(L->size());
    if (result) {
        for (size_t i = 0; i < L->size(); ++i) {
            PyObject* t = PyTuple_Pack(2,
                PyLong_FromUnsignedLongLong(static_cast<unsigned long long>((*L)[i].first)),
                PyUnicode_FromString((*L)[i].second.c_str()));
            if (!t) { Py_DECREF(result); result = NULL; break; }
            PyList_SET_ITEM(result, i, t);
        }
    }
    delete L;
    return result ? result : PyList_New(0);
}

#endif
