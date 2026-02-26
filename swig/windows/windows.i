/* SystemCallIndex and NTSTATUS before WindowsGuest (set_system_call_filter uses SystemCallIndex). */
%rename("$ignore") introvirt::windows::to_string;
%rename("$ignore") introvirt::windows::operator<<;
%include <introvirt/windows/kernel/SystemCallIndex.hh>

/* NTSTATUS: ignore Json and NTSTATUS_CODE-using members; expose value(), NT_SUCCESS(), etc. */
%ignore introvirt::windows::nt::NTSTATUS::json() const;
%ignore introvirt::windows::nt::NTSTATUS::operator Json::Value() const;
%ignore introvirt::windows::nt::NTSTATUS::code() const;
%ignore introvirt::windows::nt::NTSTATUS::operator NTSTATUS_CODE() const;
%ignore introvirt::windows::nt::NTSTATUS::operator bool() const;
%ignore introvirt::windows::nt::NTSTATUS::NT_SUCCESS(NTSTATUS_CODE);
%ignore introvirt::windows::nt::NTSTATUS::NT_INFORMATION(NTSTATUS_CODE);
%ignore introvirt::windows::nt::NTSTATUS::NT_WARNING(NTSTATUS_CODE);
%ignore introvirt::windows::nt::NTSTATUS::NT_ERROR(NTSTATUS_CODE);
%ignore introvirt::windows::nt::NTSTATUS::NTSTATUS(NTSTATUS_CODE);
%rename("$ignore") introvirt::windows::nt::to_string;
%rename("$ignore") introvirt::windows::nt::operator<<;
%include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>

%include <introvirt/windows/WindowsGuest.hh>

/* Windows event hierarchy: WindowsSystemCall -> WindowsSystemCallEvent; KPCR -> WindowsEventTaskInformation -> WindowsEvent */
%include <introvirt/windows/kernel/WindowsSystemCall.hh>
%include <introvirt/windows/event/WindowsSystemCallEvent.hh>
%ignore introvirt::windows::nt::KPCR::CurrentThread;
%include <introvirt/windows/kernel/nt/types/KPCR.hh>
%nodefaultdtor introvirt::windows::WindowsEventTaskInformation;
%include <introvirt/windows/event/WindowsEventTaskInformation.hh>
%include <introvirt/windows/event/WindowsEvent.hh>

/* OBJECT_ATTRIBUTES: expose FullPath(KPCR), ObjectName, Length, RootDirectory, Attributes, isInheritable; ignore write, json, guest_ptr */
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::write;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::json;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::ObjectNamePtr;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::SecurityQualityOfServicePtr;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::ptr;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::make_unique;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::SecurityDescriptor;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::SecurityQualityOfService;
%ignore introvirt::windows::nt::OBJECT_ATTRIBUTES::Attributes;
%include <introvirt/windows/kernel/nt/syscall/types/OBJECT_ATTRIBUTES.hh>

/* NtSystemCall: expose result() getter; ignore result(NTSTATUS_CODE) setter */
%ignore introvirt::windows::nt::NtSystemCall::result(NTSTATUS_CODE);
%include <introvirt/windows/kernel/nt/syscall/NtSystemCall.hh>

/* Generated: get_concrete_handler(WindowsEvent*) so Python gets concrete handler type (e.g. NtCreateFile). */
%include "windows_syscalls_generated.i"

%inline %{
#include <introvirt/core/memory/guest_ptr.hh>
namespace introvirt { namespace windows { namespace nt {
uint64_t get_nt_open_process_target_pid(NtOpenProcess* h) {
    return h && h->ClientId() ? h->ClientId()->UniqueProcess() : 0;
}
void block_open_process_client_id(NtOpenProcess* h) {
    if (h) h->ClientIdPtr(guest_ptr<void>());
}
}}}
%}

/* Helper: cast Guest* to WindowsGuest* (returns None if not Windows guest) */
%inline %{
namespace introvirt { namespace windows {
introvirt::windows::WindowsGuest* WindowsGuest_from_guest(introvirt::Guest* g) {
    return dynamic_cast<introvirt::windows::WindowsGuest*>(g);
}
introvirt::windows::WindowsEvent* WindowsEvent_from_event(introvirt::Event* e) {
    return dynamic_cast<introvirt::windows::WindowsEvent*>(e);
}
}} /* namespace introvirt::windows */
%}

/* NT status helper: true if raw status code indicates success (no NTSTATUS_CODE enum in Python) */
%inline %{
namespace introvirt { namespace windows { namespace nt {
bool nt_success(uint32_t code) {
    return NTSTATUS(code).NT_SUCCESS();
}
bool nt_error(uint32_t code) {
    return NTSTATUS(code).NT_ERROR();
}
bool nt_warning(uint32_t code) {
    return NTSTATUS(code).NT_WARNING();
}
bool nt_information(uint32_t code) {
    return NTSTATUS(code).NT_INFORMATION();
}
std::string ntstatus_to_string(uint32_t code) {
    return introvirt::windows::nt::to_string(NTSTATUS(code));
}
}}} /* namespace introvirt::windows::nt */
%}

/* Windows-only: get the NT return value (NTSTATUS) from a Windows syscall *return* event.
 * Returns (ok, value): ok is true only when the event is a Windows NT syscall return with a
 * parsed handler; value is the raw uint32_t status. Use nt_success(value), nt_error(value), etc.
 * For non-Windows or non-return events, returns (false, 0). */
%typemap(in, numinputs=0) (bool& ok, uint32_t& value) (bool temp_ok, uint32_t temp_value) {
  $1 = &temp_ok;
  $2 = &temp_value;
}
%typemap(argout) (bool& ok, uint32_t& value) {
  PyObject *o1 = PyBool_FromLong(*$1 ? 1 : 0);
  PyObject *o2 = PyLong_FromUnsignedLong(*$2);
  $result = SWIG_Python_AppendOutput($result, o1);
  $result = SWIG_Python_AppendOutput($result, o2);
}
%inline %{
void get_windows_syscall_result_value(const introvirt::Event* e, bool& ok, uint32_t& value) {
    ok = false;
    value = 0;
    if (!e) return;
    auto* wevent = dynamic_cast<const introvirt::windows::WindowsEvent*>(e);
    if (!wevent) return;
    auto* handler = wevent->syscall().handler();
    if (!handler) return;
    auto* nt_call = dynamic_cast<const introvirt::windows::nt::NtSystemCall*>(handler);
    if (!nt_call) return;
    ok = true;
    value = nt_call->result().value();
}
%}

/* Pass DomainInformation::domain_id by value to avoid SWIG wrapping as uint32_t* (leak + wrong repr) */
%naturalvar introvirt::DomainInformation::domain_id;

/* PE (Portable Executable) support */
%include "pe.i"

/* PDB helpers (VAD walk, get_executable_mapped_modules, resolve_symbols_via_pdb) */
%include "pdb_helpers.i"
