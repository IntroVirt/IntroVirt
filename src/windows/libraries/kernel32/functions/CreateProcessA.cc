/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "windows/injection/function.hh"
#include <introvirt/core/event/ThreadLocalEvent.hh>

#include <introvirt/core/injection/function_call.hh>
#include <introvirt/core/injection/system_call.hh>
#include <introvirt/windows/libraries/kernel32/functions/CreateProcessA.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace kernel32 {

GuestVirtualAddress CreateProcessA::lpApplicationName() const { return lpApplicationName_; }
void CreateProcessA::lpApplicationName(const GuestVirtualAddress& gva) {
    set_address_argument(0, gva);
    lpApplicationName_ = gva;
}

GuestVirtualAddress CreateProcessA::lpCommandLine() const { return lpCommandLine_; }
void CreateProcessA::lpCommandLine(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    lpCommandLine_ = gva;
}

GuestVirtualAddress CreateProcessA::lpProcessAttributes() const { return lpProcessAttributes_; }
void CreateProcessA::lpProcessAttributes(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    lpProcessAttributes_ = gva;
}

GuestVirtualAddress CreateProcessA::lpThreadAttributes() const { return lpThreadAttributes_; }
void CreateProcessA::lpThreadAttributes(const GuestVirtualAddress& gva) {
    set_address_argument(3, gva);
    lpThreadAttributes_ = gva;
}

bool CreateProcessA::bInheritHandles() const { return bInheritHandles_; }
void CreateProcessA::bInheritHandles(bool InheritHandles) {
    set_argument(4, InheritHandles);
    bInheritHandles_ = InheritHandles;
}

uint32_t CreateProcessA::dwCreationFlags() const { return dwCreationFlags_; }
void CreateProcessA::dwCreationFlags(uint32_t CreationFlags) {
    set_argument(5, CreationFlags);
    dwCreationFlags_ = CreationFlags;
}

GuestVirtualAddress CreateProcessA::lpEnvironment() const { return lpEnvironment_; }
void CreateProcessA::lpEnvironment(const GuestVirtualAddress& gva) {
    set_address_argument(6, gva);
    lpEnvironment_ = gva;
}

GuestVirtualAddress CreateProcessA::lpCurrentDirectory() const { return lpCurrentDirectory_; }
void CreateProcessA::lpCurrentDirectory(const GuestVirtualAddress& gva) {
    set_address_argument(7, gva);
    lpCurrentDirectory_ = gva;
}

GuestVirtualAddress CreateProcessA::lpStartupInfo() const { return lpStartupInfo_; }
void CreateProcessA::lpStartupInfo(const GuestVirtualAddress& gva) {
    set_address_argument(8, gva);
    lpStartupInfo_ = gva;
}

GuestVirtualAddress CreateProcessA::lpProcessInformation() const { return lpProcessAttributes_; }
void CreateProcessA::lpProcessInformation(const GuestVirtualAddress& gva) {
    set_address_argument(9, gva);
    lpProcessAttributes_ = gva;
}

std::string CreateProcessA::ApplicationName() const {
    auto mapping = map_guest_cstr(lpApplicationName());
    return std::string(mapping.get(), mapping.length());
}

std::string CreateProcessA::CommandLine() const {
    auto mapping = map_guest_cstr(lpCommandLine());
    return std::string(mapping.get(), mapping.length());
}

std::string CreateProcessA::CurrentDirectory() const {
    auto mapping = map_guest_cstr(lpCurrentDirectory());
    return std::string(mapping.get(), mapping.length());
}

bool CreateProcessA::result() const { return raw_return_value(); }

const std::string& CreateProcessA::function_name() const { return FunctionName; }
const std::string& CreateProcessA::library_name() const { return LibraryName; }

void CreateProcessA::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CreateProcessA::CreateProcessA(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    lpApplicationName_ = get_address_argument(0);
    lpCommandLine_ = get_address_argument(1);
    lpProcessAttributes_ = get_address_argument(2);
    lpThreadAttributes_ = get_address_argument(3);
    bInheritHandles_ = get_argument(4);
    dwCreationFlags_ = get_argument(5);
    lpEnvironment_ = get_address_argument(6);
    lpCurrentDirectory_ = get_address_argument(7);
    lpStartupInfo_ = get_address_argument(8);
    lpProcessInformation_ = get_address_argument(9);
}

CreateProcessA::CreateProcessA(Event& event, const GuestVirtualAddress& lpApplicationName,
                               const GuestVirtualAddress& lpCommandLine,
                               const GuestVirtualAddress& lpProcessAttributes,
                               const GuestVirtualAddress& lpThreadAttributes, bool bInheritHandles,
                               uint32_t dwCreationFlags, const GuestVirtualAddress& lpEnvironment,
                               const GuestVirtualAddress& lpCurrentDirectory,
                               const GuestVirtualAddress& lpStartupInfo,
                               const GuestVirtualAddress& lpProcessInformation)
    : WindowsFunctionCall(event, ArgumentCount) {

    this->lpApplicationName(lpApplicationName);
    this->lpCommandLine(lpCommandLine);
    this->lpProcessAttributes(lpProcessAttributes);
    this->lpThreadAttributes(lpThreadAttributes);
    this->bInheritHandles(bInheritHandles);
    this->dwCreationFlags(dwCreationFlags);
    this->lpEnvironment(lpEnvironment);
    this->lpCurrentDirectory(lpCurrentDirectory);
    this->lpStartupInfo(lpStartupInfo);
    this->lpProcessInformation(lpProcessInformation);
}

bool CreateProcessA::inject(std::string_view ApplicationName, std::string_view CommandLine,
                            const GuestVirtualAddress& lpProcessAttributes,
                            const GuestVirtualAddress& lpThreadAttributes, bool bInheritHandles,
                            uint32_t dwCreationFlags, const GuestVirtualAddress& lpEnvironment,
                            std::string_view CurrentDirectory,
                            const GuestVirtualAddress& lpStartupInfo,
                            const GuestVirtualAddress& lpProcessInformation) {

    auto& event = ThreadLocalEvent::get();

    // TODO: We need a way of passing nullptr easily, this feels clunky

    std::optional<introvirt::inject::GuestAllocation<char[]>> lpApplicationName;
    std::optional<introvirt::inject::GuestAllocation<char[]>> lpCommandLine;
    std::optional<introvirt::inject::GuestAllocation<char[]>> lpCurrentDirectory;

    // Allocate our strings in the guest if they're not empty
    if (!ApplicationName.empty())
        lpApplicationName = introvirt::inject::allocate(ApplicationName);

    if (!CommandLine.empty())
        lpCommandLine = introvirt::inject::allocate(CommandLine);

    if (!CurrentDirectory.empty())
        lpCurrentDirectory = introvirt::inject::allocate(CurrentDirectory);

    introvirt::windows::inject::FunctionInjector<CreateProcessA> injector(event);

    CreateProcessA handler(
        event, (lpApplicationName ? lpApplicationName->address() : GuestVirtualAddress()),
        (lpCommandLine ? lpCommandLine->address() : GuestVirtualAddress()), lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        (lpCurrentDirectory ? lpCurrentDirectory->address() : GuestVirtualAddress()), lpStartupInfo,
        lpProcessInformation);

    injector.call(handler);
    return handler.result();
}

} // namespace kernel32
} // namespace windows
} // namespace introvirt