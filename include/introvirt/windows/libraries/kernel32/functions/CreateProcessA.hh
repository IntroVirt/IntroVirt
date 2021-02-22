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
#pragma once

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/libraries/WindowsFunctionCall.hh>
#include <introvirt/windows/libraries/kernel32/types/types.hh>

#include <cstdint>
#include <string>
#include <string_view>

namespace introvirt {
namespace windows {
namespace kernel32 {

class CreateProcessA : public WindowsFunctionCall {
  public:
    GuestVirtualAddress lpApplicationName() const;
    void lpApplicationName(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpCommandLine() const;
    void lpCommandLine(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpProcessAttributes() const;
    void lpProcessAttributes(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpThreadAttributes() const;
    void lpThreadAttributes(const GuestVirtualAddress& gva);

    bool bInheritHandles() const;
    void bInheritHandles(bool InheritHandles);

    uint32_t dwCreationFlags() const;
    void dwCreationFlags(uint32_t CreationFlags);

    GuestVirtualAddress lpEnvironment() const;
    void lpEnvironment(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpCurrentDirectory() const;
    void lpCurrentDirectory(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpStartupInfo() const;
    void lpStartupInfo(const GuestVirtualAddress& gva);

    GuestVirtualAddress lpProcessInformation() const;
    void lpProcessInformation(const GuestVirtualAddress& gva);

    std::string ApplicationName() const;
    std::string CommandLine() const;
    std::string CurrentDirectory() const;

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CreateProcessA(Event& event);
    ~CreateProcessA() override = default;

    static constexpr int ArgumentCount = 10;
    inline static const std::string LibraryName = "kernel32";
    inline static const std::string FunctionName = "CreateProcessA";

    static bool inject(std::string_view ApplicationName, std::string_view CommandLine,
                       const GuestVirtualAddress& lpProcessAttributes,
                       const GuestVirtualAddress& lpThreadAttributes, bool bInheritHandles,
                       uint32_t dwCreationFlags, const GuestVirtualAddress& lpEnvironment,
                       std::string_view CurrentDirectory, const GuestVirtualAddress& lpStartupInfo,
                       const GuestVirtualAddress& lpProcessInformation);

  private:
    CreateProcessA(Event& event, const GuestVirtualAddress& lpApplicationName,
                   const GuestVirtualAddress& lpCommandLine,
                   const GuestVirtualAddress& lpProcessAttributes,
                   const GuestVirtualAddress& lpThreadAttributes, bool bInheritHandles,
                   uint32_t dwCreationFlags, const GuestVirtualAddress& lpEnvironment,
                   const GuestVirtualAddress& lpCurrentDirectory,
                   const GuestVirtualAddress& lpStartupInfo,
                   const GuestVirtualAddress& lpProcessInformation);

  private:
    GuestVirtualAddress lpApplicationName_;
    GuestVirtualAddress lpCommandLine_;
    GuestVirtualAddress lpProcessAttributes_;
    GuestVirtualAddress lpThreadAttributes_;
    bool bInheritHandles_;
    uint32_t dwCreationFlags_;
    GuestVirtualAddress lpEnvironment_;
    GuestVirtualAddress lpCurrentDirectory_;
    GuestVirtualAddress lpStartupInfo_;
    GuestVirtualAddress lpProcessInformation_;
};

} // namespace kernel32
} // namespace windows
} // namespace introvirt