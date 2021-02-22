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

#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/RTL_USER_PROCESS_PARAMETERS.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct __attribute__((__aligned__(sizeof(PtrType)), __ms_struct__)) _RTL_USER_PROCESS_PARAMETERS {
    uint32_t MaximumLength;
    uint32_t Length;
    uint32_t Flags;
    uint32_t DebugFlags;
    PtrType ConsoleHandle;
    uint32_t ConsoleFlags;
    PtrType StdInputHandle;
    PtrType StdOutputHandle;
    PtrType StdErrorHandle;
    _UNICODE_STRING<PtrType> CurrentDirectoryPath;
    PtrType CurrentDirectoryHandle;
    _UNICODE_STRING<PtrType> DllPath;
    _UNICODE_STRING<PtrType> ImagePathName;
    _UNICODE_STRING<PtrType> CommandLine;
    PtrType Environment;
    uint32_t StartingPositionLeft;
    uint32_t StartingPositionTop;
    uint32_t Width;
    uint32_t Height;
    uint32_t CharWidth;
    uint32_t CharHeight;
    uint32_t ConsoleTextAttributes;
    uint32_t WindowFlags;
    uint32_t ShowWindowFlags;
    _UNICODE_STRING<PtrType> WindowTitle;
};

static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint32_t>, CommandLine) == 0x40);
static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint64_t>, CommandLine) == 0x70);

static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint32_t>, Environment) == 0x48);
static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint64_t>, Environment) == 0x80);

static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint32_t>, WindowTitle) == 0x70);
static_assert(offsetof(_RTL_USER_PROCESS_PARAMETERS<uint64_t>, WindowTitle) == 0xb0);

} // namespace structs

template <typename PtrType>
class RTL_USER_PROCESS_PARAMETERS_IMPL final : public RTL_USER_PROCESS_PARAMETERS {
  public:
    const std::string& CommandLine() const override;
    const std::string& ImagePathName() const override;
    const std::string& WindowTitle() const override;
    const std::map<std::string, std::string>& Environment() const override;

    GuestVirtualAddress address() const override;
    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    RTL_USER_PROCESS_PARAMETERS_IMPL(const GuestVirtualAddress& gva);

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_RTL_USER_PROCESS_PARAMETERS<PtrType>> data_;

    mutable std::map<std::string, std::string> environment;
    mutable std::string commandLine;
    mutable std::string imagePathName;
    mutable std::string windowTitle;
};

} // namespace nt
} // namespace windows
} // namespace introvirt