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
#include <introvirt/util/json/json.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/access_mask/FILE_ACCESS_MASK.hh>

#include <cstdint>
#include <ostream>

namespace introvirt {
namespace windows {
namespace nt {

enum PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates, /* Not a real value */

    PsCreateUnknown = 0x1000
};

class PS_CREATE_INFO {
  public:
    virtual PS_CREATE_STATE State() const = 0;
    virtual uint64_t Size() const = 0;

    /** Only valid for state == PsCreateSuccess || PsCreateFailOnSectionCreate */
    virtual uint64_t FileHandle() const = 0;

    /** Only valid for state == PsCreateSuccess */
    virtual uint64_t SectionHandle() const = 0;
    virtual uint64_t UserProcessParametersNative() const = 0;
    virtual uint32_t UserProcessParametersWow64() const = 0;
    virtual uint32_t CurrentParameterFlags() const = 0;
    virtual uint64_t PebAddressNative() const = 0;
    virtual uint32_t PebAddressWow64() const = 0;
    virtual uint64_t ManifestAddress() const = 0;
    virtual uint32_t ManifestSize() const = 0;
    virtual uint32_t OutputFlags() const = 0;

    /** Only valid for state == PsCreateFailExeName */
    virtual uint64_t IFEOKey() const = 0;

    /* Only valid for state == PsCreateInitialState */
    virtual uint32_t InitFlags() const = 0;
    virtual void InitFlags(uint32_t InitFlags) = 0;

    virtual FILE_ACCESS_MASK AdditionalFileAccess() const = 0;
    virtual void AdditionalFileAccess(FILE_ACCESS_MASK AdditionalFileAccess) = 0;

    virtual GuestVirtualAddress address() const = 0;
    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    static std::unique_ptr<PS_CREATE_INFO> make_unique(const NtKernel& kernel,
                                                       const GuestVirtualAddress& gva);

    virtual ~PS_CREATE_INFO() = default;
};

const std::string& to_string(PS_CREATE_STATE state);
std::ostream& operator<<(std::ostream&, PS_CREATE_STATE);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
