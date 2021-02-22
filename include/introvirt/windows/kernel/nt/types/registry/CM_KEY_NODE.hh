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
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <string>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

class CM_KEY_NODE {
  public:
    enum Flags {
        HiveExit = 0x2,
        HiveEntry = 0x4,
        NoDelete = 0x8,
        SymbolicLink = 0x10,
        CompressedName = 0x20, // Indicates the name is ASCII rather than UNICODE
        PredefinedHandle = 0x40,
        VirtMirrored = 0x80,
        VirtTarget = 0x100,
        VirtualStore = 0x200,
    };

    virtual const std::string& Name() const = 0;
    virtual uint16_t Flags() const = 0;
    virtual const std::vector<std::unique_ptr<CM_KEY_NODE>>& StableSubKeys() const = 0;
    virtual const std::vector<std::unique_ptr<CM_KEY_NODE>>& VolatileSubKeys() const = 0;
    virtual const std::vector<std::unique_ptr<CM_KEY_VALUE>>& Values() const = 0;
    virtual GuestVirtualAddress address() const = 0;

    virtual ~CM_KEY_NODE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
