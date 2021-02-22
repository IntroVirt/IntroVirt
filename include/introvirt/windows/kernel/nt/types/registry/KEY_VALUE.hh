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
#include <introvirt/windows/kernel/fwd.hh>
#include <introvirt/windows/kernel/nt/const/REG_TYPE.hh>

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class KEY_VALUE {
  public:
    virtual const char* Data() const = 0;
    virtual uint32_t DataSize() const = 0;
    virtual REG_TYPE Type() const = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;

    virtual Json::Value json() const = 0;

    virtual GuestVirtualAddress address() const = 0;

    static std::unique_ptr<KEY_VALUE>
    make_unique(REG_TYPE regType, const GuestVirtualAddress& pKeyValue, uint32_t dataSize);

    static const REG_TYPE RegType(uint32_t type);

    virtual ~KEY_VALUE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
