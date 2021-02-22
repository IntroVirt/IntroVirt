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

#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _BaseClass = KEY_VALUE>
class KEY_VALUE_IMPL : public _BaseClass {
  public:
    const char* Data() const final { return Data_.get(); }
    uint32_t DataSize() const final { return DataSize_; }
    REG_TYPE Type() const final { return type_; }
    GuestVirtualAddress address() const final { return gva_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        os << linePrefix << "Type: " << Type() << '\n';
    }

    Json::Value json() const override {
        Json::Value result;
        result["Type"] = to_string(Type());
        return result;
    }

    KEY_VALUE_IMPL(REG_TYPE type, const GuestVirtualAddress& gva, uint32_t size)
        : type_(type), gva_(gva), Data_(gva_, size), DataSize_(size) {}

  protected:
    const REG_TYPE type_;
    const GuestVirtualAddress gva_;
    guest_ptr<char[]> Data_;
    const uint32_t DataSize_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt