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

#include <introvirt/fwd.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _BaseClass = KEY_VALUE>
class KEY_VALUE_IMPL : public _BaseClass {
  public:
    guest_ptr<const uint8_t[]> Data() const final { return buf_; }
    guest_ptr<uint8_t[]> Data() final { return buf_; }

    REG_TYPE Type() const final { return type_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        os << linePrefix << "Type: " << Type() << '\n';
    }

    Json::Value json() const override {
        Json::Value result;
        result["Type"] = to_string(Type());
        return result;
    }

    KEY_VALUE_IMPL(REG_TYPE type, const guest_ptr<void>& ptr, uint32_t size)
        : type_(type), buf_(ptr, size) {}

  protected:
    const REG_TYPE type_;
    guest_ptr<uint8_t[]> buf_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt