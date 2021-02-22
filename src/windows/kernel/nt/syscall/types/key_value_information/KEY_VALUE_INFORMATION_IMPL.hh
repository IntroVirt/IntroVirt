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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/key_value_information/KEY_VALUE_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _KEY_VALUE_INFORMATION {
    uint32_t TitleIndex;
    uint32_t Type;
};

} // namespace structs

/**
 * @brief Generic class for types we don't support
 */
template <typename _BaseClass = KEY_VALUE_INFORMATION,
          typename _StructType = structs::_KEY_VALUE_INFORMATION>
class KEY_VALUE_INFORMATION_IMPL : public _BaseClass {
  public:
    uint32_t TitleIndex() const final { return data_->TitleIndex; }

    void TitleIndex(uint32_t TitleIndex) final { data_->TitleIndex = TitleIndex; }

    REG_TYPE Type() const final { return static_cast<REG_TYPE>(data_->Type); }

    void Type(REG_TYPE Type) final { data_->Type = static_cast<decltype(data_->Type)>(Type); }

    const std::string& Name() const override {
        static std::string empty;
        return empty;
    }

    KEY_VALUE* Data() override { return nullptr; }
    const KEY_VALUE* Data() const override { return nullptr; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass() const final { return class_; }

    GuestVirtualAddress address() const final { return gva_; }
    uint32_t buffer_size() const final { return buffer_size_; }

    KEY_VALUE_INFORMATION_IMPL(KEY_VALUE_INFORMATION_CLASS information_class,
                               const GuestVirtualAddress& gva, uint32_t buffer_size);

  protected:
    const KEY_VALUE_INFORMATION_CLASS class_;
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
    guest_ptr<_StructType> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt