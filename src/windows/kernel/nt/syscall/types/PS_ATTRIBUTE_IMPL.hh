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
#include <introvirt/windows/kernel/nt/syscall/types/PS_ATTRIBUTE_LIST.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _PS_ATTRIBUTE {
    PtrType Attribute;
    PtrType Size;
    union {
        PtrType Value;
        PtrType ValuePtr;
    };
    PtrType ReturnLength;
};

} // namespace structs

template <typename PtrType>
class PS_ATTRIBUTE_IMPL final : public PS_ATTRIBUTE {
  private:
    // http://processhacker.sourceforge.net/doc/ntpsapi_8h_source.html
    static constexpr PtrType PS_ATTRIBUTE_NUMBER_MASK = 0x0000ffff;
    static constexpr PtrType PS_ATTRIBUTE_THREAD = 0x00010000; // can be used with threads
    static constexpr PtrType PS_ATTRIBUTE_INPUT = 0x00020000;  // input only
    static constexpr PtrType PS_ATTRIBUTE_UNKNOWN = 0x00040000;

  public:
    // The attribute number
    PS_ATTRIBUTE_NUM AttributeNumber() const override {
        return static_cast<PS_ATTRIBUTE_NUM>(data_->Attribute & PS_ATTRIBUTE_NUMBER_MASK);
    }
    void AttributeNumber(PS_ATTRIBUTE_NUM num) override {
        data_->Attribute &= ~PS_ATTRIBUTE_NUMBER_MASK;
        data_->Attribute |= num;
    }

    uint32_t AttributeFlags() const override {
        return data_->Attribute & ~PS_ATTRIBUTE_NUMBER_MASK;
    }
    void AttributeFlags(uint32_t flags) override {
        data_->Attribute &= PS_ATTRIBUTE_NUMBER_MASK;
        data_->Attribute |= flags;
    }

    uint64_t Size() const override { return data_->Size; }
    void Size(uint64_t size) override { data_->Size = size; }

    uint64_t Value() const override { return data_->Value; }
    void Value(uint64_t value) override { data_->Value = value; }

    uint64_t ReturnLength() const override { return data_->ReturnLength; }
    void ReturnLength(uint64_t len) override { data_->ReturnLength = len; }

    bool AttributeInputOnly() const override { return data_->Attribute & PS_ATTRIBUTE_INPUT; }
    void AttributeInputOnly(bool input) override {
        if (input)
            data_->Attribute |= PS_ATTRIBUTE_INPUT;
        else
            data_->Attribute &= ~PS_ATTRIBUTE_INPUT;
    }

    bool AttributeThreads() const override { return data_->Attribute & PS_ATTRIBUTE_THREAD; }
    void AttributeThreads(bool threads) override {
        if (threads)
            data_->Attribute |= PS_ATTRIBUTE_THREAD;
        else
            data_->Attribute &= ~PS_ATTRIBUTE_THREAD;
    }

    GuestVirtualAddress address() const override { return gva_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    PS_ATTRIBUTE_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_PS_ATTRIBUTE<PtrType>> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt