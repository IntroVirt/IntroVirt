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

#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/UNICODE_STRING.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct __attribute__((__aligned__(sizeof(PtrType)), __ms_struct__)) _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    PtrType Buffer;
};

static_assert(sizeof(_UNICODE_STRING<uint32_t>) == 0x8);
static_assert(sizeof(_UNICODE_STRING<uint64_t>) == 0x10);
static_assert(offsetof(_UNICODE_STRING<uint32_t>, Buffer) == 0x4);
static_assert(offsetof(_UNICODE_STRING<uint64_t>, Buffer) == 0x8);

} // namespace structs

template <typename PtrType>
class UNICODE_STRING_IMPL final : public UNICODE_STRING {
  public:
    uint16_t Length() const override;
    void Length(uint16_t Length) override;

    uint16_t MaximumLength() const override;
    void MaximumLength(uint16_t MaximumLength) override;

    GuestVirtualAddress BufferAddress() const override;
    void BufferAddress(const GuestVirtualAddress& gva) override;

    const uint8_t* Buffer() const override;

    void set(const std::u16string& value) override;
    using Utf16String::set;

    Json::Value json() const override;

    GuestVirtualAddress address() const override;

    UNICODE_STRING_IMPL(const GuestVirtualAddress& gva);

    ~UNICODE_STRING_IMPL() override;

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_UNICODE_STRING<PtrType>> header_;
    mutable guest_ptr<uint8_t[]> buffer_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt