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

#include "SID_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/SID_AND_ATTRIBUTES.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _SID_AND_ATTRIBUTES {
    PtrType Sid;
    uint32_t Attributes;
};

static_assert(sizeof(_SID_AND_ATTRIBUTES<uint32_t>) == 0x8);
static_assert(sizeof(_SID_AND_ATTRIBUTES<uint64_t>) == 0x10);

} // namespace structs

template <typename PtrType>
class SID_AND_ATTRIBUTES_IMPL final : public SID_AND_ATTRIBUTES {
  public:
    GuestVirtualAddress SidPtr() const override;
    void SidPtr(const GuestVirtualAddress& gva) override;

    SidAttributeFlags Attributes() const override;
    void Attributes(SidAttributeFlags Attributes) override;

    const SID* Sid() const override;
    Json::Value json() const override;

    GuestVirtualAddress address() const override { return gva_; }

    SID_AND_ATTRIBUTES_IMPL(const GuestVirtualAddress& gva);

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_SID_AND_ATTRIBUTES<PtrType>> data_;

    mutable std::optional<SID_IMPL> sid;
};

} // namespace nt
} // namespace windows
} // namespace introvirt