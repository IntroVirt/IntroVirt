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

#include "LUID_IMPL.hh"

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/LUID_AND_ATTRIBUTES.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct __attribute__((packed)) _LUID_AND_ATTRIBUTES {
    struct _LUID Luid;
    uint32_t Attributes;
};

static_assert(offsetof(_LUID_AND_ATTRIBUTES, Attributes) == 0x8);
static_assert(sizeof(_LUID_AND_ATTRIBUTES) == 0xc);

}; // namespace structs

class LUID_AND_ATTRIBUTES_IMPL final : public LUID_AND_ATTRIBUTES {
  public:
    LUID& Luid() override { return luid_; }
    const LUID& Luid() const override { return luid_; }

    LUID_ATTRIBUTES Attributes() const override { return luid_and_attributes_->Attributes; }
    void Attributes(LUID_ATTRIBUTES attributes) override {
        luid_and_attributes_->Attributes = attributes;
    }

    GuestVirtualAddress address() const override { return gva_; }

    LUID_AND_ATTRIBUTES_IMPL(const GuestVirtualAddress& gva);

  private:
    const GuestVirtualAddress gva_;
    LUID_IMPL luid_;
    guest_ptr<structs::_LUID_AND_ATTRIBUTES> luid_and_attributes_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt