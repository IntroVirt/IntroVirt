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
    guest_member_ptr<_SID, PtrType> Sid;
    uint32_t Attributes;
};

static_assert(sizeof(_SID_AND_ATTRIBUTES<uint32_t>) == 0x8);
static_assert(sizeof(_SID_AND_ATTRIBUTES<uint64_t>) == 0x10);

} // namespace structs

template <typename PtrType>
class SID_AND_ATTRIBUTES_IMPL final : public SID_AND_ATTRIBUTES {
  public:
    guest_ptr<void> SidPtr() const override { return ptr_->Sid.get(ptr_); }
    void SidPtr(const guest_ptr<void>& ptr) override {
        ptr_->Sid.set(ptr);
        if (ptr)
            sid.emplace(ptr);
    }

    SidAttributeFlags Attributes() const override { return SidAttributeFlags(ptr_->Attributes); }
    void Attributes(SidAttributeFlags Attributes) override { ptr_->Attributes = Attributes; }

    const SID* Sid() const override {
        if (sid)
            return &(*sid);
        return nullptr; // TODO: Can this actually happen?
    }

    SID* Sid() override {
        if (sid)
            return &(*sid);
        return nullptr; // TODO: Can this actually happen?
    }

    Json::Value json() const override {
        Json::Value result;
        result["SID"] = Sid()->json();
        result["Attributes"] = Attributes().value();
        return result;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    SID_AND_ATTRIBUTES_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {
        const auto pSid = SidPtr();
        if (pSid)
            sid.emplace(pSid);
    }

  private:
    guest_ptr<structs::_SID_AND_ATTRIBUTES<PtrType>> ptr_;
    mutable std::optional<SID_IMPL> sid;
};

} // namespace nt
} // namespace windows
} // namespace introvirt