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

#include <introvirt/windows/kernel/nt/types/SID.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _SID_IDENTIFIER_AUTHORITY {
    uint8_t Value[6];
};

static_assert(sizeof(_SID_IDENTIFIER_AUTHORITY) == 0x6);

struct _SID {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    _SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    uint32_t SubAuthority[1];
};

static_assert(sizeof(_SID) == 0xc);

} // namespace structs

class SID_IMPL final : public SID {
    using _SID = structs::_SID;
    using _SID_IDENTIFIER_AUTHORITY = structs::_SID_IDENTIFIER_AUTHORITY;

  public:
    uint8_t Revision() const override { return ptr_->Revision; }
    guest_ptr<const uint8_t[]> IdentifierAuthority() const override {
        return pIdentifierAuthority_;
    }
    guest_ptr<const uint32_t[]> SubAuthorities() const override { return pSubAuthorities_; }

    void Revision(uint8_t Revision) override {
        ptr_->Revision = Revision;
    }

    guest_ptr<uint8_t[]> IdentifierAuthority()  override {
        return pIdentifierAuthority_;
    }
    guest_ptr<uint32_t[]> SubAuthorities()  override { return pSubAuthorities_; }

    Json::Value json() const override;

    SID_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {

        // Pull out the IdentifierAuthority array
        pIdentifierAuthority_.reset(ptr + offsetof(_SID, IdentifierAuthority),
                                    sizeof(_SID_IDENTIFIER_AUTHORITY::Value));

        // Pull out the SubAuthority array
        pSubAuthorities_.reset(ptr + offsetof(_SID, SubAuthority), ptr_->SubAuthorityCount);
    }

  private:
    guest_ptr<_SID> ptr_;
    guest_ptr<uint8_t[]> pIdentifierAuthority_;
    guest_ptr<uint32_t[]> pSubAuthorities_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt