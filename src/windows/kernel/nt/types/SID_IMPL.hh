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
  public:
    uint8_t Revision() const override;
    const std::vector<uint8_t>& IdentifierAuthority() const override;
    const std::vector<uint32_t>& SubAuthorities() const override;

    Json::Value json() const override;

    SID_IMPL(const GuestVirtualAddress& gva);

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_SID> buffer_;
    mutable std::vector<uint8_t> IdentifierAuthority_;
    mutable std::vector<uint32_t> SubAuthorities_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt