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

#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * Windows Security Identifier (SID)
 */
class SID {
  public:
    virtual uint8_t Revision() const = 0;    
    virtual guest_ptr<const uint8_t[]> IdentifierAuthority() const = 0;
    virtual guest_ptr<const uint32_t[]> SubAuthorities() const = 0;

    virtual Json::Value json() const = 0;

    virtual void Revision(uint8_t Revision) = 0;
    virtual guest_ptr<uint8_t[]> IdentifierAuthority() = 0;
    virtual guest_ptr<uint32_t[]> SubAuthorities() = 0;

    virtual uint8_t SubAuthorityCount() const = 0;
    virtual void SubAuthorityCount(uint8_t SubAuthorityCount) = 0;

    virtual ~SID() = default;
};

/**
 * @brief Get the string representation of SID
 */
std::string to_string(const SID& sid);

/**
 * @brief Stream overload operator for SID
 */
std::ostream& operator<<(std::ostream&, const SID& sid);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
