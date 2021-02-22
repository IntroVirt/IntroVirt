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

#include "LUID.hh"

#include <introvirt/core/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

enum LUID_ATTRIBUTE_FLAGS {
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001L,
    SE_PRIVILEGE_ENABLED = 0x00000002L,
    SE_PRIVILEGE_REMOVED = 0X00000004L,
    SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000L
};

class LUID_ATTRIBUTES;

class LUID_AND_ATTRIBUTES {
  public:
    virtual LUID& Luid() = 0;
    virtual const LUID& Luid() const = 0;

    virtual LUID_ATTRIBUTES Attributes() const = 0;
    virtual void Attributes(LUID_ATTRIBUTES attributes) = 0;

    virtual GuestVirtualAddress address() const = 0;

    static std::unique_ptr<LUID_AND_ATTRIBUTES> make_unique(const GuestVirtualAddress& gva);
    static std::shared_ptr<LUID_AND_ATTRIBUTES> make_shared(const GuestVirtualAddress& gva);

    virtual ~LUID_AND_ATTRIBUTES() = default;
};

class LUID_ATTRIBUTES {
  public:
    uint32_t value() const { return value_; }
    operator uint32_t() const { return value_; }

    LUID_ATTRIBUTES(uint32_t value) : value_(value) {}

  private:
    uint32_t value_;
};

const std::string& to_string(LUID_ATTRIBUTE_FLAGS);
std::ostream& operator<<(std::ostream&, LUID_ATTRIBUTE_FLAGS);

std::string to_string(LUID_ATTRIBUTES);
std::ostream& operator<<(std::ostream&, LUID_ATTRIBUTES);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
