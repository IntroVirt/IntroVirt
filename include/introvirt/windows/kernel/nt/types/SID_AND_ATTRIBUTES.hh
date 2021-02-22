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
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Flags for the SID_AND_ATTRIBUTES Attributes member.
 *
 * See <a
 * ref="https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups_and_privileges">here</a>
 *
 */
enum SID_AND_ATTRIBUTES_FLAGS {
    SE_GROUP_MANDATORY = 0x1,
    SE_GROUP_ENABLED_BY_DEFAULT = 0x2,
    SE_GROUP_ENABLED = 0x4,
    SE_GROUP_OWNER = 0x8,
    SE_GROUP_USE_FOR_DENY_ONLY = 0x10,
    SE_GROUP_INTEGRITY = 0x20,
    SE_GROUP_INTEGRITY_ENABLED = 0x40,
    SE_GROUP_RESOURCE = 0x20000000L,
    SE_GROUP_LOGON_ID = 0xC0000000L,
};

/**
 * Windows structure that holds an SID with attributes,
 */
class SID_AND_ATTRIBUTES {
  public:
    class SidAttributeFlags final {
      public:
        bool SE_GROUP_MANDATORY() const;
        bool SE_GROUP_ENABLED_BY_DEFAULT() const;
        bool SE_GROUP_ENABLED() const;
        bool SE_GROUP_OWNER() const;
        bool SE_GROUP_USE_FOR_DENY_ONLY() const;
        bool SE_GROUP_INTEGRITY() const;
        bool SE_GROUP_INTEGRITY_ENABLED() const;
        bool SE_GROUP_RESOURCE() const;
        bool SE_GROUP_LOGON_ID() const;

        std::string string() const;
        uint32_t value() const { return value_; }
        operator uint32_t() const { return value_; }

        explicit SidAttributeFlags(uint32_t value) : value_(value) {}

      private:
        uint32_t value_;
    };

    virtual GuestVirtualAddress SidPtr() const = 0;
    virtual void SidPtr(const GuestVirtualAddress& gva) = 0;

    virtual SidAttributeFlags Attributes() const = 0;
    virtual void Attributes(SidAttributeFlags Attributes) = 0;

    virtual const SID* Sid() const = 0;

    virtual Json::Value json() const = 0;

    virtual GuestVirtualAddress address() const = 0;

    static std::shared_ptr<SID_AND_ATTRIBUTES> make_shared(const NtKernel& kernel,
                                                           const GuestVirtualAddress& gva);

    virtual ~SID_AND_ATTRIBUTES() = default;
};

std::string to_string(SID_AND_ATTRIBUTES::SidAttributeFlags);

/**
 * @brief Stream operator for SidAttributeFlags
 */
std::ostream& operator<<(std::ostream&, SID_AND_ATTRIBUTES::SidAttributeFlags);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
