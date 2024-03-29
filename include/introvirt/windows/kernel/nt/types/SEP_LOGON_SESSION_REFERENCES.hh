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
#include <introvirt/windows/kernel/nt/types/LUID.hh>

#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class SEP_LOGON_SESSION_REFERENCES {
  public:
    virtual LUID& LogonId() = 0;
    virtual const LUID& LogonId() const = 0;

    virtual LUID& BuddyLogonId() = 0;
    virtual const LUID& BuddyLogonId() const = 0;

    virtual void ReferenceCount(int64_t ReferenceCount) = 0;
    virtual int64_t ReferenceCount() const = 0;

    virtual uint32_t Flags() const = 0;
    virtual void Flags(uint32_t Flags) = 0;

    virtual const std::string& AccountName() const = 0;

    virtual const std::string& AuthorityName() const = 0;

    virtual LUID& SiblingAuthId() = 0;
    virtual const LUID& SiblingAuthId() const = 0;

    virtual ~SEP_LOGON_SESSION_REFERENCES() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt