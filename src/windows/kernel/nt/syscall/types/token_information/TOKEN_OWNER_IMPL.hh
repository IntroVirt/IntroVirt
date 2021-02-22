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

#include "TOKEN_INFORMATION_IMPL.hh"

#include "windows/kernel/nt/types/SID_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/token_information/TOKEN_OWNER.hh>

#include <mutex>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _TOKEN_OWNER {
    PtrType Owner;
};

} // namespace structs

template <typename PtrType>
class TOKEN_OWNER_IMPL final
    : public TOKEN_INFORMATION_IMPL<TOKEN_OWNER, structs::_TOKEN_OWNER<PtrType>> {
  public:
    GuestVirtualAddress OwnerPtr() const override;
    void OwnerPtr(const GuestVirtualAddress& gva) override;

    SID* Owner() override;
    const SID* Owner() const override;

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    TOKEN_OWNER_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    using TOKEN_OWNER_IMPL_BASE =
        TOKEN_INFORMATION_IMPL<TOKEN_OWNER, structs::_TOKEN_OWNER<PtrType>>;

    mutable std::mutex owner_initialized_;
    mutable std::optional<SID_IMPL> Owner_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt