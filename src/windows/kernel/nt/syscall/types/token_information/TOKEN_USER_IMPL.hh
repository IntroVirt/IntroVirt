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

#include "windows/kernel/nt/types/SID_AND_ATTRIBUTES_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/token_information/TOKEN_USER.hh>

#include <mutex>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _TOKEN_USER {
    _SID_AND_ATTRIBUTES<PtrType> User;
};

} // namespace structs

template <typename PtrType>
class TOKEN_USER_IMPL final
    : public TOKEN_INFORMATION_IMPL<TOKEN_USER, structs::_TOKEN_USER<PtrType>> {
  public:
    SID_AND_ATTRIBUTES& User() override;
    const SID_AND_ATTRIBUTES& User() const override;

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    TOKEN_USER_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    using TOKEN_USER_IMPL_BASE = TOKEN_INFORMATION_IMPL<TOKEN_USER, structs::_TOKEN_USER<PtrType>>;

    mutable std::mutex UserInit_;
    mutable std::optional<SID_AND_ATTRIBUTES_IMPL<PtrType>> User_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt