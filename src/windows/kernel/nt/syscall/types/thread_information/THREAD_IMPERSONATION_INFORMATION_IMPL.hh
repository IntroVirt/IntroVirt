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

#include "THREAD_INFORMATION_IMPL.hh"
#include "windows/kernel/nt/types/CLIENT_ID_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/thread_information/THREAD_IMPERSONATION_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _THREAD_IMPERSONATION_INFORMATION {
    PtrType ThreadImpersonationToken;
};

} // namespace structs

template <typename PtrType>
using THREAD_IMPERSONATION_INFORMATION_IMPL_BASE =
    THREAD_INFORMATION_IMPL<THREAD_IMPERSONATION_INFORMATION,
                            structs::_THREAD_IMPERSONATION_INFORMATION<PtrType>>;

template <typename PtrType>
class THREAD_IMPERSONATION_INFORMATION_IMPL final
    : public THREAD_IMPERSONATION_INFORMATION_IMPL_BASE<PtrType> {
  public:
    uint64_t ThreadImpersonationToken() const override {
        return this->data_->ThreadImpersonationToken;
    }
    void ThreadImpersonationToken(uint64_t ThreadImpersonationToken) override {
        this->data_->ThreadImpersonationToken = ThreadImpersonationToken;
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    THREAD_IMPERSONATION_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : THREAD_IMPERSONATION_INFORMATION_IMPL_BASE<PtrType>(
              THREAD_INFORMATION_CLASS::ThreadImpersonationToken, gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt