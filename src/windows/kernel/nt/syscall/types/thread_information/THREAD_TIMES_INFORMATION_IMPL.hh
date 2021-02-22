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

#include <introvirt/windows/kernel/nt/syscall/types/thread_information/THREAD_TIMES_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _THREAD_TIMES_INFORMATION {
    uint64_t CreationTime;
    uint64_t ExitTime;
    uint64_t KernelTime;
    uint64_t UserTime;
};

} // namespace structs

template <typename PtrType>
using THREAD_TIMES_INFORMATION_IMPL_BASE =
    THREAD_INFORMATION_IMPL<THREAD_TIMES_INFORMATION, structs::_THREAD_TIMES_INFORMATION<PtrType>>;

template <typename PtrType>
class THREAD_TIMES_INFORMATION_IMPL final : public THREAD_TIMES_INFORMATION_IMPL_BASE<PtrType> {
  public:
    uint64_t CreationTime() const override { return this->data_->CreationTime; }
    void CreationTime(uint64_t CreationTime) override { this->data_->CreationTime = CreationTime; }

    uint64_t ExitTime() const override { return this->data_->ExitTime; }
    void ExitTime(uint64_t ExitTime) override { this->data_->ExitTime = ExitTime; }

    uint64_t KernelTime() const override { return this->data_->KernelTime; }
    void KernelTime(uint64_t KernelTime) override { this->data_->KernelTime = KernelTime; }

    uint64_t UserTime() const override { return this->data_->UserTime; }
    void UserTime(uint64_t UserTime) override { this->data_->UserTime = UserTime; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    THREAD_TIMES_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : THREAD_TIMES_INFORMATION_IMPL_BASE<PtrType>(THREAD_INFORMATION_CLASS::ThreadTimes, gva,
                                                      buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt