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

#include <introvirt/windows/kernel/nt/syscall/types/thread_information/THREAD_BASIC_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _THREAD_BASIC_INFORMATION {
    PtrType ExitStatus;
    PtrType TebBaseAddress;
    _CLIENT_ID<PtrType> ClientId;
    PtrType AffinityMask;
    int32_t Priority;
    int32_t BasePriority;
};

static_assert(sizeof(_THREAD_BASIC_INFORMATION<uint64_t>) == 48);

} // namespace structs

template <typename PtrType>
using THREAD_BASIC_INFORMATION_IMPL_BASE =
    THREAD_INFORMATION_IMPL<THREAD_BASIC_INFORMATION, structs::_THREAD_BASIC_INFORMATION<PtrType>>;

template <typename PtrType>
class THREAD_BASIC_INFORMATION_IMPL final : public THREAD_BASIC_INFORMATION_IMPL_BASE<PtrType> {
  public:
    NTSTATUS ExitStatus() const override { return NTSTATUS(this->data_->ExitStatus); }
    void ExitStatus(NTSTATUS ExitStatus) override { this->data_->ExitStatus = ExitStatus.code(); }

    uint64_t TebBaseAddress() const override { return this->data_->TebBaseAddress; }
    void TebBaseAddress(uint64_t TebBaseAddress) override {
        this->data_->TebBaseAddress = TebBaseAddress;
    }

    const CLIENT_ID& ClientId() const override { return ClientId_; }
    CLIENT_ID& ClientId() override { return ClientId_; }

    uint64_t AffinityMask() const override { return this->data_->AffinityMask; }
    void AffinityMask(uint64_t AffinityMask) override { this->data_->AffinityMask = AffinityMask; }

    int32_t Priority() const override { return this->data_->Priority; }
    void Priority(int32_t Priority) override { this->data_->Priority = Priority; }

    int32_t BasePriority() const override { return this->data_->BasePriority; }
    void BasePriority(int32_t BasePriority) override { this->data_->BasePriority = BasePriority; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    THREAD_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : THREAD_BASIC_INFORMATION_IMPL_BASE<PtrType>(
              THREAD_INFORMATION_CLASS::ThreadBasicInformation, gva, buffer_size),
          ClientId_(this->gva_ + offsetof(structs::_THREAD_BASIC_INFORMATION<PtrType>, ClientId)) {}

  private:
    CLIENT_ID_IMPL<PtrType> ClientId_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt