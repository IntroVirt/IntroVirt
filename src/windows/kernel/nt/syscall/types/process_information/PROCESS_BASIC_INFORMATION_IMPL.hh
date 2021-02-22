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

#include "PROCESS_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/process_information/PROCESS_BASIC_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _PROCESS_BASIC_INFORMATION {
    PtrType ExitStatus;
    PtrType PebBaseAddress;
    PtrType AffinityMask;
    PtrType BasePriority;
    PtrType Pid;
    PtrType ParentPid;
};

} // namespace structs

template <typename PtrType>
using PROCESS_BASIC_INFORMATION_IMPL_BASE =
    PROCESS_INFORMATION_IMPL<PROCESS_BASIC_INFORMATION,
                             structs::_PROCESS_BASIC_INFORMATION<PtrType>>;

template <typename PtrType>
class PROCESS_BASIC_INFORMATION_IMPL final : public PROCESS_BASIC_INFORMATION_IMPL_BASE<PtrType> {
  public:
    NTSTATUS ExitStatus() const override { return NTSTATUS(this->data_->ExitStatus); }
    void ExitStatus(NTSTATUS ExitStatus) override { this->data_->ExitStatus = ExitStatus.code(); }

    uint64_t PebBaseAddress() const override { return this->data_->PebBaseAddress; }
    void PebBaseAddress(uint64_t PebBaseAddress) override {
        this->data_->PebBaseAddress = PebBaseAddress;
    }

    uint64_t AffinityMask() const override { return this->data_->AffinityMask; }
    void AffinityMask(uint64_t AffinityMask) override { this->data_->AffinityMask = AffinityMask; }

    int32_t BasePriority() const override { return this->data_->BasePriority; }
    void BasePriority(int32_t BasePriority) override { this->data_->BasePriority = BasePriority; }

    uint64_t Pid() const override { return this->data_->Pid; }
    void Pid(uint64_t Pid) override { this->data_->Pid = Pid; }

    uint64_t ParentPid() const override { return this->data_->ParentPid; }
    void ParentPid(uint64_t ParentPid) override { this->data_->ParentPid = ParentPid; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    PROCESS_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : PROCESS_BASIC_INFORMATION_IMPL_BASE<PtrType>(
              PROCESS_INFORMATION_CLASS::ProcessBasicInformation, gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt