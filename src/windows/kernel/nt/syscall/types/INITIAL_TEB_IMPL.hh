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
#include <introvirt/windows/kernel/nt/syscall/types/INITIAL_TEB.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {
template <typename PtrType>
struct _INITIAL_TEB {
    PtrType StackBase;
    PtrType StackLimit;
    PtrType StackCommit;
    PtrType StackCommitMax;
    PtrType StackReserved;
};
} // namespace structs

template <typename PtrType>
class INITIAL_TEB_IMPL final : public INITIAL_TEB {
  public:
    uint64_t StackBase() const override { return ptr_->StackBase; }
    void StackBase(uint64_t StackBase) override { ptr_->StackBase = StackBase; }

    uint64_t StackLimit() const override { return ptr_->StackLimit; }
    void StackLimit(uint64_t StackLimit) override { ptr_->StackLimit = StackLimit; }

    uint64_t StackCommit() const override { return ptr_->StackCommit; }
    void StackCommit(uint64_t StackCommit) override { ptr_->StackCommit = StackCommit; }

    uint64_t StackCommitMax() const override { return ptr_->StackCommitMax; }
    void StackCommitMax(uint64_t StackCommitMax) override { ptr_->StackCommitMax = StackCommitMax; }

    uint64_t StackReserved() const override { return ptr_->StackReserved; }
    void StackReserved(uint64_t StackReserved) override { ptr_->StackReserved = StackReserved; }

    guest_ptr<void> ptr() const override { return ptr_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    INITIAL_TEB_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_INITIAL_TEB<PtrType>> ptr_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
