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

#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class KPCR_IMPL final : public KPCR {
  public:
    uint64_t pid() const override;
    uint64_t tid() const override;
    std::string process_name() const override;
    THREAD& CurrentThread() override;
    const THREAD& CurrentThread() const override;
    bool idle() const override;
    void reset() override HOT;
    uint64_t current_thread_address() const;

    uint64_t KernelDirectoryTableBase() const override;

    KPCR_IMPL(NtKernelImpl<PtrType>& kernel, Vcpu& vcpu, uint64_t dtb = 0);
    ~KPCR_IMPL() override;

  private:
    NtKernelImpl<PtrType>& kernel_;
    Vcpu& vcpu_;
    const structs::KPCR* offsets_;
    guest_ptr<char[]> buffer_;

    const PtrType* pkernel_dtb_ = nullptr;
    const PtrType* pcurrent_thread_;
    const PtrType* pidle_thread_;

    mutable std::shared_ptr<THREAD> current_thread_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt