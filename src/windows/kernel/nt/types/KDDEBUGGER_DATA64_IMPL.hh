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

#include "windows/kernel/nt/structs/base.hh"

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/KDDEBUGGER_DATA64.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class KDDEBUGGER_DATA64_IMPL final : public KDDEBUGGER_DATA64 {
  public:
    uint64_t KernelBase() const override;

    uint32_t ServicePackNumber() const override;

    uint64_t PsLoadedModuleList() const override;

    uint64_t PsActiveProcessHead() const override;

    const std::string& NtBuildLab() const override;

    uint64_t KiProcessorBlock() const override;

    uint64_t ObpTypeObjectType() const override;

    uint64_t ObpRootDirectoryObject() const override;

    uint16_t SizeEThread() const override;

    uint64_t PspCidTable() const override;

    bool PaeEnabled() const override;

    KDDEBUGGER_DATA64_IMPL(const NtKernel& kernel);

  private:
    GuestVirtualAddress kiProcessorBlock_;
    uint32_t CmNtCSDVersion_ = 0;

    std::string NtBuildLab_;
    structs::_KDDEBUGGER_DATA64 debuggerData_{};

    guest_ptr<PtrType> pObpTypeObjectType_;
    guest_ptr<PtrType> pObpRootDirectoryObject_;
    guest_ptr<PtrType> pPspCidTable_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt