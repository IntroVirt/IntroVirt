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

#include "PROCESS_INFORMATION.hh"
#include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>

namespace introvirt {
namespace windows {
namespace nt {

class PROCESS_BASIC_INFORMATION : public PROCESS_INFORMATION {
  public:
    virtual NTSTATUS ExitStatus() const = 0;
    virtual void ExitStatus(NTSTATUS ExitStatus) = 0;

    virtual uint64_t PebBaseAddress() const = 0;
    virtual void PebBaseAddress(uint64_t PebBaseAddress) = 0;

    virtual uint64_t AffinityMask() const = 0;
    virtual void AffinityMask(uint64_t AffinityMask) = 0;

    virtual int32_t BasePriority() const = 0;
    virtual void BasePriority(int32_t BasePriority) = 0;

    virtual uint64_t Pid() const = 0;
    virtual void Pid(uint64_t Pid) = 0;

    virtual uint64_t ParentPid() const = 0;
    virtual void ParentPid(uint64_t ParentPid) = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
