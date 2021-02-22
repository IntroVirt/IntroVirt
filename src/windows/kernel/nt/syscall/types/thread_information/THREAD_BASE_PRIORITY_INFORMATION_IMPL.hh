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

#include <introvirt/windows/kernel/nt/syscall/types/thread_information/THREAD_BASE_PRIORITY_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _THREAD_BASE_PRIORITY_INFORMATION {
    int32_t BasePriority;
};

static_assert(sizeof(_THREAD_BASE_PRIORITY_INFORMATION) == 4);

} // namespace structs

using THREAD_BASE_PRIORITY_INFORMATION_IMPL_BASE =
    THREAD_INFORMATION_IMPL<THREAD_BASE_PRIORITY_INFORMATION,
                            structs::_THREAD_BASE_PRIORITY_INFORMATION>;

class THREAD_BASE_PRIORITY_INFORMATION_IMPL final
    : public THREAD_BASE_PRIORITY_INFORMATION_IMPL_BASE {
  public:
    int32_t BasePriority() const override { return this->data_->BasePriority; }
    void BasePriority(int32_t BasePriority) override { this->data_->BasePriority = BasePriority; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    THREAD_BASE_PRIORITY_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : THREAD_BASE_PRIORITY_INFORMATION_IMPL_BASE(THREAD_INFORMATION_CLASS::ThreadBasePriority,
                                                     gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt