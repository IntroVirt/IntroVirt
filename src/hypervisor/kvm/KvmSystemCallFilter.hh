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

#include <introvirt/core/syscall/SystemCallFilter.hh>

namespace introvirt {
namespace kvm {

/**
 * @brief SystemCallFilter that pins its bitmap page into KVM
 *
 * The hypervisor checks the shared page before delivering syscall events, so
 * ignored calls do not require a userspace context switch.
 */
class KvmSystemCallFilter final : public SystemCallFilter {
  public:
    /**
     * @param fd VM fd (domain filter) or VCPU fd (per-vcpu filter)
     */
    explicit KvmSystemCallFilter(int fd);
    ~KvmSystemCallFilter() override;

    KvmSystemCallFilter(const KvmSystemCallFilter&) = delete;
    KvmSystemCallFilter& operator=(const KvmSystemCallFilter&) = delete;

  private:
    int fd_;
};

} // namespace kvm
} // namespace introvirt
