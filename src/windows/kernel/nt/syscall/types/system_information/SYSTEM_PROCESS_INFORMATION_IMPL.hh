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

#include "SYSTEM_INFORMATION_IMPL.hh"
#include "SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL.hh"

#include "windows/kernel/nt/syscall/types/offset_iterable.hh"

#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_PROCESS_INFORMATION.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
using SYSTEM_PROCESS_INFORMATION_IMPL_BASE =
    offset_iterable<SYSTEM_PROCESS_INFORMATION_ENTRY,
                    SYSTEM_INFORMATION_IMPL<SYSTEM_PROCESS_INFORMATION>>;

template <typename PtrType>
class SYSTEM_PROCESS_INFORMATION_IMPL final : public SYSTEM_PROCESS_INFORMATION_IMPL_BASE<PtrType> {
  public:
    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SYSTEM_PROCESS_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : SYSTEM_PROCESS_INFORMATION_IMPL_BASE<PtrType>(
              [](const GuestVirtualAddress& gva, uint32_t buffer_size) {
                  return std::make_shared<SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL<PtrType>>(
                      gva, buffer_size);
              },
              gva, buffer_size, SYSTEM_INFORMATION_CLASS::SystemProcessInformation, gva,
              buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt