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

#include <introvirt/windows/kernel/nt/syscall/types/process_information/PROCESS_COOKIE_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _PROCESS_COOKIE_INFORMATION {
    uint32_t Cookie;
};

} // namespace structs

using PROCESS_COOKIE_INFORMATION_IMPL_BASE =
    PROCESS_INFORMATION_IMPL<PROCESS_COOKIE_INFORMATION, structs::_PROCESS_COOKIE_INFORMATION>;

class PROCESS_COOKIE_INFORMATION_IMPL final : public PROCESS_COOKIE_INFORMATION_IMPL_BASE {
  public:
    uint32_t Cookie() const override { return this->data_->Cookie; }
    void Cookie(uint32_t Cookie) override { this->data_->Cookie = Cookie; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    PROCESS_COOKIE_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : PROCESS_COOKIE_INFORMATION_IMPL_BASE(PROCESS_INFORMATION_CLASS::ProcessCookie, gva,
                                               buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt