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

#include "TOKEN_INFORMATION_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/token_information/TOKEN_IS_APP_CONTAINER.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _TOKEN_IS_APP_CONTAINER {
    uint32_t TokenIsAppContainer;
};

} // namespace structs

using TOKEN_IS_APP_CONTAINER_IMPL_BASE =
    TOKEN_INFORMATION_IMPL<TOKEN_IS_APP_CONTAINER, structs::_TOKEN_IS_APP_CONTAINER>;

class TOKEN_IS_APP_CONTAINER_IMPL final : public TOKEN_IS_APP_CONTAINER_IMPL_BASE {
  public:
    uint32_t TokenIsAppContainer() const override { return data_->TokenIsAppContainer; }
    void TokenIsAppContainer(uint32_t value) override { data_->TokenIsAppContainer = value; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    TOKEN_IS_APP_CONTAINER_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);
};

} // namespace nt
} // namespace windows
} // namespace introvirt