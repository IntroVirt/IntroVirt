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

#include "KEY_VALUE_STRING_IMPL.hh"

#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_EXPAND_STRING.hh>

namespace introvirt {
namespace windows {
namespace nt {

class KEY_VALUE_EXPAND_STRING_IMPL final : public KEY_VALUE_STRING_IMPL<KEY_VALUE_EXPAND_STRING> {
  public:
    std::string ExpandedStringValue() const override;

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    KEY_VALUE_EXPAND_STRING_IMPL(const GuestVirtualAddress& gva, uint32_t size);

  private:
    std::string ExpandedValue_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt