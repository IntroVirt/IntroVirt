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

#include "SECTION_INFORMATION.hh"

namespace introvirt {
namespace windows {
namespace nt {

class SECTION_BASIC_INFORMATION : public SECTION_INFORMATION {
  public:
    virtual uint64_t BaseAddress() const = 0;
    virtual void BaseAddress(uint64_t value) = 0;

    virtual uint32_t AllocationAttributes() const = 0;
    virtual void AllocationAttributes(uint32_t value) = 0;

    virtual uint64_t MaximumSize() const = 0;
    virtual void MaximumSize(uint64_t value) = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
