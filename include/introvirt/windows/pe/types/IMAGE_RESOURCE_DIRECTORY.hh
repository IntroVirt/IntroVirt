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

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/pe/fwd.hh>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_RESOURCE_DIRECTORY {
  public:
    virtual uint32_t Characteristics() const = 0;
    virtual uint32_t TimeDateStamp() const = 0;
    virtual uint16_t MajorVersion() const = 0;
    virtual uint16_t MinorVersion() const = 0;
    virtual uint16_t NumberOfNamedEntries() const = 0;
    virtual uint16_t NumberOfIdEntries() const = 0;

    virtual const std::vector<std::unique_ptr<const IMAGE_RESOURCE_DIRECTORY_ENTRY>>&
    entries() const = 0;

    virtual const IMAGE_RESOURCE_DIRECTORY_ENTRY* entry(uint16_t Id) const = 0;

    virtual ~IMAGE_RESOURCE_DIRECTORY() = default;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
