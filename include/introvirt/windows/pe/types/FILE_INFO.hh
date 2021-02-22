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

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

/**
 * @brief A common base class for VS_VERSIONINFO types
 *
 */
class FILE_INFO {
  public:
    virtual uint16_t wLength() const = 0;
    virtual uint16_t wValueLength() const = 0;
    virtual uint16_t wType() const = 0;
    virtual const std::string& szKey() const = 0;
    virtual GuestVirtualAddress pChildren() const = 0;

    virtual ~FILE_INFO() = default;
};

} // namespace pe
} // namespace windows
} // namespace introvirt