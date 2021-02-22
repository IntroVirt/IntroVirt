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

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Class for the Windows NT OBJECT_HEADER_CREATOR_INFO structure
 */
class OBJECT_HEADER_CREATOR_INFO {
  public:
    /**
     * @brief Get the PID of the process that created the object
     *
     * @return the CreatorUniqueProcess field from the structure
     */
    virtual uint64_t CreatorUniqueProcess() const = 0;

    virtual ~OBJECT_HEADER_CREATOR_INFO() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt