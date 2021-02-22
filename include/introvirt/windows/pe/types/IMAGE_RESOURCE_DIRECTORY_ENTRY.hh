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

#include <introvirt/windows/pe/fwd.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_RESOURCE_DIRECTORY_ENTRY {
  public:
    /**
     * @brief Indicates if the value is a string or an ID
     *
     * @return true
     * @return false
     */
    virtual bool NameIsString() const = 0;

    /**
     * @brief Get the Name if applicable
     *
     * @return std::string
     * @throw InvalidMethodException if NameIsString is not set
     */
    virtual const std::string& Name() const = 0;

    /**
     * @brief Get the ID if applicable
     *
     * @return uint16_t
     * @throw InvalidMethodException if NameIsString is set
     */
    virtual uint16_t Id() const = 0;

    /**
     * @brief Indicates if the data held is a directory
     *
     * @return true if the entry contains an IMAGE_RESOURCE_DIRECTORY
     * @return false if the entry contains an IMAGE_RESOURCE_DATA_ENTRY
     */
    virtual bool DataIsDirectory() const = 0;

    /**
     * @brief Get the IMAGE_RESOURCE_DIRECTORY if it exists
     *
     * @return The IMAGE_RESOURCE_DIRECTORY if DataIsDirectory is set, nullptr otherwise
     */
    virtual const IMAGE_RESOURCE_DIRECTORY* Directory() const = 0;

    /**
     * @brief Get the IMAGE_RESOURCE_DATA_ENTRY if it exists
     *
     * @return The IMAGE_RESOURCE_DATA_ENTRY if DataIsDirectory is not set, nullptr otherwise
     */
    virtual const IMAGE_RESOURCE_DATA_ENTRY* Data() const = 0;

    virtual ~IMAGE_RESOURCE_DIRECTORY_ENTRY() = default;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
