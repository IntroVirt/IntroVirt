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

#include "FILE_INFORMATION.hh"

#include <cstdint>

namespace introvirt {
namespace windows {
namespace nt {

class FILE_ATTRIBUTE_TAG_INFORMATION : public FILE_INFORMATION {
    /**
     * Return one or more FILE_ATTRIBUTE_XXX flags.
     *
     * @returns The FileAttributes field
     */
    virtual FILE_ATTRIBUTES FileAttributes() const = 0;

    /**
     * @brief Set the FileAttributes field
     *
     * @param attributes The value to set
     */
    virtual void FileAttributes(FILE_ATTRIBUTES attributes) = 0;

    /**
     * @brief Get the ReparseTag field
     *
     * Specifies the reparse point tag.
     * Only valid if the FileAttributes includes the FILE_ATTRIBUTE_REPARSE_POINT flag,
     *
     * @returns The ReparseTag field
     */
    virtual uint32_t ReparseTag() const = 0;

    /**
     * @brief Set the ReparseTag field
     *
     * @param value The value to set
     */
    virtual void ReparseTag(uint32_t value) = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
