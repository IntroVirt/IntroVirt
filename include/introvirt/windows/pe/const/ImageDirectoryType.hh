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
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

enum ImageDirectoryType : uint16_t {
    // Export Directory
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    // Import Directory
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    // Resource Directory
    IMAGE_DIRECTORY_ENTRY_RESOURCE,
    // Exception Directory
    IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    // Security Directory
    IMAGE_DIRECTORY_ENTRY_SECURITY,
    // Base Relocation Table
    IMAGE_DIRECTORY_ENTRY_BASERELOC,
    // Debug Directory
    IMAGE_DIRECTORY_ENTRY_DEBUG,
    // Description String
    IMAGE_DIRECTORY_ENTRY_COPYRIGHT,
    // Machine Value (MIPS GP)
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
    // TLS Directory
    IMAGE_DIRECTORY_ENTRY_TLS,
    // Load Configuration Directory
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,

    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,

    IMAGE_DIRECTORY_ENTRY_MAX = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
};

const std::string& to_string(ImageDirectoryType type);
std::ostream& operator<<(std::ostream& os, ImageDirectoryType type);

} // namespace pe
} // namespace windows
} // namespace introvirt