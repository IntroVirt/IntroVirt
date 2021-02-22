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
namespace pe {

/**
 * @brief Charactaristic flags for IMAGE_FILE_HEADER
 *
 * @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313%28v=vs.85%29.aspx
 *
 */
enum ImageFileCharacteristics : uint16_t {

    /**
     * @brief Relocation info stripped from file.
     *
     * The file must be loaded at its preferred base address.
     */
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
    /**
     * @brief The file is executable (there are no unresolved external references).
     */
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
    /**
     * @brief COFF line numbers were stripped from the file.
     */
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
    /**
     * @brief COFF symbol table entries were stripped from file.
     */
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
    /**
     * @brief Aggressively trim the working set.
     *
     * This flag is obsolete.
     */
    IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010,
    /**
     * @brief The application can handle addresses larger than 2 GB.
     */
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
    /**
     * @brief 16 bit word machine.
     */
    IMAGE_FILE_16BIT_MACHINE = 0x0040,
    /**
     * @brief The bytes of the word are reversed.
     *
     * This flag is obsolete.
     */
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
    /**
     * @brief The computer supports 32-bit words.
     */
    IMAGE_FILE_32BIT_MACHINE = 0x0100,
    /**
     * @brief Debugging information was removed and stored separately in another file.
     */
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
    /**
     * @brief If the image is on removable media, copy it to and run it from the swap file.
     */
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
    /**
     * @brief If the image is on the network, copy it to and run it from the swap file.
     */
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
    /**
     * @brief The image is a system file.
     */
    IMAGE_FILE_SYSTEM = 0x1000,
    /**
     * @brief The image is a DLL file.
     *
     * While it is an executable file, it cannot be run directly.
     */
    IMAGE_FILE_DLL = 0x2000,
    /**
     * @brief The file should be run only on a uniprocessor computer.
     */
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
    /**
     * @brief The bytes of the word are reversed.
     *
     * This flag is obsolete.
     */
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000,
};

} // namespace pe
} // namespace windows
} // namespace introvirt