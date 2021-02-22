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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/pe/const/MachineType.hh>
#include <introvirt/windows/pe/types/IMAGE_SECTION_HEADER.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

/**
 * @brief Also known as the COFF_HEADER.
 *
 * See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313%28v=vs.85%29.aspx
 */
class IMAGE_FILE_HEADER {
  public:
    /**
     * @returns A MachineType value describing the architecture this PE is built for
     */
    virtual MachineType Machine() const = 0;

    /**
     * @returns The number of sections
     */
    virtual uint16_t NumberOfSections() const = 0;

    /**
     * @returns The time date stamp
     */
    virtual uint32_t TimeDateStamp() const = 0;

    /**
     * @returns An offset to the symbol table from the base of the image
     */
    virtual uint32_t PointerToSymbolTable() const = 0;

    /**
     * @returns The number of symbols
     */
    virtual uint32_t NumberOfSymbols() const = 0;

    /**
     * @returns The size of the IMAGE_OPTIONAL_HEADER section
     */
    virtual uint16_t SizeOfOptionalHeader() const = 0;

    /**
     * @returns The characteristics value from the IMAGE_FILE_HEADER
     * @see ImageFileCharacteristics
     */
    virtual uint16_t Characteristics() const = 0;

    virtual ~IMAGE_FILE_HEADER() = default;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
