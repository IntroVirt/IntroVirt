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

#include <introvirt/windows/pe/const/ImageDirectoryType.hh>
#include <introvirt/windows/pe/const/SubsystemType.hh>
#include <introvirt/windows/pe/fwd.hh>

#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_OPTIONAL_HEADER {
  public:
    virtual uint16_t Magic() const = 0;
    virtual uint8_t MajorLinkerVersion() const = 0;
    virtual uint8_t MinorLinkerVersion() const = 0;
    virtual uint32_t SizeOfCode() const = 0;
    virtual uint32_t SizeOfInitializedData() const = 0;
    virtual uint32_t SizeOfUninitializedData() const = 0;
    virtual GuestVirtualAddress AddressOfEntryPoint() const = 0;
    virtual GuestVirtualAddress BaseOfCode() const = 0;
    virtual GuestVirtualAddress BaseOfData() const = 0;
    virtual uint64_t ImageBase() const = 0;
    virtual uint32_t SectionAlignment() const = 0;
    virtual uint32_t FileAlignment() const = 0;
    virtual uint16_t MajorOperatingSystemVersion() const = 0;
    virtual uint16_t MinorOperatingSystemVersion() const = 0;
    virtual uint16_t MajorImageVersion() const = 0;
    virtual uint16_t MinorImageVersion() const = 0;
    virtual uint16_t MajorSubsystemVersion() const = 0;
    virtual uint16_t MinorSubsystemVersion() const = 0;
    virtual uint32_t Win32VersionValue() const = 0;
    virtual uint32_t SizeOfImage() const = 0;
    virtual uint32_t SizeOfHeaders() const = 0;
    virtual uint32_t CheckSum() const = 0;
    virtual uint16_t Subsystem() const = 0;
    virtual uint16_t DllCharacteristics() const = 0;
    virtual uint64_t SizeOfStackReserve() const = 0;
    virtual uint64_t SizeOfStackCommit() const = 0;
    virtual uint64_t SizeOfHeapReserve() const = 0;
    virtual uint64_t SizeOfHeapCommit() const = 0;
    virtual uint32_t LoaderFlags() const = 0;
    virtual uint32_t NumberOfRvaAndSizes() const = 0;

    virtual const IMAGE_RELOCATION_SECTION* basereloc_directory() const = 0;
    virtual const IMAGE_DEBUG_DIRECTORY* debug_directory() const = 0;
    virtual const IMAGE_EXCEPTION_SECTION* exception_directory() const = 0;
    virtual const IMAGE_EXPORT_DIRECTORY* export_directory() const = 0;
    virtual const IMAGE_RESOURCE_DIRECTORY* resource_directory() const = 0;
    virtual const IMPORT_NAME_TABLE* import_directory() const = 0;

    /**
     * @brief Get the address of the IMAGE_OPTIONAL_HEADER
     *
     * @return GuestVirtualAddress
     */
    virtual GuestVirtualAddress address() const = 0;

    /**
     * @brief Check if the PE is 32 or 64 bit
     *
     * @return true if the PE is 64-bit
     * @return false if the PE is 32-bit
     */
    virtual bool x64() const = 0;

    static std::unique_ptr<IMAGE_OPTIONAL_HEADER> make_unique(const GuestVirtualAddress& image_base,
                                                              const IMAGE_FILE_HEADER& file_header);

    virtual ~IMAGE_OPTIONAL_HEADER() = default;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
