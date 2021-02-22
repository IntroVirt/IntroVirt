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

#include <introvirt/fwd.hh>
#include <mspdb/PDB.hh>

#include <vector>

namespace introvirt {
namespace windows {
namespace pe {

/**
 * @brief Parser for Windows Portable Executable (PE) headers
 */
class PE {
  public:
    /**
     * @return The DOS_HEADER member of the PE
     */
    virtual const DOS_HEADER& dos_header() const = 0;

    /**
     *@returns The IMAGE_FILE_HEADER of this PE
     */
    virtual const IMAGE_FILE_HEADER& file_header() const = 0;

    /**
     * @returns The IMAGE_OPTIONAL_HEADER of this PE
     */
    virtual const IMAGE_OPTIONAL_HEADER& optional_header() const = 0;

    /**
     * @returns The IMAGE_EXPORT_DIRECTORY of this PE, or NULL if one does not exist
     */
    virtual const IMAGE_EXPORT_DIRECTORY* export_directory() const = 0;

    /**
     * @brief Get the sections in this PE
     *
     * @return const std::vector<const IMAGE_SECTION_HEADER>&
     */
    virtual const std::vector<std::unique_ptr<const IMAGE_SECTION_HEADER>>& sections() const = 0;

    /**
     * @brief Get the debug symbols for this PE
     * @return The debug symbols for this PE
     * @throws PeException if the PDB symbols could not be loaded
     */
    virtual const mspdb::PDB& pdb() const = 0;

    /**
     * @returns The base address of the image
     */
    virtual GuestVirtualAddress address() const = 0;

    static std::unique_ptr<PE> make_unique(const GuestVirtualAddress& gva);

    virtual ~PE() = default;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
