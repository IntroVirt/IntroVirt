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
#include <introvirt/windows/pe/fwd.hh>

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>

namespace introvirt {
namespace windows {
namespace pe {

enum ExportType { EXPORT_TYPE_CODE, EXPORT_TYPE_DATA, EXPORT_TYPE_FORWARD };

struct Export {
    std::string name;
    ExportType exportType;
    GuestVirtualAddress address;
};

/**
 * The PE format defines an IMAGE_EXPORT_DIRECTORY section that lists exported symbols with their
 * addresses
 */
class IMAGE_EXPORT_DIRECTORY {
  public:
    virtual uint32_t Characteristics() const = 0;
    virtual uint32_t TimeDateStamp() const = 0;
    virtual uint16_t MajorVersion() const = 0;
    virtual uint16_t MinorVersion() const = 0;

    /**
     * @returns A map of address to export information
     */
    virtual const std::map<GuestVirtualAddress, Export>& AddressToExportMap() const = 0;

    /**
     * @returns A map of symbol names to export information
     */
    virtual const std::unordered_map<std::string, Export>& NameToExportMap() const = 0;

    /**
     * @returns The export specified by name (case sensitive)
     */
    virtual const Export* find(const std::string& name) const = 0;

    virtual ~IMAGE_EXPORT_DIRECTORY() = default;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
