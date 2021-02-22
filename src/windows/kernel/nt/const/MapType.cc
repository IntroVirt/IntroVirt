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
#include <introvirt/windows/kernel/nt/const/MapType.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

MapType::MapType() = default;
MapType::MapType(uint32_t value) : value(value) {}

uint32_t MapType::getValue() const { return value; }
MapType::operator uint32_t() const { return value; }
void MapType::setValue(uint32_t value) { this->value = value; }
bool MapType::isFlagEnabled(Flag flag) const { return (value & flag) != 0u; }
void MapType::disableFlag(Flag flag) { value &= ~(static_cast<uint32_t>(flag)); }
void MapType::enableFlag(Flag flag) { value |= flag; }

std::string MapType::to_string(const std::string& separator) const {
    std::ostringstream result;

    if (isFlagEnabled(MAP_PROCESS)) {
        result << "MAP_PROCESS" << separator;
    }

    if (isFlagEnabled(MAP_SYSTEM)) {
        result << "MAP_SYSTEM" << separator;
    }

    std::string resultStr = result.str();

    // Remove the trailing separator if one exists
    if (!resultStr.empty() != 0u) {
        return resultStr.substr(0, resultStr.size() - separator.size());
    }

    return resultStr;
}

std::string to_string(const MapType& options, const std::string& separator) {
    return options.to_string(separator);
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
