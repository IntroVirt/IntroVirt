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
#include <introvirt/windows/pe/const/RelocationType.hh>

namespace introvirt {
namespace windows {
namespace pe {

const std::string& to_string(RelocationType type) {
    const static std::string IMAGE_REL_BASED_ABSOLUTESTR = "IMAGE_REL_BASED_ABSOLUTE";
    const static std::string IMAGE_REL_BASED_HIGHSTR = "IMAGE_REL_BASED_HIGH";
    const static std::string IMAGE_REL_BASED_LOWStr = "IMAGE_REL_BASED_LOW";
    const static std::string IMAGE_REL_BASED_HIGHLOWStr = "IMAGE_REL_BASED_HIGHLOW";
    const static std::string IMAGE_REL_BASED_HIGHADJSTR = "IMAGE_REL_BASED_HIGHADJ";
    const static std::string IMAGE_REL_BASED_MACHINE_SPECIFIC_5STR =
        "IMAGE_REL_BASED_MACHINE_SPECIFIC_5";
    const static std::string IMAGE_REL_BASED_RESERVEDSTR = "IMAGE_REL_BASED_RESERVED";
    const static std::string IMAGE_REL_BASED_MACHINE_SPECIFIC_7STR =
        "IMAGE_REL_BASED_MACHINE_SPECIFIC_7";
    const static std::string IMAGE_REL_BASED_MACHINE_SPECIFIC_8STR =
        "IMAGE_REL_BASED_MACHINE_SPECIFIC_8";
    const static std::string IMAGE_REL_BASED_MACHINE_SPECIFIC_9STR =
        "IMAGE_REL_BASED_MACHINE_SPECIFIC_9";
    const static std::string IMAGE_REL_BASED_DIR64STR = "IMAGE_REL_BASED_DIR64";
    const static std::string IMAGE_REL_UNKNOWNSTR = "IMAGE_REL_UNKNOWN";

    switch (type) {
    case RelocationType::IMAGE_REL_BASED_ABSOLUTE:
        return IMAGE_REL_BASED_ABSOLUTESTR;
    case RelocationType::IMAGE_REL_BASED_HIGH:
        return IMAGE_REL_BASED_HIGHSTR;
    case RelocationType::IMAGE_REL_BASED_LOW:
        return IMAGE_REL_BASED_LOWStr;
    case RelocationType::IMAGE_REL_BASED_HIGHLOW:
        return IMAGE_REL_BASED_HIGHLOWStr;
    case RelocationType::IMAGE_REL_BASED_HIGHADJ:
        return IMAGE_REL_BASED_HIGHADJSTR;
    case RelocationType::IMAGE_REL_BASED_MACHINE_SPECIFIC_5:
        return IMAGE_REL_BASED_MACHINE_SPECIFIC_5STR;
    case RelocationType::IMAGE_REL_BASED_RESERVED:
        return IMAGE_REL_BASED_RESERVEDSTR;
    case RelocationType::IMAGE_REL_BASED_MACHINE_SPECIFIC_7:
        return IMAGE_REL_BASED_MACHINE_SPECIFIC_7STR;
    case RelocationType::IMAGE_REL_BASED_MACHINE_SPECIFIC_8:
        return IMAGE_REL_BASED_MACHINE_SPECIFIC_8STR;
    case RelocationType::IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
        return IMAGE_REL_BASED_MACHINE_SPECIFIC_9STR;
    case RelocationType::IMAGE_REL_BASED_DIR64:
        return IMAGE_REL_BASED_DIR64STR;
    }

    return IMAGE_REL_UNKNOWNSTR;
}

std::ostream& operator<<(std::ostream& os, RelocationType type) {
    os << to_string(type);
    return os;
}

} // namespace pe
} // namespace windows
} // namespace introvirt