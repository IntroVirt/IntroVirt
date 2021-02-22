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
#include <introvirt/windows/pe/const/SubsystemType.hh>

namespace introvirt {
namespace windows {
namespace pe {

const std::string& to_string(SubsystemType type) {
    static const std::string NATIVESTR = "NATIVE";
    static const std::string WINDOWS_GUISTR = "WINDOWS_GUI";
    static const std::string WINDOWS_CUISTR = "WINDOWS_CUI";
    static const std::string OS2_CUISTR = "OS2_CUI";
    static const std::string POSIX_CUISTR = "POSIX_CUI";
    static const std::string UNKNOWN_SUBSYSTEMSTR = "UNKNOWN_SUBSYSTEM";

    switch (type) {
    case SubsystemType::NATIVE:
        return NATIVESTR;
    case SubsystemType::WINDOWS_GUI:
        return WINDOWS_GUISTR;
    case SubsystemType::WINDOWS_CUI:
        return WINDOWS_CUISTR;
    case SubsystemType::OS2_CUI:
        return OS2_CUISTR;
    case SubsystemType::POSIX_CUI:
        return POSIX_CUISTR;
    }

    return UNKNOWN_SUBSYSTEMSTR;
}

std::ostream& operator<<(std::ostream& os, SubsystemType type) {
    os << to_string(type);
    return os;
}

} // namespace pe
} // namespace windows
} // namespace introvirt