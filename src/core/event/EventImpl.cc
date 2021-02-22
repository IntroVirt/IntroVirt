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
#include "EventImpl.hh"

namespace introvirt {

const std::string& to_string(OS os) {
    static const std::string WindowsStr("Windows");
    static const std::string LinuxStr("Linux");
    static const std::string UnknownStr("Unknown");

    switch (os) {
    case OS::Windows:
        return WindowsStr;
    case OS::Linux:
        return LinuxStr;
    case OS::Unknown:
        return UnknownStr;
    }
    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, OS val) {
    os << to_string(val);
    return os;
}

} // namespace introvirt