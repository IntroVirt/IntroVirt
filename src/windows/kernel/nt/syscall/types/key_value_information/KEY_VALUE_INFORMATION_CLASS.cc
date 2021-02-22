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

#include <introvirt/windows/kernel/nt/syscall/types/key_value_information/KEY_VALUE_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(KEY_VALUE_INFORMATION_CLASS infoClass) {
    const static std::string KeyValueBasicInformationStr = "KeyValueBasicInformation";
    const static std::string KeyValueFullInformationStr = "KeyValueFullInformation";
    const static std::string KeyValuePartialInformationStr = "KeyValuePartialInformation";
    const static std::string KeyValueFullInformationAlign64Str = "KeyValueFullInformationAlign64";
    const static std::string KeyValuePartialInformationAlign64Str =
        "KeyValuePartialInformationAlign64";
    const static std::string UnknownStr = "Unknown";

    switch (infoClass) {
    case KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation:
        return KeyValueBasicInformationStr;
    case KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation:
        return KeyValueFullInformationStr;
    case KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation:
        return KeyValuePartialInformationStr;
    case KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformationAlign64:
        return KeyValueFullInformationAlign64Str;
    case KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformationAlign64:
        return KeyValuePartialInformationAlign64Str;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, KEY_VALUE_INFORMATION_CLASS infoClass) {
    os << to_string(infoClass);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
