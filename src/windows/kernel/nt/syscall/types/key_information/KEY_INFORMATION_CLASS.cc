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

#include <introvirt/windows/kernel/nt/syscall/types/key_information/KEY_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(KEY_INFORMATION_CLASS infoClass) {
    static const std::string KeyBasicInformationStr = "KeyBasicInformation";
    static const std::string KeyNodeInformationStr = "KeyNodeInformation";
    static const std::string KeyFullInformationStr = "KeyFullInformation";
    static const std::string KeyNameInformationStr = "KeyNameInformation";
    static const std::string KeyCachedInformationStr = "KeyCachedInformation";
    static const std::string KeyFlagsInformationStr = "KeyFlagsInformation";
    static const std::string KeyVirtualizationInformationStr = "KeyVirtualizationInformation";
    static const std::string KeyHandleTagsInformationStr = "KeyHandleTagsInformation";
    static const std::string UnknownStr = "Unknown";

    switch (infoClass) {
    case KEY_INFORMATION_CLASS::KeyBasicInformation:
        return KeyBasicInformationStr;
    case KEY_INFORMATION_CLASS::KeyNodeInformation:
        return KeyNodeInformationStr;
    case KEY_INFORMATION_CLASS::KeyFullInformation:
        return KeyFullInformationStr;
    case KEY_INFORMATION_CLASS::KeyNameInformation:
        return KeyNameInformationStr;
    case KEY_INFORMATION_CLASS::KeyCachedInformation:
        return KeyCachedInformationStr;
    case KEY_INFORMATION_CLASS::KeyFlagsInformation:
        return KeyFlagsInformationStr;
    case KEY_INFORMATION_CLASS::KeyVirtualizationInformation:
        return KeyVirtualizationInformationStr;
    case KEY_INFORMATION_CLASS::KeyHandleTagsInformation:
        return KeyHandleTagsInformationStr;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, KEY_INFORMATION_CLASS infoClass) {
    os << to_string(infoClass);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
