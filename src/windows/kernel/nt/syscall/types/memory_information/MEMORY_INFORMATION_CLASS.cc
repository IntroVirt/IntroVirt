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

#include <introvirt/windows/kernel/nt/syscall/types/memory_information/MEMORY_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(MEMORY_INFORMATION_CLASS infoClass) {
    static const std::string MemoryBasicInformationStr("MemoryBasicInformation");
    static const std::string MemoryWorkingSetListStr("MemoryWorkingSetList");
    static const std::string MemorySectionNameStr("MemorySectionName");
    static const std::string MemoryBasicVlmInformationStr("MemoryBasicVlmInformation");
    static const std::string MemoryWorkingSetExListStr("MemoryWorkingSetExList");
    static const std::string UnknownStr("Unknown");

    switch (infoClass) {
    case MEMORY_INFORMATION_CLASS::MemoryBasicInformation:
        return MemoryBasicInformationStr;
    case MEMORY_INFORMATION_CLASS::MemoryWorkingSetList:
        return MemoryWorkingSetListStr;
    case MEMORY_INFORMATION_CLASS::MemorySectionName:
        return MemorySectionNameStr;
    case MEMORY_INFORMATION_CLASS::MemoryBasicVlmInformation:
        return MemoryBasicVlmInformationStr;
    case MEMORY_INFORMATION_CLASS::MemoryWorkingSetExList:
        return MemoryWorkingSetExListStr;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, MEMORY_INFORMATION_CLASS infoClass) {
    os << to_string(infoClass);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
