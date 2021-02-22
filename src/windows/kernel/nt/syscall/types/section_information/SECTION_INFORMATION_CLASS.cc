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

#include <introvirt/windows/kernel/nt/syscall/types/section_information/SECTION_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(SECTION_INFORMATION_CLASS infoClass) {
    static const std::string SectionBasicInformationStr("SectionBasicInformation");
    static const std::string SectionImageInformationStr("SectionImageInformation");
    static const std::string SectionRelocationInformationStr("SectionRelocationInformation");
    static const std::string UnknownStr("Unknown");

    switch (infoClass) {
    case SECTION_INFORMATION_CLASS::SectionBasicInformation:
        return SectionBasicInformationStr;
    case SECTION_INFORMATION_CLASS::SectionImageInformation:
        return SectionImageInformationStr;
    case SECTION_INFORMATION_CLASS::SectionRelocationInformation:
        return SectionRelocationInformationStr;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, SECTION_INFORMATION_CLASS infoClass) {
    os << to_string(infoClass);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
