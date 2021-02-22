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
#include <introvirt/windows/pe/const/ImageDirectoryType.hh>

namespace introvirt {
namespace windows {
namespace pe {

const std::string& to_string(ImageDirectoryType type) {

    static const std::string IMAGE_DIRECTORY_ENTRY_EXPORTStr = "IMAGE_DIRECTORY_ENTRY_EXPORT";
    static const std::string IMAGE_DIRECTORY_ENTRY_IMPORTStr = "IMAGE_DIRECTORY_ENTRY_IMPORT";
    static const std::string IMAGE_DIRECTORY_ENTRY_RESOURCEStr = "IMAGE_DIRECTORY_ENTRY_RESOURCE";
    static const std::string IMAGE_DIRECTORY_ENTRY_EXCEPTIONStr = "IMAGE_DIRECTORY_ENTRY_EXCEPTION";
    static const std::string IMAGE_DIRECTORY_ENTRY_SECURITYStr = "IMAGE_DIRECTORY_ENTRY_SECURITY";
    static const std::string IMAGE_DIRECTORY_ENTRY_BASERELOCStr = "IMAGE_DIRECTORY_ENTRY_BASERELOC";
    static const std::string IMAGE_DIRECTORY_ENTRY_DEBUGStr = "IMAGE_DIRECTORY_ENTRY_DEBUG";
    static const std::string IMAGE_DIRECTORY_ENTRY_COPYRIGHTStr = "IMAGE_DIRECTORY_ENTRY_COPYRIGHT";
    static const std::string IMAGE_DIRECTORY_ENTRY_GLOBALPTRStr = "IMAGE_DIRECTORY_ENTRY_GLOBALPTR";
    static const std::string IMAGE_DIRECTORY_ENTRY_TLSStr = "IMAGE_DIRECTORY_ENTRY_TLS";
    static const std::string IMAGE_DIRECTORY_ENTRY_LOAD_CONFIGStr =
        "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG";
    static const std::string IMAGE_DIRECTORY_ENTRY_BOUND_IMPORTStr =
        "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT";
    static const std::string IMAGE_DIRECTORY_ENTRY_IATStr = "IMAGE_DIRECTORY_ENTRY_IAT";
    static const std::string IMAGE_DIRECTORY_ENTRY_DELAY_IMPORTStr =
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT";
    static const std::string IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTORStr =
        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR";
    static const std::string IMAGE_DIRECTORY_ENTRY_UNKNOWNStr = "IMAGE_DIRECTORY_ENTRY_UNKNOWN";

    switch (type) {
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_EXPORT:
        return IMAGE_DIRECTORY_ENTRY_EXPORTStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_IMPORT:
        return IMAGE_DIRECTORY_ENTRY_IMPORTStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_RESOURCE:
        return IMAGE_DIRECTORY_ENTRY_RESOURCEStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_EXCEPTION:
        return IMAGE_DIRECTORY_ENTRY_EXCEPTIONStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_SECURITY:
        return IMAGE_DIRECTORY_ENTRY_SECURITYStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_BASERELOC:
        return IMAGE_DIRECTORY_ENTRY_BASERELOCStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_DEBUG:
        return IMAGE_DIRECTORY_ENTRY_DEBUGStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
        return IMAGE_DIRECTORY_ENTRY_COPYRIGHTStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
        return IMAGE_DIRECTORY_ENTRY_GLOBALPTRStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_TLS:
        return IMAGE_DIRECTORY_ENTRY_TLSStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
        return IMAGE_DIRECTORY_ENTRY_LOAD_CONFIGStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
        return IMAGE_DIRECTORY_ENTRY_BOUND_IMPORTStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_IAT:
        return IMAGE_DIRECTORY_ENTRY_IATStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
        return IMAGE_DIRECTORY_ENTRY_DELAY_IMPORTStr;
    case ImageDirectoryType::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
        return IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTORStr;
    }

    return IMAGE_DIRECTORY_ENTRY_UNKNOWNStr;
}

std::ostream& operator<<(std::ostream& os, ImageDirectoryType type) {
    os << to_string(type);
    return os;
}

} // namespace pe
} // namespace windows
} // namespace introvirt