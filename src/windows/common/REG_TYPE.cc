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

#include <introvirt/windows/kernel/nt/const/REG_TYPE.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(REG_TYPE type) {
    static const std::string REG_NONEStr("REG_NONE");
    static const std::string REG_SZStr("REG_SZ");
    static const std::string REG_EXPAND_SZStr("REG_EXPAND_SZ");
    static const std::string REG_BINARYStr("REG_BINARY");
    static const std::string REG_DWORD_LITTLE_ENDIANStr("REG_DWORD_LITTLE_ENDIAN");
    static const std::string REG_DWORD_BIG_ENDIANStr("REG_DWORD_BIG_ENDIAN");
    static const std::string REG_LINKStr("REG_LINK");
    static const std::string REG_MULTI_SZStr("REG_MULTI_SZ");
    static const std::string REG_RESOURCE_LISTStr("REG_RESOURCE_LIST");
    static const std::string REG_FULL_RESOURCE_DESCRIPTORStr("REG_FULL_RESOURCE_DESCRIPTOR");
    static const std::string REG_RESOURCE_REQUIREMENTS_LISTStr("REG_RESOURCE_REQUIREMENTS_LIST");
    static const std::string REG_QWORD_LITTLE_ENDIANStr("REG_QWORD_LITTLE_ENDIAN");
    static const std::string UnknownStr("Unknown");

    switch (type) {
    case REG_TYPE::REG_NONE:
        return REG_NONEStr;
    case REG_TYPE::REG_SZ:
        return REG_SZStr;
    case REG_TYPE::REG_EXPAND_SZ:
        return REG_EXPAND_SZStr;
    case REG_TYPE::REG_BINARY:
        return REG_BINARYStr;
    case REG_TYPE::REG_DWORD_LITTLE_ENDIAN:
        return REG_DWORD_LITTLE_ENDIANStr;
    case REG_TYPE::REG_DWORD_BIG_ENDIAN:
        return REG_DWORD_BIG_ENDIANStr;
    case REG_TYPE::REG_LINK:
        return REG_LINKStr;
    case REG_TYPE::REG_MULTI_SZ:
        return REG_MULTI_SZStr;
    case REG_TYPE::REG_RESOURCE_LIST:
        return REG_RESOURCE_LISTStr;
    case REG_TYPE::REG_FULL_RESOURCE_DESCRIPTOR:
        return REG_FULL_RESOURCE_DESCRIPTORStr;
    case REG_TYPE::REG_RESOURCE_REQUIREMENTS_LIST:
        return REG_RESOURCE_REQUIREMENTS_LISTStr;
    case REG_TYPE::REG_QWORD_LITTLE_ENDIAN:
        return REG_QWORD_LITTLE_ENDIANStr;
    case REG_TYPE::REG_TYPE_UNKNOWN:
        break;
    };

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, REG_TYPE type) {
    os << to_string(type);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
