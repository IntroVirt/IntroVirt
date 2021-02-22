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

#include <introvirt/windows/kernel/nt/const/FILE_ATTRIBUTES.hh>

#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(FILE_ATTRIBUTE_TYPE type) {
    static const std::string FILE_ATTRIBUTE_READONLYStr("FILE_ATTRIBUTE_READONLY");
    static const std::string FILE_ATTRIBUTE_HIDDENStr("FILE_ATTRIBUTE_HIDDEN");
    static const std::string FILE_ATTRIBUTE_SYSTEMStr("FILE_ATTRIBUTE_SYSTEM");
    static const std::string FILE_ATTRIBUTE_DIRECTORYStr("FILE_ATTRIBUTE_DIRECTORY");
    static const std::string FILE_ATTRIBUTE_ARCHIVEStr("FILE_ATTRIBUTE_ARCHIVE");
    static const std::string FILE_ATTRIBUTE_DEVICEStr("FILE_ATTRIBUTE_DEVICE");
    static const std::string FILE_ATTRIBUTE_NORMALStr("FILE_ATTRIBUTE_NORMAL");
    static const std::string FILE_ATTRIBUTE_TEMPORARYStr("FILE_ATTRIBUTE_TEMPORARY");
    static const std::string FILE_ATTRIBUTE_SPARSE_FILEStr("FILE_ATTRIBUTE_SPARSE_FILE");
    static const std::string FILE_ATTRIBUTE_REPARSE_POINTStr("FILE_ATTRIBUTE_REPARSE_POINT");
    static const std::string FILE_ATTRIBUTE_COMPRESSEDStr("FILE_ATTRIBUTE_COMPRESSED");
    static const std::string FILE_ATTRIBUTE_OFFLINEStr("FILE_ATTRIBUTE_OFFLINE");
    static const std::string FILE_ATTRIBUTE_NOT_CONTENT_INDEXEDStr(
        "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED");
    static const std::string FILE_ATTRIBUTE_ENCRYPTEDStr("FILE_ATTRIBUTE_ENCRYPTED");
    static const std::string FILE_ATTRIBUTE_VIRTUALStr("FILE_ATTRIBUTE_VIRTUAL");
    static const std::string FILE_ATTRIBUTE_UNKNOWNStr("FILE_ATTRIBUTE_UNKNOWN");

    switch (type) {
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_READONLY:
        return FILE_ATTRIBUTE_READONLYStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_HIDDEN:
        return FILE_ATTRIBUTE_HIDDENStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_SYSTEM:
        return FILE_ATTRIBUTE_SYSTEMStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_DIRECTORY:
        return FILE_ATTRIBUTE_DIRECTORYStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_ARCHIVE:
        return FILE_ATTRIBUTE_ARCHIVEStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_DEVICE:
        return FILE_ATTRIBUTE_DEVICEStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_NORMAL:
        return FILE_ATTRIBUTE_NORMALStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_TEMPORARY:
        return FILE_ATTRIBUTE_TEMPORARYStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_SPARSE_FILE:
        return FILE_ATTRIBUTE_SPARSE_FILEStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_REPARSE_POINT:
        return FILE_ATTRIBUTE_REPARSE_POINTStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_COMPRESSED:
        return FILE_ATTRIBUTE_COMPRESSEDStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_OFFLINE:
        return FILE_ATTRIBUTE_OFFLINEStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED:
        return FILE_ATTRIBUTE_NOT_CONTENT_INDEXEDStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_ENCRYPTED:
        return FILE_ATTRIBUTE_ENCRYPTEDStr;
    case FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_VIRTUAL:
        return FILE_ATTRIBUTE_VIRTUALStr;
    }

    return FILE_ATTRIBUTE_UNKNOWNStr;
}

#define CHECK_AND_ADD(t)                                                                           \
    if (atts.get() & t)                                                                            \
        ss << to_string(t) << ' ';

std::string to_string(FILE_ATTRIBUTES atts) {
    std::stringstream ss;

    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_READONLY);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_HIDDEN);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_SYSTEM);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_DIRECTORY);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_ARCHIVE);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_DEVICE);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_NORMAL);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_TEMPORARY);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_SPARSE_FILE);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_REPARSE_POINT);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_COMPRESSED);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_OFFLINE);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_ENCRYPTED);
    CHECK_AND_ADD(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_VIRTUAL);

    return ss.str();
}

#define CHECK_AND_ADD_JSON(t)                                                                      \
    if (attributes & t)                                                                            \
        result["Attributes"].append(to_string(t));

Json::Value FILE_ATTRIBUTES::json() const {
    Json::Value result;
    result["value"] = get();

    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_READONLY);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_HIDDEN);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_SYSTEM);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_DIRECTORY);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_ARCHIVE);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_DEVICE);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_NORMAL);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_TEMPORARY);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_SPARSE_FILE);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_REPARSE_POINT);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_COMPRESSED);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_OFFLINE);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_ENCRYPTED);
    CHECK_AND_ADD_JSON(FILE_ATTRIBUTE_TYPE::FILE_ATTRIBUTE_VIRTUAL);

    return result;
}

std::string FILE_ATTRIBUTES::dir_string() const {
    std::stringstream ss;
    ss << '[';
    if (isDirectory()) {
        ss << 'd';
    } else if (isDevice()) {
        ss << 'D';
    } else {
        ss << ' ';
    }
    if (isArchive()) {
        ss << 'A';
    } else {
        ss << ' ';
    }
    if (isReadOnly()) {
        ss << 'R';
    } else {
        ss << ' ';
    }
    if (isSystem()) {
        ss << 'S';
    } else {
        ss << ' ';
    }
    if (isHidden()) {
        ss << 'H';
    } else {
        ss << ' ';
    }
    ss << ']';
    return ss.str();
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
