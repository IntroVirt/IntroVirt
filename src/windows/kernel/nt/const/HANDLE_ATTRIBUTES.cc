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

#include <introvirt/windows/kernel/nt/const/HANDLE_ATTRIBUTES.hh>

#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

HANDLE_ATTRIBUTES::HANDLE_ATTRIBUTES(uint32_t flags) : flags(flags) {}

HANDLE_ATTRIBUTES::HANDLE_ATTRIBUTES(const HANDLE_ATTRIBUTES&) = default;
HANDLE_ATTRIBUTES& HANDLE_ATTRIBUTES::operator=(const HANDLE_ATTRIBUTES&) = default;

uint32_t HANDLE_ATTRIBUTES::get() const { return flags; }
Json::Value HANDLE_ATTRIBUTES::json() const {
    Json::Value result;
    result["value"] = flags;

    if (isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_INHERIT))
        result["flags"].append(to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_INHERIT));
    if (isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_PERMANENT))
        result["flags"].append(to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_PERMANENT));
    if (isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_EXCLUSIVE))
        result["flags"].append(to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_EXCLUSIVE));
    if (isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_CASE_INSENSITIVE))
        result["flags"].append(to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_CASE_INSENSITIVE));
    if (isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_OPENIF))
        result["flags"].append(to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_OPENIF));
    if (isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_OPENLINK))
        result["flags"].append(to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_OPENLINK));
    if (isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_KERNEL_HANDLE))
        result["flags"].append(to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_KERNEL_HANDLE));
    if (isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_FORCE_ACCESS_CHECK))
        result["flags"].append(to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_FORCE_ACCESS_CHECK));

    return result;
}

HANDLE_ATTRIBUTES::operator uint32_t() const { return flags; }
HANDLE_ATTRIBUTES::operator Json::Value() const { return json(); }

bool HANDLE_ATTRIBUTES::isSet(HANDLE_ATTRIBUTES_FLAG flag) const {
    return flags & static_cast<uint32_t>(flag);
}
void HANDLE_ATTRIBUTES::set(HANDLE_ATTRIBUTES_FLAG flag) { flags |= static_cast<uint32_t>(flag); }
void HANDLE_ATTRIBUTES::clear(HANDLE_ATTRIBUTES_FLAG flag) {
    flags &= ~(static_cast<uint32_t>(flag));
}

std::string to_string(HANDLE_ATTRIBUTES atts) {
    std::stringstream ss;

    if (atts.isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_INHERIT))
        ss << to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_INHERIT) << ' ';
    if (atts.isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_PERMANENT))
        ss << to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_PERMANENT) << ' ';
    if (atts.isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_EXCLUSIVE))
        ss << to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_EXCLUSIVE) << ' ';
    if (atts.isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_CASE_INSENSITIVE))
        ss << to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_CASE_INSENSITIVE) << ' ';
    if (atts.isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_OPENIF))
        ss << to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_OPENIF) << ' ';
    if (atts.isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_OPENLINK))
        ss << to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_OPENLINK) << ' ';
    if (atts.isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_KERNEL_HANDLE))
        ss << to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_KERNEL_HANDLE) << ' ';
    if (atts.isSet(HANDLE_ATTRIBUTES_FLAG::OBJ_FORCE_ACCESS_CHECK))
        ss << to_string(HANDLE_ATTRIBUTES_FLAG::OBJ_FORCE_ACCESS_CHECK) << ' ';

    return ss.str();
}

const std::string& to_string(HANDLE_ATTRIBUTES_FLAG flag) {
    static const std::string OBJ_INHERITStr("OBJ_INHERIT");
    static const std::string OBJ_PERMANENTStr("OBJ_PERMANENT");
    static const std::string OBJ_EXCLUSIVEStr("OBJ_EXCLUSIVE");
    static const std::string OBJ_CASE_INSENSITIVEStr("OBJ_CASE_INSENSITIVE");
    static const std::string OBJ_OPENIFStr("OBJ_OPENIF");
    static const std::string OBJ_OPENLINKStr("OBJ_OPENLINK");
    static const std::string OBJ_KERNEL_HANDLEStr("OBJ_KERNEL_HANDLE");
    static const std::string OBJ_FORCE_ACCESS_CHECKStr("OBJ_FORCE_ACCESS_CHECK");
    static const std::string OBJ_VALID_ATTRIBUTESStr("OBJ_VALID_ATTRIBUTES");
    static const std::string UNKNOWN("UNKNOWN");

    switch (flag) {
    case HANDLE_ATTRIBUTES_FLAG::OBJ_INHERIT:
        return OBJ_INHERITStr;
    case HANDLE_ATTRIBUTES_FLAG::OBJ_PERMANENT:
        return OBJ_PERMANENTStr;
    case HANDLE_ATTRIBUTES_FLAG::OBJ_EXCLUSIVE:
        return OBJ_EXCLUSIVEStr;
    case HANDLE_ATTRIBUTES_FLAG::OBJ_CASE_INSENSITIVE:
        return OBJ_CASE_INSENSITIVEStr;
    case HANDLE_ATTRIBUTES_FLAG::OBJ_OPENIF:
        return OBJ_OPENIFStr;
    case HANDLE_ATTRIBUTES_FLAG::OBJ_OPENLINK:
        return OBJ_OPENLINKStr;
    case HANDLE_ATTRIBUTES_FLAG::OBJ_KERNEL_HANDLE:
        return OBJ_KERNEL_HANDLEStr;
    case HANDLE_ATTRIBUTES_FLAG::OBJ_FORCE_ACCESS_CHECK:
        return OBJ_FORCE_ACCESS_CHECKStr;
    case HANDLE_ATTRIBUTES_FLAG::OBJ_VALID_ATTRIBUTES:
        return OBJ_VALID_ATTRIBUTESStr;
    }

    return UNKNOWN;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
