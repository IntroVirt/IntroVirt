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

#include <introvirt/core/arch/x86/Exception.hh>

#include <string>

namespace introvirt {
namespace x86 {

static const std::string DIVIDE_ERRORStr("DIVIDE_ERROR");
static const std::string DEBUGStr("DEBUG");
static const std::string NMIStr("NMI");
static const std::string INT3Str("INT3");
static const std::string OVERFLOWStr("OVERFLOW");
static const std::string BOUNDSStr("BOUNDS");
static const std::string INVALID_OPStr("INVALID_OP");
static const std::string NO_DEVICEStr("NO_DEVICE");
static const std::string DOUBLE_FAULTStr("DOUBLE_FAULT");
static const std::string COPRO_SEGStr("COPRO_SEG");
static const std::string INVALID_TSSStr("INVALID_TSS");
static const std::string NO_SEGMENTStr("NO_SEGMENT");
static const std::string STACK_ERRORStr("STACK_ERROR");
static const std::string GP_FAULTStr("GP_FAULT");
static const std::string PAGE_FAULTStr("PAGE_FAULT");
static const std::string SPURIOUS_INTStr("SPURIOUS_INT");
static const std::string COPRO_ERRORStr("COPRO_ERROR");
static const std::string ALIGNMENT_CHECKStr("ALIGNMENT_CHECK");
static const std::string MACHINE_CHECKStr("MACHINE_CHECK");
static const std::string SIMD_ERRORStr("SIMD_ERROR");
static const std::string UNKNOWNStr("UNKNOWN");

const std::string& to_string(Exception exception) {
    switch (exception) {
    case Exception::DIVIDE_ERROR:
        return DIVIDE_ERRORStr;
    case Exception::DEBUG:
        return DEBUGStr;
    case Exception::NMI:
        return NMIStr;
    case Exception::INT3:
        return INT3Str;
    case Exception::OVERFLOW:
        return OVERFLOWStr;
    case Exception::BOUNDS:
        return BOUNDSStr;
    case Exception::INVALID_OP:
        return INVALID_OPStr;
    case Exception::NO_DEVICE:
        return NO_DEVICEStr;
    case Exception::DOUBLE_FAULT:
        return DOUBLE_FAULTStr;
    case Exception::COPRO_SEG:
        return COPRO_SEGStr;
    case Exception::INVALID_TSS:
        return INVALID_TSSStr;
    case Exception::NO_SEGMENT:
        return NO_SEGMENTStr;
    case Exception::STACK_ERROR:
        return STACK_ERRORStr;
    case Exception::GP_FAULT:
        return GP_FAULTStr;
    case Exception::PAGE_FAULT:
        return PAGE_FAULTStr;
    case Exception::SPURIOUS_INT:
        return SPURIOUS_INTStr;
    case Exception::COPRO_ERROR:
        return COPRO_ERRORStr;
    case Exception::ALIGNMENT_CHECK:
        return ALIGNMENT_CHECKStr;
    case Exception::MACHINE_CHECK:
        return MACHINE_CHECKStr;
    case Exception::SIMD_ERROR:
        return SIMD_ERRORStr;
    case Exception::UNKNOWN:
        return UNKNOWNStr;
    }
    return UNKNOWNStr;
}

std::ostream& operator<<(std::ostream& os, Exception exception) {
    os << to_string(exception);
    return os;
}

} // namespace x86
} // namespace introvirt