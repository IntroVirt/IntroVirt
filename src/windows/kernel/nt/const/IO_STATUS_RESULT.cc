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

#include <introvirt/windows/kernel/nt/const/IO_STATUS_RESULT.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(IO_STATUS_RESULT type) {
    static const std::string FILE_SUPERSEDEDStr("FILE_SUPERSEDED");
    static const std::string FILE_OPENEDStr("FILE_OPENED");
    static const std::string FILE_CREATEDStr("FILE_CREATED");
    static const std::string FILE_OVERWRITTENStr("FILE_OVERWRITTEN");
    static const std::string FILE_EXISTSStr("FILE_EXISTS");
    static const std::string FILE_DOES_NOT_EXISTStr("FILE_DOES_NOT_EXIST");
    static const std::string FILE_RESULT_UNAVAILABLEStr("FILE_RESULT_UNAVAILABLE");
    static const std::string IO_STATUS_RESULT_INVALIDStr("IO_STATUS_RESULT_INVALID");

    switch (type) {
    case IO_STATUS_RESULT::FILE_SUPERSEDED:
        return FILE_SUPERSEDEDStr;
    case IO_STATUS_RESULT::FILE_OPENED:
        return FILE_OPENEDStr;
    case IO_STATUS_RESULT::FILE_CREATED:
        return FILE_CREATEDStr;
    case IO_STATUS_RESULT::FILE_OVERWRITTEN:
        return FILE_OVERWRITTENStr;
    case IO_STATUS_RESULT::FILE_EXISTS:
        return FILE_EXISTSStr;
    case IO_STATUS_RESULT::FILE_DOES_NOT_EXIST:
        return FILE_DOES_NOT_EXISTStr;
    case IO_STATUS_RESULT::FILE_RESULT_UNAVAILABLE:
        return FILE_RESULT_UNAVAILABLEStr;
    case IO_STATUS_RESULT::IO_STATUS_RESULT_INVALID:
        break;
    }

    return IO_STATUS_RESULT_INVALIDStr;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
