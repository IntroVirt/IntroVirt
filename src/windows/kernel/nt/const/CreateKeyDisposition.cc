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

#include <introvirt/windows/kernel/nt/const/CreateKeyDisposition.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(CreateKeyDisposition disp) {
    static const std::string REG_CREATED_NEW_KEY_STR("REG_CREATED_NEW_KEY");
    static const std::string REG_OPENED_EXISTING_KEY_STR("REG_OPENED_EXISTING_KEY");
    static const std::string REG_UNKNOWN_DISPOSITION_STR("REG_UNKNOWN_DISPOSITION");

    switch (disp) {
    case CreateKeyDisposition::REG_CREATED_NEW_KEY:
        return REG_CREATED_NEW_KEY_STR;
    case CreateKeyDisposition::REG_OPENED_EXISTING_KEY:
        return REG_CREATED_NEW_KEY_STR;
    default:
        return REG_UNKNOWN_DISPOSITION_STR;
    }
}
std::ostream& operator<<(std::ostream& os, CreateKeyDisposition disp) {
    os << to_string(disp);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
