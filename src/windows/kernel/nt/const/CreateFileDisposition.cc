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

#include <introvirt/windows/kernel/nt/const/CreateFileDisposition.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(CreateFileDisposition disposition) {
    const static std::string FILE_SUPERSEDE_STR("FILE_SUPERSEDE ");
    const static std::string FILE_OPEN_STR("FILE_OPEN");
    const static std::string FILE_CREATE_STR("FILE_CREATE");
    const static std::string FILE_OPEN_IF_STR("FILE_OPEN_IF");
    const static std::string FILE_OVERWRITE_STR("FILE_OVERWRITE");
    const static std::string FILE_OVERWRITE_IF_STR("FILE_OVERWRITE_IF");
    const static std::string FILE_CREATE_DISPOSITION_INVALID_STR("FILE_CREATE_DISPOSITION_INVALID");

    switch (disposition) {
    case CreateFileDisposition::FILE_SUPERSEDE:
        return FILE_SUPERSEDE_STR;
    case CreateFileDisposition::FILE_OPEN:
        return FILE_OPEN_STR;
    case CreateFileDisposition::FILE_CREATE:
        return FILE_CREATE_STR;
    case CreateFileDisposition::FILE_OPEN_IF:
        return FILE_OPEN_IF_STR;
    case CreateFileDisposition::FILE_OVERWRITE:
        return FILE_OVERWRITE_STR;
    case CreateFileDisposition::FILE_OVERWRITE_IF:
        return FILE_OVERWRITE_IF_STR;
    case CreateFileDisposition::FILE_CREATE_DISPOSITION_INVALID:
        return FILE_CREATE_DISPOSITION_INVALID_STR;
    }

    return FILE_CREATE_DISPOSITION_INVALID_STR;
}

std::ostream& operator<<(std::ostream& os, CreateFileDisposition disposition) {
    os << to_string(disposition);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
