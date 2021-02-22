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

#include <introvirt/windows/kernel/nt/const/OBJECT_WAIT_TYPE.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(OBJECT_WAIT_TYPE infoClass) {
    static const std::string WaitAllObjectsStr("WaitAllObjects");
    static const std::string WaitAnyObjectStr("WaitAnyObject");
    static const std::string WaitUnknownStr("Unknown");

    switch (infoClass) {
    case OBJECT_WAIT_TYPE::WaitAllObjects:
        return WaitAllObjectsStr;
    case OBJECT_WAIT_TYPE::WaitAnyObject:
        return WaitAnyObjectStr;
    }

    return WaitUnknownStr;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
