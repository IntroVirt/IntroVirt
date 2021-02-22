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

#include <introvirt/windows/kernel/condrv/const/ConsoleRequestIoctl.hh>

namespace introvirt {
namespace windows {
namespace condrv {

const static std::string ConsoleCallServerGenericStr("ConsoleCallServerGeneric");
const static std::string ConsoleCommitStateStr("ConsoleCommitState");
const static std::string ConsoleLaunchServerProcessStr("ConsoleLaunchServerProcess");
const static std::string UnknownStr("Unknown");

const std::string& to_string(ConsoleRequestIoctl code) {
    switch (code) {
    case ConsoleRequestIoctl::ConsoleCallServerGeneric:
        return ConsoleCallServerGenericStr;
    case ConsoleRequestIoctl::ConsoleCommitState:
        return ConsoleCommitStateStr;
    case ConsoleRequestIoctl::ConsoleLaunchServerProcess:
        return ConsoleLaunchServerProcessStr;
    case ConsoleRequestIoctl::Unknown:
        return UnknownStr;
    }

    return UnknownStr;
}

} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */
