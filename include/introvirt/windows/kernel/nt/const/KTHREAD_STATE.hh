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
#pragma once

#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

enum KTHREAD_STATE {
    Initialized = 0,
    Ready = 1,
    Running = 2,
    Standby = 3,
    Terminated = 4,
    Waiting = 5,
    Transition = 6,
    DeferredReady = 7,
    GateWait = 8,

    /* IntroVirt only value */
    UnknownThreadState = 255,
};

/**
 * @brief Get the string value of a KTHREAD_STATE
 */
const std::string& to_string(KTHREAD_STATE state);

/**
 * @brief Stream operator overload for KTHREAD_STATE
 */
std::ostream& operator<<(std::ostream&, KTHREAD_STATE state);

} // namespace nt
} // namespace windows
} // namespace introvirt
