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

#include <introvirt/windows/kernel/nt/const/KTHREAD_STATE.hh>

namespace introvirt {
namespace windows {
namespace nt {

const static std::string InitializedStr = "Initialized";
const static std::string ReadyStr = "Ready";
const static std::string RunningStr = "Running";
const static std::string StandbyStr = "Standby";
const static std::string TerminatedStr = "Terminated";
const static std::string WaitingStr = "Waiting";
const static std::string TransitionStr = "Transition";
const static std::string DeferredReadyStr = "DeferredReady";
const static std::string GateWaitStr = "GateWait";
const static std::string UnknownStr = "Unknown";

const std::string& to_string(KTHREAD_STATE state) {
    switch (state) {
    case KTHREAD_STATE::Initialized:
        return InitializedStr;
    case KTHREAD_STATE::Ready:
        return ReadyStr;
    case KTHREAD_STATE::Running:
        return RunningStr;
    case KTHREAD_STATE::Standby:
        return StandbyStr;
    case KTHREAD_STATE::Terminated:
        return TerminatedStr;
    case KTHREAD_STATE::Waiting:
        return WaitingStr;
    case KTHREAD_STATE::Transition:
        return TransitionStr;
    case KTHREAD_STATE::DeferredReady:
        return DeferredReadyStr;
    case KTHREAD_STATE::GateWait:
        return GateWaitStr;
    case KTHREAD_STATE::UnknownThreadState:
        return UnknownStr;
    }
    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, KTHREAD_STATE state) {
    os << to_string(state);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt