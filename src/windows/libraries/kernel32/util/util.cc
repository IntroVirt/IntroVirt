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
#include "windows/injection/function.hh"

#include <introvirt/core/event/ThreadLocalEvent.hh>

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>
#include <introvirt/windows/kernel/nt/types/TEB.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
#include <introvirt/windows/libraries/kernel32/util/util.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace kernel32 {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.win.kernel32.util"));

WinError GetLastError() {
    if (inject::LastErrorValueInject) {
        return *inject::LastErrorValueInject;
    }

    auto& event = static_cast<WindowsEvent&>(ThreadLocalEvent::get());

    const nt::TEB* teb = event.task().pcr().CurrentThread().Teb();
    if (likely(teb != nullptr))
        return teb->LastErrorValue();

    LOG4CXX_WARN(logger, "Thread missing TEB in GetLastError() call");
    return WinError::ERROR_SUCCESS;
}

} // namespace kernel32
} // namespace windows
} // namespace introvirt
