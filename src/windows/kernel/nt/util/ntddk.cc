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
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/kernel/nt/util/ntddk.hh>

#include <introvirt/core/event/ThreadLocalEvent.hh>

namespace introvirt {
namespace windows {
namespace nt {

uint64_t PsGetCurrentProcessId() {
    const auto& event = ThreadLocalEvent::get();
    return event.task().pid();
}

uint64_t PsGetCurrentThreadId() {
    const auto& event = ThreadLocalEvent::get();
    return event.task().tid();
}

} // namespace nt
} // namespace windows
} // namespace introvirt