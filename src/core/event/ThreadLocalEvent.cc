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
#include <introvirt/core/event/ThreadLocalEvent.hh>

namespace introvirt {

static thread_local Event* thread_local_event_ = nullptr;

Event& ThreadLocalEvent::get() {
    if (unlikely(!thread_local_event_))
        throw InvalidMethodException();

    return *thread_local_event_;
}

bool ThreadLocalEvent::active() { return thread_local_event_ != nullptr; }
void ThreadLocalEvent::set(Event& event) { thread_local_event_ = &event; }
void ThreadLocalEvent::clear() { thread_local_event_ = nullptr; }

} // namespace introvirt
