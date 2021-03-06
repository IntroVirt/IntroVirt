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

#include <introvirt/core/arch/x86/Exception.hh>

namespace introvirt {

/**
 * @brief Interface for x86 exception events
 *
 * This event is for x86 CPU exceptions, such as software breakpoints.
 */
class ExceptionEvent {
  public:
    /**
     * @brief Get the vector of the exception that was intercepted
     *
     * @return The exception type associated with this event
     */
    virtual x86::Exception vector() const = 0;

    virtual ~ExceptionEvent() = default;
};

} // namespace introvirt