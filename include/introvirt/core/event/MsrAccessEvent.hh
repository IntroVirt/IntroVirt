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

#include <cstdint>

namespace introvirt {

/**
 * @brief Interface for MSR read/write events
 *
 * Methods related to control MSR (Model Specific Register) reads and writes
 */
class MsrAccessEvent {
  public:
    /**
     * Get the number of the Ms register being accessed
     *
     * @return The control register that has been accessed
     */
    virtual uint64_t index() const = 0;

    /**
     * @brief Get the value of the control register
     *
     * @return The value of the new MSR value on WRITE, or the returned value on READ
     */
    virtual uint64_t value() const = 0;

    MsrAccessEvent() = default;
    virtual ~MsrAccessEvent() = default;
};

} // namespace introvirt