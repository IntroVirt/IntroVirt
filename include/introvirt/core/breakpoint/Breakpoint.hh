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

#include <introvirt/core/fwd.hh>

#include <functional>
#include <memory>

namespace introvirt {

/**
 * @brief Breakpoint interface class
 *
 */
class Breakpoint {
  public:
    /**
     * @brief Change the callback of the breakpoint
     *
     * @param callback The new callback to run
     */
    virtual void callback(std::function<void(Event&)> callback) = 0;

    /**
     * @brief Get the arbitrary data associated with the breakpoint
     *
     * @return std::shared_ptr<void>
     */
    virtual std::shared_ptr<void> data() = 0;
    virtual std::shared_ptr<const void> data() const = 0;

    /**
     * @brief Set the arbitrary data associated with the breakpoint
     *
     * @param value
     */
    virtual void data(const std::shared_ptr<void>& value) = 0;
    virtual void data(std::shared_ptr<void>&& value) = 0;

    virtual ~Breakpoint() = default;
};

} // namespace introvirt