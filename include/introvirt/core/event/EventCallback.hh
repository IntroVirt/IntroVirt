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

#include <memory>

namespace introvirt {

/**
 * @brief Interface for an event poller callback
 *
 * When running a callback-style event poller, this is the event delivery mechanism.
 */
class EventCallback {
  public:
    /**
     * @brief Process an incoming event
     *
     * @param event The incoming event
     */
    virtual void process_event(Event& event) = 0;

    virtual ~EventCallback() = default;
};

} // namespace introvirt