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

#include <introvirt/core/breakpoint/Breakpoint.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/function/FunctionCall.hh>
#include <introvirt/core/injection/system_call.hh>

#include <log4cxx/logger.h>

#include <functional>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace introvirt {

template <class T>
class FunctionCallReturnData {
  public:
    FunctionCallReturnData(std::unique_ptr<T>&& handler) : handler(std::move(handler)) {}

    std::shared_ptr<Breakpoint> bp;
    std::unique_ptr<T> handler;
};

template <class T>
class FunctionCallFactory final {
  private:
    static inline const log4cxx::LoggerPtr logger =
        log4cxx::Logger::getLogger("introvirt.FunctionCallFactory");

  public:
    void function_breakpoint_hit(Event& event) {
        // Run our filter (if applicable)
        if (filter_ && !filter_(event))
            return;

        // Create an instance
        std::unique_ptr<T> handler;
    retry:
        try {
            LOG4CXX_DEBUG(logger, "Entered TRY block");
            handler = std::make_unique<T>(event);
        } catch (VirtualAddressNotPresentException& ex) {
            auto* guest = event.domain().guest();
            if (guest) {
                LOG4CXX_DEBUG(logger, ex);
                if (guest->page_in(event, ex.virtual_address())) {
                    LOG4CXX_DEBUG(logger,
                                  "Successfully paged in " << n2hexstr(ex.virtual_address()));
                    goto retry;
                }
                LOG4CXX_WARN(logger, "Failed to page in " << n2hexstr(ex.virtual_address()));
                throw;
            }
        }

        // Deliver it
        try {
            callback_(event, *handler);
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "Exception during callback: " << ex);
            return;
        }

        // See if we want to hook the return
        if (handler->hook_return()) {
            auto& domain = event.domain();

            // Create the return breakpoint
            auto return_address = handler->return_address();

            // Create an instance of the return data
            auto return_data = std::make_shared<FunctionCallReturnData<T>>(std::move(handler));

            auto return_bp = domain.create_breakpoint(
                return_address, std::bind(&FunctionCallFactory<T>::function_ret_breakpoint_hit,
                                          this, std::placeholders::_1, return_data));

            return_data->bp = std::move(return_bp);
        }
    }

    void function_ret_breakpoint_hit(Event& event,
                                     std::shared_ptr<FunctionCallReturnData<T>> return_data) {
        // Check if this is the matching return
        if (return_data->handler->is_return_event(event)) {
            // Handle the return
            return_data->handler->handle_return(event);

            // Run the user's callback
            try {
                return_callback_(event, *(return_data->handler));
            } catch (TraceableException& ex) {
                LOG4CXX_WARN(logger, "Exception during callback: " << ex);
            }

            // Get rid of the breakpoint
            return_data->bp.reset();
        }
    }

    FunctionCallFactory(const guest_ptr<void>& address, std::function<void(Event&, T&)> callback,
                        std::function<void(Event&, T&)> return_callback,
                        std::function<bool(Event&)> filter = nullptr)
        : callback_(callback), return_callback_(return_callback), filter_(filter) {

        // Register a breakpoint for ourselves
        auto& domain = const_cast<Domain&>(address.domain());
        func_bp_ = domain.create_breakpoint(
            address, std::bind(&FunctionCallFactory<T>::function_breakpoint_hit, this,
                               std::placeholders::_1));
    }

    ~FunctionCallFactory() {}

  private:
    const std::function<void(Event&, T&)> callback_;
    const std::function<void(Event&, T&)> return_callback_;
    const std::function<bool(Event&)> filter_;

    std::shared_ptr<Breakpoint> func_bp_;
};

} // namespace introvirt