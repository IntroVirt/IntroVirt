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
#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace introvirt {

/**
 * @brief Base class for function calls
 */
class FunctionCall {
  public:
    /**
     * @brief Get the return address for this function call
     *
     * @return GuestVirtualAddress
     */
    virtual GuestVirtualAddress return_address() const = 0;

    /**
     * @brief Set the return address for this function call
     *
     * @param value The new return address to use
     */
    virtual void return_address(const GuestVirtualAddress& value) = 0;

    /**
     * @brief Check if the user is requesting that the return be intercepted
     *
     * @return true
     * @return false
     */
    bool hook_return() const;

    /**
     * @brief Configure if the return should be intercepted
     *
     * @param val If set to true, intercept the return
     */
    void hook_return(bool val);

    /**
     * @brief Check if the given event is a return event for this function call
     *
     * @param event
     * @return true
     * @return false
     */
    virtual bool is_return_event(Event& event) const = 0;

    /**
     * @brief Handle the return event
     *
     * Perform processing to handle the return of the function call
     *
     * @param event The return event
     */
    virtual void handle_return(Event& event) = 0;

    /**
     * @brief Check if the call has returned
     *
     * @return true if the call has returned
     * @return false if the call has not returnerd
     */
    virtual bool returned() const = 0;

    /**
     * @brief Get the name of the library this call is for
     *
     * @return const std::string&
     */
    virtual const std::string& library_name() const = 0;

    /**
     * @brief Get the function name
     *
     * @return const std::string&
     */
    virtual const std::string& function_name() const = 0;

    /**
     * @brief Write out a textual representation of the function for display
     *
     * @param os
     */
    virtual void write(std::ostream& os = std::cout) const = 0;

    /**
     * @brief Store arbitrary data with the FunctionCall
     *
     * This can be useful for storing data when handling the function call,
     * and retreiving it when the call returns.
     *
     * @param key The name of the value to store
     * @param value The data to store
     */
    void data(const std::string& key, const std::shared_ptr<void>& value);

    /**
     * @copydoc FunctionCall::data(const std::string&,  const std::shared_ptr<void>&)
     */
    void data(const std::string& key, std::shared_ptr<void>&& value);

    /**
     * @brief Retrieve arbitrary data stored with the FunctionCall
     *
     * This can be used to retrieve arbitrary stored data.
     *
     * @param key The name of the value to retrieve
     * @return The data that was stored, or nullptr if the key was not found.
     */
    std::shared_ptr<void> data(const std::string& key);

    /**
     * @copydoc FunctionCall::data(const std::string&)
     *
     * This is the const version.
     */
    std::shared_ptr<const void> data(const std::string& key) const;

    virtual ~FunctionCall() = default;

  private:
    std::unordered_map<std::string, std::shared_ptr<void>> data_;
    bool hook_return_ = false;
};

} // namespace introvirt