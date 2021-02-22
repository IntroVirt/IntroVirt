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
#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

namespace introvirt {

/**
 * Abstract base class for a system call handler
 */
class SystemCall {
  public:
    /**
     * @brief Get the name of the system call
     *
     * @return The name of the system call as a string
     */
    virtual const std::string& name() const = 0;

    /**
     * @brief Write a human-readable description of this system call
     * @param os The stream to write to
     */
    virtual void write(std::ostream& os = std::cout) const = 0;

    /**
     * @return a JSON representation of the system call
     */
    virtual Json::Value json() const = 0;

    /**
     * @return True if this call will return
     */
    virtual bool will_return() const = 0;

    /**
     * @brief Store arbitrary data with the SystemCall
     *
     * This can be useful for storing data when handling the system call,
     * and retreiving it when the call returns.
     *
     * @param key The name of the value to store
     * @param value The data to store
     */
    virtual void data(const std::string& key, const std::shared_ptr<void>& value) = 0;

    /**
     * @copydoc SystemCall::data(const std::string&,  const std::shared_ptr<void>&)
     */
    virtual void data(const std::string& key, std::shared_ptr<void>&& value) = 0;

    /**
     * @brief Retrieve arbitrary data stored with the SystemCall
     *
     * This can be used to retrieve arbitrary stored data.
     *
     * @param key The name of the value to retrieve
     * @return The data that was stored, or nullptr if the key was not found.
     */
    virtual std::shared_ptr<void> data(const std::string& key) = 0;

    /**
     * @copydoc SystemCall::data(const std::string&)
     *
     * This is the const version.
     */
    virtual std::shared_ptr<const void> data(const std::string& key) const = 0;

    /**
     * @brief Check if this system call is supported by a more specific handler
     *
     * @return true If there is a derived class supporting this system call
     * @return false If there is no system call handler for the current call
     */
    virtual bool supported() const = 0;

    /**
     * @brief Handle a system call return event
     *
     * @param event The system call return event
     */
    virtual void handle_return_event(Event& event) = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~SystemCall() = default;
};

} // namespace introvirt
