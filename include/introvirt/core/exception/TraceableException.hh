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

#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>

namespace introvirt {

/**
 * @brief Base class for exceptions with stack unwinding
 *
 * This is a base class for other, more specific exceptions.
 * It can print out the stack trace leading to the exception.
 */
class TraceableException : public std::runtime_error {
  public:
    /**
     * @brief Get the errno value if one was set
     *
     * @return The errno value if one was set, 0 otherwise.
     */
    int error_code() const;

    /**
     * @brief Move constructor
     */
    TraceableException(TraceableException&&) noexcept;

    /**
     * @brief Move assignment operator
     */
    TraceableException& operator=(TraceableException&&) noexcept;

    /**
     * @brief Destroy the instance
     */
    ~TraceableException() override;

  protected:
    /**
     * @brief Construct a new Traceable Exception object
     *
     * @param msg The error message
     */
    explicit TraceableException(const std::string& msg);

    /**
     * @brief Construct a new Traceable Exception object with an erro code
     *
     * @param msg The error message
     * @param err The errno value
     */
    TraceableException(const std::string& msg, int err);

  private:
    friend std::ostream& operator<<(std::ostream& os, const TraceableException& error);

    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
};

/**
 * @brief Write this exception to a stream
 *
 * @param os The output stream to write to
 * @param error The exception to write
 * @return std::ostream& The stream that was provided
 */
std::ostream& operator<<(std::ostream& os, const TraceableException& error);

} // namespace introvirt
