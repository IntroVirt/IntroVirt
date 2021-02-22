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

#include <introvirt/core/exception/TraceableException.hh>

#include <cstdint>

namespace introvirt {

/**
 * @brief Thrown when an error occurs during system call injection
 */
class SystemCallInjectionException final : public TraceableException {
  public:
    /**
     * @brief Construct a new instance
     *
     * @param message The error message
     */
    SystemCallInjectionException(const std::string& message);

    /**
     * @brief Move constructor
     */
    SystemCallInjectionException(SystemCallInjectionException&&) noexcept;

    /**
     * @brief Move assignment operator
     */
    SystemCallInjectionException& operator=(SystemCallInjectionException&&) noexcept;

    /**
     * @brief Destructor
     */
    ~SystemCallInjectionException() noexcept override;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
};

} // namespace introvirt
