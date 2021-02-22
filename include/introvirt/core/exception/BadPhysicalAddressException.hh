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

#include <introvirt/core/exception/MemoryException.hh>

#include <cstdint>

namespace introvirt {

/**
 * @brief Thrown when we fail to map a guest physical address
 */
class BadPhysicalAddressException final : public MemoryException {
  public:
    /**
     * @brief Construct a new Bad Physical Address Exception object
     *
     * @param gpa The physical address that failed to map
     * @param err An errno value
     */
    BadPhysicalAddressException(uint64_t gpa, int err);

    /**
     * @brief Move constructor
     */
    BadPhysicalAddressException(BadPhysicalAddressException&&) noexcept;

    /**
     * @brief Move assignment operator
     */
    BadPhysicalAddressException& operator=(BadPhysicalAddressException&&) noexcept;

    /**
     * @brief Destructor
     */
    ~BadPhysicalAddressException() noexcept override;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
};

} // namespace introvirt
