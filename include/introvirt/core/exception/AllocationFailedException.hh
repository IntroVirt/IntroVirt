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
 * @brief Thrown when failing to allocate guest memory
 */
class AllocationFailedException final : public TraceableException {
  public:
    /**
     * @brief Get the requested number of bytes
     *
     * @return The number of bytes that were requested
     */
    size_t requested() const;

    /**
     * @brief Construct a new instance
     *
     * @param requested The number of bytes that were requested
     */
    AllocationFailedException(size_t requested);

    /**
     * @brief Move constructor
     */
    AllocationFailedException(AllocationFailedException&&) noexcept;

    /**
     * @brief Move assignment operator
     */
    AllocationFailedException& operator=(AllocationFailedException&&) noexcept;

    /**
     * @brief Destructor
     */
    ~AllocationFailedException() noexcept override;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
};

} // namespace introvirt
