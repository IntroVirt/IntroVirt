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

#include <introvirt/windows/fwd.hh>
#include <introvirt/windows/kernel/SystemCallIndex.hh>

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

namespace introvirt {
namespace windows {

/**
 * @brief Class for converting between native system call numbers and our SystemCall values.
 *
 * Windows changes around the system call numbers between builds. This class is used to convert
 * between the native values and our "normalized" values.
 *
 */
class SystemCallConverter final {
  public:
    /**
     * @brief Normalize a system call
     *
     * Windows system call numbers change between builds.
     * To handle that, we have to normalize them to our own representation.
     *
     * @param index The raw index used by the guest
     * @return A normalized system call
     */
    SystemCallIndex normalize(uint32_t index) const;

    /**
     * @brief Convert a normalized system call into the native value
     *
     * Windows system call numbers change between builds.
     * To handle that, we have to normalize them to our own representation.
     *
     * @param index The SystemCallIndex value to convert
     * @return A raw system call index, or 0xFFFFFFFF if the guest does not support the call
     */
    uint32_t native(SystemCallIndex index) const;

    /**
     * @brief Get the number of system calls detected in the guest
     *
     * @return The number of system calls that we've detected
     */
    uint32_t count() const;

    /**
     * @brief Construct a new System Call Table object
     *
     * @param guest The guest to detect call numbers for
     * @throws GuestDetectionException if we fail to detect call numbers for the guest
     */
    SystemCallConverter(const WindowsGuest& guest);

    /**
     * @brief Destroy the instance
     */
    ~SystemCallConverter();

    /**
     * @brief A mask used for normalizing system calls
     *
     * System call numbers can have extra information, this mask
     * is used to get the call index itself.
     */
    static constexpr uint64_t SystemCallIndexMask = 0x1FFF;

  private:
    SystemCallIndex _normalize(uint32_t index,
                               const std::vector<SystemCallIndex>& to_normalized) const;

    std::vector<SystemCallIndex> to_normalized_nt_;
    std::vector<SystemCallIndex> to_normalized_win32k_;

    std::unordered_map<SystemCallIndex, uint32_t> to_native_;
};

} // namespace windows
} // namespace introvirt