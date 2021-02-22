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

#include "TOKEN_INFORMATION_CLASS.hh"

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/util/json/json.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief An abstract class reprseneting a more specific token information buffer.
 *
 */
class TOKEN_INFORMATION {
  public:
    /**
     * @brief Get the type of token information held in the buffer
     *
     * @return TOKEN_INFORMATION_CLASS
     */
    virtual TOKEN_INFORMATION_CLASS TokenInformationClass() const = 0;

    /**
     * @brief Get the address that the buffer is at
     *
     * @return GuestVirtualAddress
     */
    virtual GuestVirtualAddress address() const = 0;

    /**
     * @brief Get the size of the buffer
     *
     * @return uint32_t
     */
    virtual uint32_t buffer_size() const = 0;

    /**
     * @brief Write a description to the ostream
     * @param os The output stream to write to
     * @param linePrefix The prefix written before each line
     */
    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;

    /**
     * @brief Return the token information class as a JSON representation
     *
     * @return Json::Value
     */
    virtual Json::Value json() const = 0;

    /**
     * @brief Create a KEY_VALUE_INFORMATION parser instance.
     *
     * @param kernel The kernel of the guest
     * @param information_class The type of information contained in the buffer
     * @param gva The address of the information in the guest
     * @param buffer_size The size of the information buffer
     */
    static std::unique_ptr<TOKEN_INFORMATION> make_unique(const NtKernel& kernel,
                                                          TOKEN_INFORMATION_CLASS information_class,
                                                          const GuestVirtualAddress& gva,
                                                          uint32_t buffer_size);

    virtual ~TOKEN_INFORMATION() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
