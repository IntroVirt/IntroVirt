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

#include "TOKEN_INFORMATION.hh"

#include <introvirt/windows/kernel/nt/syscall/types/array_iterator.hh>
#include <introvirt/windows/kernel/nt/types/LUID_AND_ATTRIBUTES.hh>

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class TOKEN_PRIVILEGES : public TOKEN_INFORMATION {
  public:
    using iterator = array_iterator<LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES, false>;
    using const_iterator = array_iterator<LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES, true>;

    /**
     * @brief Get an entry at the specified index
     *
     * @param index The index into the array
     * @return LUID_AND_ATTRIBUTES&
     */
    virtual LUID_AND_ATTRIBUTES& operator[](uint32_t index) = 0;
    virtual const LUID_AND_ATTRIBUTES& operator[](uint32_t index) const = 0;

    /**
     * @copydoc TOKEN_GROUPS::operator[](uint32_t)
     *
     * @param index
     * @return LUID_AND_ATTRIBUTES&
     */
    virtual LUID_AND_ATTRIBUTES& at(uint32_t index) = 0;
    virtual const LUID_AND_ATTRIBUTES& at(uint32_t index) const = 0;

    /**
     * @brief Remove an element from the list
     *
     * @param iter An iter to the element to remove
     * @return const_iterator containing the next element after the erased one
     */
    virtual iterator erase(const const_iterator& iter) = 0;

    /**
     * @brief Get the number of entries
     *
     * @return uint32_t
     */
    virtual uint32_t length() const = 0;

    /**
     * @brief Get an iterator to the first entry
     *
     * @return const_iterator
     */
    virtual iterator begin() = 0;

    /**
     * @brief Get the end iterator
     *
     * @return const_iterator
     */
    virtual iterator end() = 0;

    /**
     * @brief Get an iterator to the first entry
     *
     * @return const_iterator
     */
    virtual const_iterator begin() const = 0;

    /**
     * @brief Get the end iterator
     *
     * @return const_iterator
     */
    virtual const_iterator end() const = 0;

    static std::unique_ptr<TOKEN_PRIVILEGES> make_unique(const GuestVirtualAddress& gva);
    static std::unique_ptr<TOKEN_PRIVILEGES> make_unique(const GuestVirtualAddress& gva,
                                                         uint32_t buffer_size);
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
