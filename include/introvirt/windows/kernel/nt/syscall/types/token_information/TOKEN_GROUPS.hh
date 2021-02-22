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

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/kernel/nt/syscall/types/array_iterator.hh>
#include <introvirt/windows/kernel/nt/types/SID_AND_ATTRIBUTES.hh>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Handler for TOKEN_GROUPS information buffers
 *
 */
class TOKEN_GROUPS : public TOKEN_INFORMATION {
  public:
    using iterator = array_iterator<SID_AND_ATTRIBUTES, TOKEN_GROUPS, false>;
    using const_iterator = array_iterator<SID_AND_ATTRIBUTES, TOKEN_GROUPS, true>;

    /**
     * @brief Get an entry at the specified index
     *
     * @param index The index into the array
     * @return SID_AND_ATTRIBUTES&
     */
    virtual SID_AND_ATTRIBUTES& operator[](uint32_t index) = 0;
    virtual const SID_AND_ATTRIBUTES& operator[](uint32_t index) const = 0;

    /**
     * @copydoc TOKEN_GROUPS::operator[](uint32_t)
     *
     * @param index
     * @return SID_AND_ATTRIBUTES&
     */
    virtual SID_AND_ATTRIBUTES& at(uint32_t index) = 0;
    virtual const SID_AND_ATTRIBUTES& at(uint32_t index) const = 0;

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
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
