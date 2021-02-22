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

#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/size_iterator.hh>

#include <cassert>
#include <cstring>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _T, typename _BaseClass>
class size_iterable : public _BaseClass {
  public:
    using iterator = typename _BaseClass::iterator;
    using const_iterator = typename _BaseClass::const_iterator;

    iterator begin() override {
        if (data_length())
            return iterator(_T::make_shared(first_entry_), buffer_end());
        return end();
    }
    iterator end() override { return iterator(); }

    iterator erase(const const_iterator& position) override {
        // Erase the element and return a new iterator to the next one
        assert(position != end());

        const uint32_t entry_size = position->Size();

        const GuestVirtualAddress current_gva = position->address();
        const GuestVirtualAddress next_gva = current_gva + entry_size;

        // Make sure we're not already at the end
        bool last_entry = false;
        const GuestVirtualAddress buf_end = buffer_end();
        if (next_gva < buf_end) {
            const size_t map_size = buf_end - current_gva;
            const size_t copy_size = buf_end - next_gva;

            // Map in the buffer
            guest_ptr<char[]> buffer(current_gva, map_size);

            // Shift all of the data towards the start of the buffer
            std::memmove(buffer.get(), buffer.get() + entry_size, copy_size);
        } else {
            // The next entry would pass the end of the buffer, so we're erasing the last one
            last_entry = true;
        }

        // Reduce the size of the data length
        data_length(data_length() - entry_size);

        if (last_entry) {
            // We just erased the last entry, so return end()
            return end();
        }

        // Return a new iterator with the entry at the current address
        return iterator(_T::make_shared(current_gva), buffer_end());
    }

    const_iterator begin() const override {
        if (data_length())
            return const_iterator(_T::make_shared(first_entry_), buffer_end());
        return end();
    }
    const_iterator end() const override { return const_iterator(); }

    /**
     * @brief Get the amount of data used by entries
     *
     * @return uint64_t The size of the entries in bytes
     */
    virtual uint64_t data_length() const = 0;

    /**
     * @brief Set the number of bytes used by entries
     *
     * @param value The size of the entries in bytes
     */
    virtual void data_length(uint64_t value) = 0;

    GuestVirtualAddress buffer_end() const { return first_entry_ + data_length(); }

    size_iterable(const GuestVirtualAddress& first_entry) : first_entry_(first_entry) {}

  protected:
    const GuestVirtualAddress first_entry_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt