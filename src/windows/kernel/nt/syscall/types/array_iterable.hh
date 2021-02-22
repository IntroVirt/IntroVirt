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

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/offset_iterator.hh>

#include <cassert>
#include <cmath>
#include <cstring>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _T, typename _BaseClass, uint32_t _EntrySize,
          typename _EntryCountType = uint32_t, bool _EntryCountInBytes = false,
          int _EntryBytesAdditional = 0>
class array_iterable : public _BaseClass {
  public:
    // Can't set _EntryBytesAdditional if _EntryCountInBytes==false
    static_assert(_EntryCountInBytes == true || _EntryBytesAdditional == 0);

    using iterator = typename _BaseClass::iterator;
    using const_iterator = typename _BaseClass::const_iterator;

    iterator begin() override {
        if (length() > 0)
            return iterator(*this, 0);
        return end();
    }
    iterator end() override { return iterator(*this); }

    iterator erase(const const_iterator& position) override {
        assert(position.index() < length());

        const uint32_t index = position.index();
        const GuestVirtualAddress gva = position->address();
        const GuestVirtualAddress end_gva = first_entry_ + (length() * _EntrySize);
        const size_t count = end_gva - gva;

        // Map in the buffer
        guest_ptr<char[]> buffer(gva, count);

        // Shift all of the data towards the start of the buffer
        std::memmove(buffer.get(), buffer.get() + _EntrySize, count - _EntrySize);

        // We have to clear the value table for all affected entries
        for (uint32_t i = index; i < length(); ++i) {
            value_table_.at(i).reset();
        }

        length(length() - 1);

        // Return a new iterator with the entry at the current index
        return iterator(*this, index);
    }

    const_iterator begin() const override {
        if (length() > 0)
            return const_iterator(*this, 0);
        return end();
    }
    const_iterator end() const override { return const_iterator(*this); }

    _T& operator[](uint32_t index) override { return at(index); }
    const _T& operator[](uint32_t index) const override { return at(index); }

    _T& at(uint32_t index) override {
        const auto* const_this = this;
        return const_cast<_T&>(const_this->at(index));
    }

    const _T& at(uint32_t index) const override {
        assert(index < length());

        auto& entry = value_table_.at(index);
        if (!entry) {
            // Calculate the address of the entry
            const auto pEntry = first_entry_ + (_EntrySize * index);
            entry = std::make_shared<_T>(pEntry);
        }
        return *entry;
    };

    template <typename... Args>
    array_iterable(const GuestVirtualAddress& length_ptr, const GuestVirtualAddress& first_entry,
                   Args&&... args)
        : _BaseClass(std::forward<Args>(args)...), first_entry_(first_entry), length_(length_ptr) {

        value_table_.resize(length());
    }

    uint32_t length() const override {
        // Get the number of entries in the buffer
        if constexpr (_EntryCountInBytes) {
            return (*length_ - _EntryBytesAdditional) / _EntrySize;
        } else {
            return *length_;
        }
    }

    // TODO: Add bounds checking based on buffer_size()

    void length(uint32_t value) {
        // Set the number of entries in the buffer
        if constexpr (_EntryCountInBytes) {
            *length_ = (_EntrySize * value) + _EntryBytesAdditional;
        } else {
            *length_ = value;
        }
    }

  protected:
    const GuestVirtualAddress first_entry_;
    guest_ptr<_EntryCountType> length_; // May be in either "entries" or "bytes"

    mutable std::vector<std::shared_ptr<_T>> value_table_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt