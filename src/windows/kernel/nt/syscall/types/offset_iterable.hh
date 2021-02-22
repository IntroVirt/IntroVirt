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
#include <introvirt/windows/kernel/nt/syscall/types/offset_iterator.hh>

#include <cstring>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _T, typename _BaseClass>
class offset_iterable : public _BaseClass {
  public:
    using iterator = typename _BaseClass::iterator;
    using const_iterator = typename _BaseClass::const_iterator;

    iterator begin() override {
        if (buffer_size_)
            return iterator(make_shared_func_,
                            make_shared_func_(first_entry_, buffer_end_ - first_entry_),
                            buffer_end_);
        return end();
    }
    iterator end() override { return iterator(); }

    iterator erase(const const_iterator& position) override {
        // Erase the element and return a new iterator to the next one

        // TODO: This implementation doesn't work.
        // In SYSTEM_PROCESS_INFORMATION, the UNICODE_STRING buffer gets shifted,
        // leading to an invalid pointer.

        const uint32_t next_entry_offset = position->NextEntryOffset();
        if (next_entry_offset == 0) {
            // We're already at the last entry
            // Change the previous entry's offset to 0
            _T* const previous = const_cast<_T*>(position.previous());
            if (previous == nullptr) {
                // TODO: No previous entry. But we can't actually have an empty buffer.
                // Not sure what the right thing to do here
                throw InvalidMethodException();
            }
            previous->NextEntryOffset(0);

            // Reduce our buffer sizes
            buffer_size_ -= next_entry_offset;
            buffer_end_ = first_entry_ + buffer_size_;

            return end();
        }

        // Find the last entry. We already checked above to make sure we weren't the last one.
        const_iterator iter(position);
        const_iterator test;
        do {
            test = ++iter;
            ++test;
        } while (test != end());

        GuestVirtualAddress entries_end = iter->address() + iter->buffer_size();

        const GuestVirtualAddress current_gva = position->address();
        const GuestVirtualAddress next_gva = current_gva + next_entry_offset;

        // Make sure we're not already at the end
        bool last_entry = false;
        if (next_gva < entries_end) {
            const size_t map_size = entries_end - current_gva;
            const size_t copy_size = entries_end - next_gva;

            // Map in the buffer
            guest_ptr<char[]> buffer(current_gva, map_size);

            // Shift all of the data towards the start of the buffer
            std::memmove(buffer.get(), buffer.get() + next_entry_offset, copy_size);
        } else {
            // No more entries after this one
            last_entry = true;
        }

        buffer_size_ -= next_entry_offset;
        buffer_end_ = first_entry_ + buffer_size_;

        if (last_entry) {
            return end();
        }

        // Return a new iterator with the entry at the current address
        return iterator(make_shared_func_,
                        make_shared_func_(current_gva, buffer_end_ - current_gva), buffer_end_);
    }

    const_iterator begin() const override {
        if (buffer_size_)
            return const_iterator(make_shared_func_,
                                  make_shared_func_(first_entry_, buffer_end_ - first_entry_),
                                  buffer_end_);
        return end();
    }
    const_iterator end() const override { return const_iterator(); }

    template <typename... Args>
    offset_iterable(
        std::function<std::shared_ptr<_T>(const GuestVirtualAddress&, uint32_t)> make_shared_func,
        const GuestVirtualAddress& first_entry, uint32_t buffer_size, Args&&... args)
        : _BaseClass(std::forward<Args>(args)...), make_shared_func_(make_shared_func),
          first_entry_(first_entry), buffer_end_(first_entry_ + buffer_size),
          buffer_size_(buffer_size) {}

  protected:
    std::function<std::shared_ptr<_T>(const GuestVirtualAddress&, uint32_t)> make_shared_func_;
    const GuestVirtualAddress first_entry_;
    GuestVirtualAddress buffer_end_;
    uint32_t buffer_size_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt