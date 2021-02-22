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

#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <functional>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Iterator helper for _INFORMATION types that have a NextEntryOffset field
 *
 * @tparam _T
 * @tparam false
 */
template <typename _T, bool _Const = false>
class offset_iterator {
  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = void;

    /* deduce const qualifier from bool _Const parameter */
    using reference = typename std::conditional_t<_Const, const _T&, _T&>;
    using pointer = typename std::conditional_t<_Const, const _T*, _T*>;

  public:
    inline reference operator*() const { return *current_; }
    inline pointer operator->() const { return current_.get(); }
    inline bool operator==(const offset_iterator<_T, _Const>& other) const {
        if (!current_ || !other.current_) {
            // One of them is nullptr
            // Return true if they're both nullptr, false if only one is
            return (current_.get() == other.current_.get());
        }

        return current_->address() == other.current_->address();
    }
    inline bool operator!=(const offset_iterator<_T, _Const>& other) const {
        return !(operator==(other));
    }

    // Prefix operator
    offset_iterator& operator++() {
        if (unlikely(!current_)) {
            // Already at the end iterator
            return *this;
        }

        // Get the next entry offset
        const uint64_t next_entry_offset = current_->NextEntryOffset();
        GuestVirtualAddress pNextEntry;

        // If there is another
        if (next_entry_offset) {
            // If it's non-zero, there should be another entry
            pNextEntry = current_->address() + next_entry_offset;
            if (pNextEntry >= buffer_end_) {
                // We're past the end of the buffer.
                pNextEntry = GuestVirtualAddress();
            }
        }

        if (pNextEntry) {
            previous_ = std::move(current_);
            current_ = make_shared_func_(pNextEntry, buffer_end_ - pNextEntry);
        } else {
            // We've reached the end
            current_.reset();
            previous_.reset();
        }

        return *this;
    }

    // Postfix operator
    offset_iterator operator++(int) {
        auto copy = *this;
        operator++();
        return copy;
    }

    pointer previous() const { return previous_.get(); }

    offset_iterator(
        std::function<std::shared_ptr<_T>(const GuestVirtualAddress&, uint32_t)> make_shared_func,
        const std::shared_ptr<_T>& value, const GuestVirtualAddress& buffer_end)
        : make_shared_func_(make_shared_func), current_(value), buffer_end_(buffer_end) {}
    offset_iterator(
        std::function<std::shared_ptr<_T>(const GuestVirtualAddress&, uint32_t)> make_shared_func,
        std::shared_ptr<_T>&& value, const GuestVirtualAddress& buffer_end)
        : make_shared_func_(make_shared_func), current_(std::move(value)), buffer_end_(buffer_end) {
    }

    // null/end constructor
    offset_iterator() {}

    // Copy constructor to convert from iterator to const_iterator
    template <bool _Const_ = _Const, class = std::enable_if_t<_Const_>>
    offset_iterator(const offset_iterator<_T, false>& src)
        : make_shared_func_(src.make_shared_func_), current_(src.current_),
          previous_(src.previous_), buffer_end_(src.buffer_end_) {}

    offset_iterator<_T, _Const>(const offset_iterator<_T, _Const>&) = default;
    offset_iterator<_T, _Const>& operator=(const offset_iterator<_T, _Const>&) = default;

  private:
    friend class offset_iterator<_T, false>;
    friend class offset_iterator<_T, true>;

    std::function<std::shared_ptr<_T>(const GuestVirtualAddress&, uint32_t)> make_shared_func_;
    std::shared_ptr<_T> current_;
    std::shared_ptr<_T> previous_;
    GuestVirtualAddress buffer_end_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt