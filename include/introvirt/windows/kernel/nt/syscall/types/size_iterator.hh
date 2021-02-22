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

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Iterator helper for _INFORMATION types that have a Size field
 *
 * @tparam _T
 * @tparam false
 */
template <typename _T, bool _Const = false>
class size_iterator {
  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = void;

    /* deduce const qualifier from bool _Const parameter */
    using reference = typename std::conditional_t<_Const, const _T&, _T&>;
    using pointer = typename std::conditional_t<_Const, const _T*, _T*>;

  public:
    inline reference operator*() const { return *current_; }
    inline pointer operator->() const { return current_.get(); }
    inline bool operator==(const size_iterator<_T, _Const>& other) const {
        if (!current_ || !other.current_) {
            // One of them is nullptr
            // Return true if they're both nullptr, false if only one is
            return (current_.get() == other.current_.get());
        }

        return current_->address() == other.current_->address();
    }
    inline bool operator!=(const size_iterator<_T, _Const>& other) const {
        return !(operator==(other));
    }

    // Prefix operator
    size_iterator& operator++() {
        if (unlikely(!current_)) {
            // Already at the end iterator
            return *this;
        }

        // Get the next entry offset
        const uint64_t entry_size = current_->Size();

        GuestVirtualAddress pNextEntry = current_->address() + entry_size;
        if (pNextEntry < buffer_end_) {
            current_ = _T::make_shared(pNextEntry);
        } else {
            // Next address would be past the end of the buffer
            current_.reset();
        }

        return *this;
    }

    // Postfix operator
    size_iterator operator++(int) {
        auto copy = *this;
        operator++();
        return copy;
    }

    size_iterator(const std::shared_ptr<_T>& value, const GuestVirtualAddress& buffer_end)
        : current_(value), buffer_end_(buffer_end) {}
    size_iterator(std::shared_ptr<_T>&& value, const GuestVirtualAddress& buffer_end)
        : current_(std::move(value)), buffer_end_(buffer_end) {}

    // null/end constructor
    size_iterator() {}

    // Copy constructor to convert from iterator to const_iterator
    template <bool _Const_ = _Const, class = std::enable_if_t<_Const_>>
    size_iterator(const size_iterator<_T, false>& src)
        : current_(src.current_), buffer_end_(src.buffer_end_) {}

    size_iterator<_T, _Const>(const size_iterator<_T, _Const>&) = default;
    size_iterator<_T, _Const>& operator=(const size_iterator<_T, _Const>&) = default;

  private:
    std::shared_ptr<_T> current_;
    GuestVirtualAddress buffer_end_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt