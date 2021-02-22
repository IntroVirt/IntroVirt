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
#include <introvirt/util/compiler.hh>

#include <cassert>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Iterator helper for _INFORMATION types that have a fixed array result
 *
 * @tparam _T
 * @tparam false
 */
template <typename _T, typename _Container, bool _Const = false>
class array_iterator {
  public:
    using iterator_category = std::random_access_iterator_tag;
    using difference_type = int32_t;
    using value_type = _T;

    /* deduce const qualifier from bool _Const parameter */
    using reference = typename std::conditional_t<_Const, const _T&, _T&>;
    using pointer = typename std::conditional_t<_Const, const _T*, _T*>;

  public:
    inline reference operator*() const { return container_[index_]; }
    inline pointer operator->() const { return &(container_[index_]); }

    inline bool operator==(const array_iterator<_T, _Container, _Const>& other) const {
        return index_ == other.index_;
    }
    inline bool operator!=(const array_iterator<_T, _Container, _Const>& other) const {
        return !(operator==(other));
    }

    reference operator[](difference_type offset) const { return container_[index_ + offset]; }

    array_iterator& operator+=(difference_type offset) {
        assert((index_ + offset) <= container_->size());
        index_ += offset;
        return *this;
    }

    array_iterator operator+(difference_type offset) const {
        auto result = *this;
        result += offset;
        return result;
    }

    array_iterator& operator-=(difference_type offset) {
        assert((index_ - offset) >= 0);
        index_ -= offset;
        return *this;
    }

    array_iterator operator-(difference_type offset) const {
        auto result = *this;
        result += offset;
        return result;
    }

    // Prefix increment operator
    array_iterator& operator++() {
        // Check if we're already at the end
        assert(index_ < container_.length());
        ++index_;
        return *this;
    }

    // Postfix increment operator
    array_iterator operator++(int) {
        auto copy = *this;
        operator++();
        return copy;
    }

    // Prefix decrement operator
    array_iterator& operator--() {
        // Check if we're at the start
        assert(index_ > 0);
        --index_;
        return *this;
    }

    // Postfix decrement operator
    array_iterator operator--(int) {
        auto copy = *this;
        operator--();
        return copy;
    }

    uint32_t index() const { return index_; }

    array_iterator(const _Container& container, uint32_t index)
        : container_(container), index_(index) {}

    // null/end constructor
    array_iterator(const _Container& container)
        : container_(container), index_(container.length()) {}

    // Copy constructor to convert from iterator to const_iterator
    template <bool Const_ = _Const, class = std::enable_if_t<Const_>>
    array_iterator(const array_iterator<_T, _Container, false>& src)
        : container_(src.container), index_(src.index_) {}

    array_iterator<_T, _Container, _Const>(const array_iterator<_T, _Container, _Const>&) = default;
    array_iterator<_T, _Container, _Const>&
    operator=(const array_iterator<_T, _Container, _Const>&) = default;

  private:
    const _Container& container_;
    uint32_t index_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt