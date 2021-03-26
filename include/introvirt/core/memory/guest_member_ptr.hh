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

#include "guest_ptr.hh"
#include "guest_size_t_ptr.hh"

namespace introvirt {

/// Helper class to embed in structs
template <typename _ResultType, typename _PtrType>
class guest_member_ptr final {
    using _basic_resulttype = std::remove_extent_t<_ResultType>;
    using _basic_ptrtype = std::remove_extent_t<_PtrType>;

    static_assert(std::is_same_v<_basic_ptrtype, uint32_t> ||
                      std::is_same_v<_basic_ptrtype, uint64_t>,
                  "Invalid PtrType");

    static constexpr bool _is_result_array = std::is_array_v<_ResultType>;
    static constexpr bool _is_ptrtype_array = std::is_array_v<_PtrType>;
    static constexpr bool _is_pointer = std::is_pointer_v<_basic_resulttype>;
    static constexpr bool _is_cstring = std::is_same_v<std::remove_const_t<_ResultType>, char[]>;
    static constexpr bool _is_wstring =
        std::is_same_v<std::remove_const_t<_ResultType>, char16_t[]>;

    using _outptr_type =
        guest_ptr<_ResultType, std::conditional_t<_is_pointer, _basic_ptrtype, void>>;

    inline void _check_bounds(size_t index) const {
        constexpr bool length = sizeof(_PtrType) / sizeof(_basic_ptrtype);
        introvirt_assert(index < length, "Accessing array out of bounds");
    }

  public:
    explicit inline operator bool() const { return raw_ != 0; }
    constexpr bool x64() const { return std::is_same_v<_basic_ptrtype, uint64_t>; }

    /// setters
    void set(_basic_ptrtype in) {
        static_assert(!_is_ptrtype_array, "set() requires a length for array types");
        raw_ = in;
    }
    void set(_basic_ptrtype in, size_t index) {
        static_assert(_is_ptrtype_array, "set() only requires a length for array types");
        _check_bounds(index);
        raw_[index] = in;
    }
    template <typename Tp, typename PtrType>
    void set(const guest_ptr<Tp, PtrType>& in) {
        static_assert(!_is_ptrtype_array, "set() requires a length for array types");
        raw_ = in.address();
    }
    template <typename Tp, typename PtrType>
    void set(const guest_ptr<Tp, PtrType>& in, size_t index) {
        static_assert(_is_ptrtype_array, "set() only requires a length for array types");
        _check_bounds(index);
        raw_[index] = in.address();
    }

    /// Getters
    _outptr_type get(guest_ptr<void> context) const {
        // Neither the result nor the ptrtype is not an array
        static_assert(!_is_result_array, "length is needed for arrays");
        static_assert(!_is_ptrtype_array, "index needed for arrays");
        context.reset(raw_);
        return _outptr_type(context);
    }
    _outptr_type get(guest_ptr<void> context, size_t length) const {
        // The ptrtype is not an array, but the result is
        static_assert(_is_result_array, "length is only needed for arrays");
        static_assert(!_is_ptrtype_array, "index needed for arrays");
        context.reset(raw_);
        return _outptr_type(context, length);
    }
    _outptr_type get(size_t index, guest_ptr<void> context) const {
        // The ptrtype is an array, but the result is not
        static_assert(!_is_result_array, "length is needed for arrays");
        static_assert(_is_ptrtype_array, "index only needed for non arrays");
        _check_bounds(index);
        context.reset(raw_[index]);
        return _outptr_type(context);
    }
    _outptr_type get(size_t index, guest_ptr<void> context, size_t length) const {
        // Both the result and ptrtype are arrays
        static_assert(_is_result_array, "length only needed for arrays");
        static_assert(_is_ptrtype_array, "index only needed for non arrays");
        _check_bounds(index);
        context.reset(raw_[index]);
        return _outptr_type(context, length);
    }

    /// cstring helpers
    guest_ptr<char[]> cstring(guest_ptr<void> context, size_t max_length = 0xFFFF) const {
        static_assert(_is_cstring, "cstring() is only valid for char[]");
        static_assert(!_is_ptrtype_array, "index is required for cstring() arrays");
        context.reset(raw_);
        return map_guest_cstring(context, max_length);
    }
    guest_ptr<char[]> cstring(size_t index, guest_ptr<void> context,
                              size_t max_length = 0xFFFF) const {
        static_assert(_is_cstring, "cstring() is only valid for char[]");
        static_assert(_is_ptrtype_array, "index is only required for cstring() arrays");
        _check_bounds(index);
        context.reset(raw_[index]);
        return map_guest_cstring(context, max_length);
    }
    /// wstring helpers
    guest_ptr<char16_t[]> wstring(guest_ptr<void> context, size_t max_length = 0xFFFF) const {
        static_assert(_is_wstring, "wstring() is only valid for char16_t[]");
        static_assert(!_is_ptrtype_array, "index is required for cstring() arrays");
        context.reset(raw_);
        return map_guest_wstring(context, max_length);
    }
    guest_ptr<char16_t[]> wstring(size_t index, guest_ptr<void> context,
                                  size_t max_length = 0xFFFF) const {
        static_assert(_is_wstring, "wstring() is only valid for char16_t[]");
        static_assert(_is_ptrtype_array, "index is only required for cstring() arrays");
        _check_bounds(index);
        context.reset(raw_[index]);
        return map_guest_wstring(context, max_length);
    }

    _basic_ptrtype raw() const {
        static_assert(!_is_ptrtype_array, "Index required for arrays");
        return raw_;
    }

    _basic_ptrtype raw(size_t index) const {
        static_assert(_is_ptrtype_array, "Index only required for arrays");
        _check_bounds(index);
        return raw_[index];
    }

  private:
    _PtrType raw_;
};

static_assert(sizeof(guest_member_ptr<void, uint32_t>) == sizeof(uint32_t),
              "guest_ptr_member size mismatch");
static_assert(sizeof(guest_member_ptr<void, uint64_t>) == sizeof(uint64_t),
              "guest_ptr_member size mismatch");

} // namespace introvirt