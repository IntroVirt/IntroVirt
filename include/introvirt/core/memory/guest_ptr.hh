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

#include <introvirt/core/arch/x86/PageDirectory.hh>
#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/util/compiler.hh>

#include <cassert>
#include <cstdint>
#include <vector>

namespace introvirt {

/**
 * @brief guest_ptr for single objects
 *
 * This template allows syntax like
 * @code{.cc}
 * guest_ptr<uint32_t> ptr(gva);
 * @endcode
 *
 * @tparam _Tp The type of data
 */
template <typename _Tp>
class guest_ptr {
  public:
    static_assert(std::is_pod_v<_Tp>, "guest_ptr types must be plain old data");

    inline _Tp& operator*() const {
        assert(buffer_);
        return *buffer_;
    }

    inline _Tp* operator->() const {
        assert(buffer_);
        return buffer_;
    }

    inline _Tp* get() const { return buffer_; }

    inline operator bool() const { return buffer_ != nullptr; }

    /**
     * @brief Reset the guest_ptr to nullptr
     */
    void reset() {
        mapping_.reset();
        buffer_ = nullptr;
    }

    /**
     * @brief Reset the guest_ptr to a new value
     *
     * @param ga The address in the guest of the data
     */
    void reset(const GuestAddress& ga) {
        if (ga.value()) {
            mapping_ = std::make_shared<GuestMemoryMapping>(ga.map(sizeof(_Tp)));
            char* const buf = reinterpret_cast<char*>(mapping_->get());
            buffer_ = reinterpret_cast<_Tp*>(buf + ga.page_offset());
        } else {
            reset();
        }
    }

    guest_ptr() : buffer_(nullptr) {}
    guest_ptr(const GuestAddress& ga) { reset(ga); }

    /**
     * @brief Copy constructor to get a const version from a non-const
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_const_v<U>>>
    guest_ptr(const guest_ptr<std::remove_const_t<_Tp>>& in)
        : mapping_(in.mapping_), buffer_(in.buffer_) {}

    /**
     * @brief Move constructor to get a const version from a non-const
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_const_v<U>>>
    guest_ptr(guest_ptr<std::remove_const_t<_Tp>>&& in)
        : mapping_(std::move(in.mapping_)), buffer_(in.buffer_) {
        in.buffer_ = nullptr;
        in.length_ = 0;
    }

    /**
     * @brief Copy assignment operator to assign non-const to const
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_const_v<U>>>
    guest_ptr& operator=(const guest_ptr<std::remove_const_t<_Tp>>& in) noexcept {
        mapping_ = in.maping_;
        buffer_ = in.buffer_;
        return *this;
    }

    /**
     * @brief Move assignment operator to get a const version from a non-const
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_const_v<U>>>
    guest_ptr& operator=(guest_ptr<std::remove_const_t<_Tp>>&& in) noexcept {
        mapping_ = std::move(in.maping_);
        buffer_ = in.buffer_;
        in.buffer_ = nullptr;
        return *this;
    }

    guest_ptr(const guest_ptr&) noexcept = default;
    guest_ptr& operator=(const guest_ptr&) noexcept = default;
    guest_ptr(guest_ptr&&) noexcept = default;
    guest_ptr& operator=(guest_ptr&&) noexcept = default;

  private:
    std::shared_ptr<GuestMemoryMapping> mapping_;
    _Tp* buffer_;
};

/**
 * @brief guest_ptr for array with a runtime length
 *
 * This template allows syntax like
 * @code{.cc}
 * guest_ptr<char[]> ptr(gva, 64);
 * @endcode
 *
 * @tparam _Tp The type of data
 */
template <typename _Tp>
class guest_ptr<_Tp[]> {
  public:
    static_assert(std::is_pod_v<_Tp>, "guest_ptr types must be plain old data");

    inline _Tp* begin() const { return buffer_; }
    inline _Tp* end() const { return buffer_ + length_; }

    inline _Tp& operator*() const {
        assert(buffer_);
        return *buffer_;
    }

    inline _Tp* operator->() const {
        assert(buffer_);
        return buffer_;
    }

    inline _Tp* get() const { return buffer_; }

    inline _Tp& at(size_t index) const {
        assert(index < length_);
        return buffer_[index];
    }

    inline _Tp& operator[](size_t index) const { return at(index); }

    inline operator bool() const { return buffer_ != nullptr; }

    /**
     * @brief Get the number of elements in the array
     *
     * @return size_t
     */
    inline size_t length() const { return length_; }

    /**
     * @brief Reset the guest_ptr to nullptr
     */
    void reset() {
        mapping_.reset();
        buffer_ = nullptr;
        length_ = 0;
    }

    /**
     * @brief Reset the guest_ptr to a new value
     *
     * @param ga The address in the guest of the data
     * @param length The number of elements in the array
     */
    void reset(const GuestAddress& ga, size_t length) {
        if (ga.value() && length) {
            mapping_ = std::make_shared<GuestMemoryMapping>(ga.map(sizeof(_Tp) * length));
            char* const buf = reinterpret_cast<char*>(mapping_->get());
            buffer_ = reinterpret_cast<_Tp*>(buf + ga.page_offset());
            length_ = length;
        } else {
            reset();
        }
    }

    /**
     * @brief Convienience operator to get an std::string_view from guest_ptr<char[]>
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_same_v<U, char>>>
    operator std::string_view() const {
        return std::string_view(buffer_, length_);
    }

    /**
     * @brief Convienience operator to get an std::u16_string_view from guest_ptr<char16_t[]>
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_same_v<U, char16_t>>>
    operator std::u16string_view() const {
        return std::u16string_view(buffer_, length_);
    }

    template <typename U>
    friend class guest_ptr;

    guest_ptr() : buffer_(nullptr), length_(0) {}
    guest_ptr(const GuestAddress& ga, size_t length) { reset(ga, length); }
    guest_ptr(std::shared_ptr<GuestMemoryMapping>&& mapping, _Tp* buffer, size_t length)
        : mapping_(std::move(mapping)), buffer_(buffer), length_(length) {}

    /**
     * @brief Copy constructor to get a const version from a non-const
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_const_v<U>>>
    guest_ptr(const guest_ptr<std::remove_const_t<_Tp>[]>& in)
        : mapping_(in.mapping_), buffer_(in.buffer_), length_(in.length_) {}

    /**
     * @brief Move constructor to get a const version from a non-const
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_const_v<U>>>
    guest_ptr(guest_ptr<std::remove_const_t<_Tp>[]>&& in)
        : mapping_(std::move(in.mapping_)), buffer_(in.buffer_), length_(in.length_) {
        in.buffer_ = nullptr;
        in.length_ = 0;
    }

    /**
     * @brief Copy assignment operator to assign non-const to const
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_const_v<U>>>
    guest_ptr& operator=(const guest_ptr<std::remove_const_t<_Tp>[]>& in) noexcept {
        mapping_ = in.maping_;
        buffer_ = in.buffer_;
        length_ = in.length_;
        return *this;
    }

    /**
     * @brief Move assignment operator to get a const version from a non-const
     */
    template <typename U = _Tp, typename = typename std::enable_if_t<std::is_const_v<U>>>
    guest_ptr& operator=(guest_ptr<std::remove_const_t<_Tp>[]>&& in) noexcept {
        mapping_ = std::move(in.maping_);
        buffer_ = in.buffer_;
        length_ = in.length_;
        in.buffer_ = nullptr;
        in.length_ = 0;
        return *this;
    }

    template <typename U>
    friend class guest_ptr;

    guest_ptr(const guest_ptr&) noexcept = default;
    guest_ptr& operator=(const guest_ptr&) noexcept = default;
    guest_ptr(guest_ptr&&) noexcept = default;
    guest_ptr& operator=(guest_ptr&&) noexcept = default;

  private:
    std::shared_ptr<GuestMemoryMapping> mapping_;
    _Tp* buffer_;
    size_t length_;
};

#if 0
/**
 * 
 * @brief guest_ptr for array with a compile time length
 *
 * This template allows syntax like
 * @code{.cc}
 * guest_ptr<char[64]> ptr(gva);
 * @endcode
 *
 * @tparam _Tp The type of data
 * @tparam _Count The number of elements
 */
template <typename _Tp, size_t _Count, typename _AddressType>
class guest_ptr<_Tp[_Count], _AddressType> : public guest_ptr<_Tp[], _AddressType> {
  public:
    guest_ptr() : guest_ptr<_Tp[]>() {}
    guest_ptr(const GuestAddress& ga) : guest_ptr<_Tp[]>(_Count) {}

    guest_ptr(const guest_ptr&) noexcept = default;
    guest_ptr& operator=(const guest_ptr&) noexcept = default;
    guest_ptr(guest_ptr&&) noexcept = default;
    guest_ptr& operator=(guest_ptr&&) noexcept = default;
};

#endif

template <typename _CharType>
inline guest_ptr<_CharType[]> make_guest_str(const GuestAddress& ga, size_t max_length = 0xFFFF) {
    std::shared_ptr<GuestMemoryMapping> mapping;
    std::size_t bytes_available = PageDirectory::PAGE_SIZE - ga.page_offset();
    std::size_t chars_available = bytes_available / sizeof(_CharType);

    if constexpr (sizeof(_CharType) > 1) {
        if (unlikely(chars_available == 0)) {
            // Not enough space for even one element. Can happen if the type is more than one byte.
            bytes_available += PageDirectory::PAGE_SIZE;
            chars_available = bytes_available / sizeof(_CharType);
        }
    }

    // Scan for a null pointer
    size_t offset = 0;
    _CharType* buffer = nullptr;

    do {
        // Perform the mapping, and loop until we can find a null
        mapping = std::make_shared<GuestMemoryMapping>(ga.map(bytes_available));

        // Get the page
        uint8_t* const buf = reinterpret_cast<uint8_t*>(mapping->get());

        // Offset into the page and cast to our type
        buffer = reinterpret_cast<_CharType*>(buf + ga.page_offset());

        // Look for a null byte, starting at our offset
        while (offset < chars_available) {
            if (buffer[offset] == 0)
                goto done;

            // If we've hit the size limit, exit early
            if (unlikely(++offset >= max_length)) {
                goto done;
            }
        }

        // We didn't find a null character, map more data
        bytes_available += PageDirectory::PAGE_SIZE;
        chars_available = bytes_available / sizeof(_CharType);
    } while (true);

done:
    return guest_ptr<_CharType[]>(std::move(mapping), buffer, offset);
}

/**
 * @brief Helper function for map_guest_str<char>
 *
 * @param ga The starting address of the string
 * @param max_length The maximum number of char values to map
 */
inline guest_ptr<char[]> map_guest_cstr(const GuestAddress& ga, size_t max_length = 0xFFFF) {
    return make_guest_str<char>(ga);
}

/**
 * @brief Helper function for map_guest_str<char16_t>
 *
 * @param ga The starting address of the string
 * @param max_length The maximum number of char16_t values to map
 */
inline guest_ptr<char16_t[]> map_guest_wstr(const GuestAddress& ga, size_t max_length = 0xFFFF) {
    return make_guest_str<char16_t>(ga);
}

} // namespace introvirt
