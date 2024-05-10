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

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <algorithm>
#include <string_view>
#include <type_traits>
#include <optional>

namespace introvirt {
namespace inject {

// GuestAllocation for single objects
template <typename _Tp>
class GuestAllocation {
    using pointer_type = typename guest_ptr<_Tp>::pointer_type;

  public:
    static_assert(std::is_pod_v<_Tp>, "GuestAllocation types must be POD if not specialized");

    /**
     * @brief Get the underlying address
     */
    uint64_t address() const { return ptr_.address(); }

    /**
     * @brief Transparently decay into a guest_ptr<_Tp>
     */
    operator const guest_ptr<_Tp> &() const { return ptr_; }

    /**
     * @brief Transparently decay into a guest_ptr<void>
     */
    operator guest_ptr<void>() const { return ptr_; }

    /**
     * @brief Get a copy of the underlying pointer
     *
     * @return guest_ptr<_Tp>
     */
    const guest_ptr<_Tp>& ptr() const { return ptr_; }

    /**
     * @brief Release this memory from management
     *
     * This can be used to keep memory in the guest permanently.
     * You are essentially causing a memory leak in the guest
     * process by calling this, so be careful.
     *
     * @return guest_ptr<_Tp> containing the mapping
     */
    guest_ptr<_Tp> release() {
        guest_ptr<_Tp> result(ptr_);
        ptr_.reset();
        region_size_ = 0;
        return result;
    }

    /**
     * @brief GuestAllocation array constructor
     *
     * @param length The number of elements in the array
     */
    template <typename Tp = _Tp, typename std::enable_if_t<std::is_array_v<Tp>>* dummy = nullptr>
    explicit GuestAllocation(size_t length) {
        static_assert(_is_array(), "Only array types require a runtime length");

        auto& domain = Domain::thread_local_domain();
        guest_ = domain.guest();
        introvirt_assert(guest_ != nullptr, "");
        region_size_ = sizeof(std::remove_all_extents_t<_Tp>) * length;

        // allocate will round up region_size_
        ptr_.reset(guest_->allocate(region_size_), length);
    }

    template <typename... _Args, typename Tp = _Tp,
              typename std::enable_if_t<!std::is_array_v<Tp>>* dummy = nullptr>
    explicit GuestAllocation(_Args&&... __args) {
        static_assert(!_is_array(), "Array types require a runtime length");

        auto& domain = Domain::thread_local_domain();
        guest_ = domain.guest();
        introvirt_assert(guest_ != nullptr, "");
        region_size_ = sizeof(_Tp);

        // allocate will round up region_size_
        ptr_.reset(guest_->allocate(region_size_));

        // Assign the value to the pointer
        *ptr_ = _Tp(std::forward<_Args>(__args)...);
    }

    ~GuestAllocation() {
        if (region_size_ != 0) {
            guest_->guest_free(ptr_, region_size_);
        }
    }

    GuestAllocation(const GuestAllocation&) = delete;
    GuestAllocation& operator=(const GuestAllocation&) = delete;

    GuestAllocation(GuestAllocation&& src) noexcept
        : guest_(src.guest_), ptr_(std::move(src.ptr_)), region_size_(src.region_size_) {

        src.region_size_ = 0;
    }
    GuestAllocation& operator=(GuestAllocation&& src) noexcept {
        guest_ = src.guest_;
        ptr_ = std::move(src.ptr_);
        region_size_ = src.region_size_;

        src.region_size_ = 0;
    }

  protected:
    static constexpr bool _is_array() { return std::is_array_v<_Tp>; }

    Guest* guest_;
    guest_ptr<_Tp> ptr_;
    size_t region_size_;
};

// allocate for single objects
template <typename _Tp, typename... _Args>
inline GuestAllocation<_Tp> allocate(_Args&&... args) {
    return GuestAllocation<_Tp>(std::forward<_Args>(args)...);
}

// allocate for arrays with runtime lengths
template <typename _Tp>
inline GuestAllocation<_Tp> allocate(size_t num) {
    return GuestAllocation<_Tp>(num);
}

// Special wrapper for strings
inline auto allocate(std::string_view str) {
    // Allocate length + 1 for the null terminator
    auto result = allocate<char[]>(str.length() + 1);
    auto& ptr = result.ptr();

    // Copy the string and null terminate it
    std::copy(str.begin(), str.end(), ptr.begin());
    ptr[str.length()] = '\0';

    return result;
}

// Special wrapper for utf16 strings
inline auto allocate(std::u16string_view str) {
    // Allocate length + 1 for the null terminator
    auto result = allocate<char16_t[]>(str.length() + 1);
    auto& ptr = result.ptr();

    // Copy the string and null terminate it
    std::copy(str.begin(), str.end(), ptr.begin());
    ptr[str.length()] = '\0';

    return result;
}

template <typename _Tp>
class GuestAllocationComplexBase {
    static_assert(!std::is_array_v<_Tp>, "Arrays of this type are not supported");

  public:
    operator _Tp*() { return value_.get(); }
    _Tp& operator*() { return *value_; }
    _Tp* get() { return value_.get(); }
    _Tp* operator->() { return value_.get(); }

    uint64_t address() const { return ptr().address(); }

    guest_ptr<void> ptr() const { return allocation_->ptr(); }
    operator guest_ptr<void>() const { return allocation_->ptr(); }

    GuestAllocationComplexBase() = default;
    GuestAllocationComplexBase(const GuestAllocationComplexBase&) = delete;
    GuestAllocationComplexBase& operator=(const GuestAllocationComplexBase&) = delete;

  protected:
    std::optional<GuestAllocation<uint8_t[]>> allocation_;
    std::shared_ptr<_Tp> value_;
};

} // namespace inject
} // namespace introvirt