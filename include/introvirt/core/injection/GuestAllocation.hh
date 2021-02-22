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
#include <cassert>
#include <string_view>
#include <type_traits>

namespace introvirt {
namespace inject {

// GuestAllocation for single objects
template <typename _Tp>
class GuestAllocation {
  public:
    static_assert(std::is_pod_v<_Tp>, "GuestAllocation types must be POD if not specialized");

    /**
     * @brief Get the address of the buffer
     *
     * @return A pointer to the first element in the array
     */
    _Tp* get() { return ptr_.get(); }

    /**
     * @copydoc GuestAllocation<T>::get()
     */
    const _Tp* get() const { return ptr_.get(); }

    /**
     * @brief Dereference the first element in the array
     *
     * @return The dereferenced value
     */
    _Tp& operator*() { return *ptr_; }

    /**
     * @copydoc GuestAllocation<T>::operator*()
     */
    const _Tp& operator*() const { return *ptr_; }

    /**
     * @brief Overload for accessing the allocation like a pointer
     *
     * @return A pointer to the first element in the array
     */
    _Tp* operator->() { return ptr_; }

    /**
     * @copydoc GuestAllocation<T>::operator->()
     */
    const _Tp* operator->() const { return ptr_; }

    /**
     * @brief Implicit conversion to pointer type
     */
    operator _Tp*() { return ptr_.get(); }

    /**
     * @copydoc GuestAllocation<T>::operator _Tp*()
     */
    operator const _Tp*() const { return ptr_.get(); }

    /**
     * @brief Transparently decay into a GuestVirtualAddress
     *
     * @return GuestVirtualAddress
     */
    operator GuestVirtualAddress() const { return base_address_; }

    GuestVirtualAddress address() const { return base_address_; }

    /**
     * @brief Release this memory from management
     *
     * This can be used to keep memory in the guest permanently.
     * You are essentially causing a memory leak in the guest
     * process by calling this, so be careful.
     *
     * @return guest_ptr<T[]> containing the mapping
     */
    guest_ptr<_Tp> release() {
        base_address_ = GuestVirtualAddress();
        region_size_ = 0;

        guest_ptr<_Tp> result = ptr_;
        ptr_.reset();
        return result;
    }

    template <typename... _Args>
    explicit GuestAllocation(_Args&&... __args) {
        auto& domain = Domain::thread_local_domain();

        guest_ = domain.guest();
        assert(guest_ != nullptr);

        region_size_ = sizeof(_Tp);

        // This will round up region_size_
        base_address_ = guest_->allocate(region_size_);

        // Map it in
        ptr_.reset(base_address_);

        // Assign the value to the value
        *ptr_ = _Tp(std::forward<_Args>(__args)...);
    }

    ~GuestAllocation() {
        if (likely(region_size_ != 0))
            guest_->guest_free(base_address_, region_size_);
    }

    GuestAllocation(const GuestAllocation&) = delete;
    GuestAllocation& operator=(const GuestAllocation&) = delete;

    GuestAllocation(GuestAllocation&& src) noexcept {
        guest_ = src.guest_;
        ptr_ = std::move(src.ptr_);
        base_address_ = std::move(src.base_address_);
        region_size_ = src.region_size_;

        src.array_.reset();
        src.base_address_ = NullGuestAddress();
        src.region_size_ = 0;
    }

    GuestAllocation& operator=(GuestAllocation&& src) noexcept {
        guest_ = src.guest_;
        ptr_ = std::move(src.ptr_);
        base_address_ = std::move(src.base_address_);
        region_size_ = src.region_size_;

        src.array_.reset();
        src.base_address_ = NullGuestAddress();
        src.region_size_ = 0;
        return *this;
    }

  protected:
    Guest* guest_;
    guest_ptr<_Tp> ptr_;
    GuestVirtualAddress base_address_;
    size_t region_size_;
};

// GuestAllocation for array with a runtime length
template <typename _Tp>
class GuestAllocation<_Tp[]> {
  public:
    static_assert(std::is_pod_v<_Tp>, "GuestAllocation types must be POD if not specialized");

    /**
     * @brief Get the begin iterator
     *
     * This is for using c++11-style for-loops over the array
     *
     * @return The beginning iterator of the array
     */
    inline _Tp* begin() { return array_.begin(); }

    /**
     * @brief Get the begin iterator
     *
     * This is for using c++11-style for-loops over the array
     *
     * @return The beginning iterator of the array
     */
    inline const _Tp* begin() const { return array_.begin(); }

    /**
     * @brief Get the end iterator for the array
     *
     * This is for using c++11-style for-loops over the array
     *
     * @return The end iterator of the array
     */
    inline _Tp* end() { return array_.end(); }

    /**
     * @brief Get the end iterator for the array
     *
     * This is for using c++11-style for-loops over the array
     *
     * @return The end iterator of the array
     */
    inline const _Tp* end() const { return array_.end(); }

    /**
     * @brief Get the address of the buffer
     *
     * @return A pointer to the first element in the array
     */
    _Tp* get() { return array_.get(); }

    /**
     * @copydoc GuestAllocation<T>::get()
     */
    const _Tp* get() const { return array_.get(); }

    /**
     * @brief Accessor for an element at a specific position in the array
     *
     * @param index The index into the array
     * @return The element at the specified index
     */
    _Tp& at(size_t index) { return array_.at(index); }

    /**
     * @copydoc GuestAllocation<T>::at(size_t)
     */
    const _Tp& at(size_t index) const { return array_.at(index); }

    /**
     * @brief Accessor for an element at a specific position in the array
     *
     * @param index The index into the array
     * @return The element at the specified index
     */
    _Tp& operator[](size_t index) { return array_[index]; }

    /**
     * @copydoc GuestAllocation<T>::operator[](size_t)
     */
    const _Tp& operator[](size_t index) const { return array_[index]; }

    /**
     * @brief Release this memory from management
     *
     * This can be used to keep memory in the guest permanently.
     * You are essentially causing a memory leak in the guest
     * process by calling this, so be careful.
     *
     * @return guest_ptr<T[]> containing the mapping
     */
    guest_ptr<_Tp[]> release() {
        base_address_ = GuestVirtualAddress();
        region_size_ = 0;

        guest_ptr<_Tp[]> result = array_;
        array_.reset();
        return result;
    }

    /**
     * @brief GuestAllocation array constructor
     *
     * @param count The number of elements in the array
     */
    explicit GuestAllocation(size_t count) {
        auto& domain = Domain::thread_local_domain();

        guest_ = domain.guest();
        assert(guest_ != nullptr);

        region_size_ = sizeof(_Tp) * count;

        // This will round up region_size_
        base_address_ = guest_->allocate(region_size_);

        // Map it in
        array_.reset(base_address_, count);
    }

    ~GuestAllocation() {
        if (likely(region_size_ != 0))
            guest_->guest_free(base_address_, region_size_);
    }

    /**
     * @brief Implicit conversion to pointer type
     */
    operator _Tp*() { return array_.get(); }

    /**
     * @copydoc GuestAllocation<T[_Size]>::operator _Tp*()
     */
    operator const _Tp*() const { return array_.get(); }

    /**
     * @brief Transparently decay into a GuestVirtualAddress
     *
     * @return GuestVirtualAddress
     */
    operator GuestVirtualAddress() const { return base_address_; }

    GuestVirtualAddress address() const { return base_address_; }

    GuestAllocation(const GuestAllocation&) = delete;
    GuestAllocation& operator=(const GuestAllocation&) = delete;

    GuestAllocation(GuestAllocation&& src) noexcept {
        guest_ = src.guest_;
        array_ = std::move(src.array_);
        base_address_ = std::move(src.base_address_);
        region_size_ = src.region_size_;

        src.array_.reset();
        src.base_address_ = NullGuestAddress();
        src.region_size_ = 0;
    }
    GuestAllocation& operator=(GuestAllocation&& src) noexcept {
        guest_ = src.guest_;
        array_ = std::move(src.array_);
        base_address_ = std::move(src.base_address_);
        region_size_ = src.region_size_;

        src.array_.reset();
        src.base_address_ = NullGuestAddress();
        src.region_size_ = 0;
        return *this;
    }

  protected:
    Guest* guest_;
    guest_ptr<_Tp[]> array_;
    GuestVirtualAddress base_address_;
    size_t region_size_;
};

// GuestAllocation for array with a compile time length
template <typename _Tp, size_t _Count>
class GuestAllocation<_Tp[_Count]> : public GuestAllocation<_Tp[]> {
  public:
    explicit GuestAllocation() : GuestAllocation<_Tp[]>(_Count) {}
};

template <typename _Tp>
struct _GuestAllocate {
    typedef GuestAllocation<_Tp> __single_object;
};

template <typename _Tp>
struct _GuestAllocate<_Tp[]> {
    typedef GuestAllocation<_Tp[]> __array;
};

template <typename _Tp, size_t _Bound>
struct _GuestAllocate<_Tp[_Bound]> {
    struct __invalid_type {};
};

// allocate for single objects
template <typename _Tp, typename... _Args>
inline typename _GuestAllocate<_Tp>::__single_object allocate(_Args&&... __args) {
    return GuestAllocation<_Tp>(std::forward<_Args>(__args)...);
}

// allocate for arrays of unknown bound
template <typename _Tp>
inline typename _GuestAllocate<_Tp>::__array allocate(size_t __num) {
    return GuestAllocation<_Tp>(__num);
}

// Disable allocate for arrays of known bound
template <typename _Tp, typename... _Args>
inline typename _GuestAllocate<_Tp>::__invalid_type allocate(_Args&&...) = delete;

// Special wrapper for strings
inline auto allocate(std::string_view str) {
    // Allocate length + 1 for the null terminator
    auto result = allocate<char[]>(str.length() + 1);

    // Copy the string and null terminate it
    std::copy(str.begin(), str.end(), result.begin());
    result[str.length()] = '\0';

    return result;
}

template <typename _Tp>
class GuestAllocationComplexBase {
  public:
    _Tp* get() { return value_.get(); }
    const _Tp* get() const { return value_.get(); }

    _Tp& operator*() { return *value_; }
    const _Tp& operator*() const { return *value_; }

    _Tp* operator->() { return value_.get(); }
    const _Tp* operator->() const { return value_.get(); }

    operator _Tp*() { return value_.get(); }
    operator const _Tp*() const { return value_.get(); }

    GuestVirtualAddress address() const { return value_->address(); }
    operator GuestVirtualAddress() const { return value_->address(); }

    GuestAllocationComplexBase() = default;
    GuestAllocationComplexBase(const GuestAllocationComplexBase&) = delete;
    GuestAllocationComplexBase& operator=(const GuestAllocationComplexBase&) = delete;

  protected:
    std::unique_ptr<_Tp> value_;
};

} // namespace inject
} // namespace introvirt