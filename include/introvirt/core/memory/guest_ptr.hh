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
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/fwd.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/util/introvirt_assert.hh>
#include <introvirt/util/n2hexstr.hh>
#include <introvirt/windows/common/Utf16String.hh>

#include <cstdint>
#include <ostream>
#include <string_view>

namespace introvirt {

// Optionally have a page_directory if not a physical address
template <bool _Physical>
class basic_guest_ptr_members_page_dir {
  protected:
    uint64_t page_directory_;
};
template <>
class basic_guest_ptr_members_page_dir<true> {
  protected:
};

// Optionally have a length, only if the type is an array
template <bool _Array>
class basic_guest_ptr_members_length {
  protected:
};
template <>
class basic_guest_ptr_members_length<true> {
  protected:
    size_t length_;
};

template <typename _Tp, bool _Physical, bool _Array, typename _Enable = void>
class basic_guest_ptr_members : public basic_guest_ptr_members_page_dir<_Physical>,
                                public basic_guest_ptr_members_length<_Array> {
  protected:
    const Domain* domain_;
    uint64_t address_;
    std::shared_ptr<GuestMemoryMapping> mapping_;
    _Tp* buffer_;
};

// Variants for when we're a guest_size_t/guest_ptr_t wrapper
template <typename _Tp, bool _Physical>
class basic_guest_ptr_members<_Tp, _Physical, false, std::enable_if_t<is_guest_size_v<_Tp>>> {
  protected:
    mutable basic_guest_ptr<guest_ptr_t, void, _Physical> ptr_;
};
template <typename _Tp, bool _Physical>
class basic_guest_ptr_members<_Tp, _Physical, true, std::enable_if_t<is_guest_size_v<_Tp>>> {
  protected:
    mutable basic_guest_ptr<guest_ptr_t[], void, _Physical> ptr_;
};

/*
 * Common base class for guest_ptr and guest_phys_ptr
 */
template <typename _Tp, typename _PtrType, bool _Physical, typename _Enabled>
class basic_guest_ptr : public basic_guest_ptr_members<
                            std::conditional_t<std::is_pointer_v<std::remove_extent_t<_Tp>>,
                                               _PtrType, std::remove_all_extents_t<_Tp>>,
                            _Physical, std::is_array_v<_Tp>> {

  public:
    using basic_type = typename std::remove_pointer_t<std::remove_extent_t<_Tp>>;
    using array_element_type = std::remove_extent_t<_Tp>;
    using pointer_type = typename std::add_pointer_t<basic_type>;
    using ref_type = typename std::add_lvalue_reference_t<basic_type>;

    static constexpr bool _is_array_v = std::is_array_v<_Tp>;
    static constexpr bool _is_pointer_v = std::is_pointer_v<array_element_type>;
    static constexpr bool _is_ppointer_v =
        std::is_pointer_v<std::remove_pointer_t<array_element_type>>;
    static constexpr bool _is_void_v = std::is_void_v<basic_type>;
    static constexpr bool _is_void_ptr = std::is_void_v<basic_type> && _is_pointer_v;
    static constexpr bool _is_non_guest_ptr_t_v = _is_pointer_v && !is_guest_size_v<_PtrType>;
    static constexpr bool _is_guest_ptr_t_v = _is_pointer_v && is_guest_size_v<_PtrType>;
    static constexpr bool _is_access_allowed = !_is_void_v || _is_void_ptr;

    using outptr_type =
        basic_guest_ptr<basic_type, std::conditional_t<_is_ppointer_v, _PtrType, void>, _Physical>;

    // Sanity checks
    static_assert(!std::is_array_v<std::remove_extent_t<_Tp>>,
                  "Multidimensional arrays are not allowed");
    static_assert(!std::is_reference_v<basic_type>, "Reference types are not allowed");
    static_assert(!_is_pointer_v || !std::is_void_v<_PtrType>,
                  "_PtrType must be specified for nested pointers");
    static_assert(_is_void_v || std::is_pod_v<_Tp>,
                  "guest_ptr types must be plain old data or void");
    static_assert(!(_is_array_v && _is_void_v && !_is_pointer_v), "void[] is not allowed");

    // TODO -- Fix this vvv
    static_assert(!std::is_pointer_v<_PtrType>, "_PtrType must be uint32_t, uint64_t, or "
                                                "guest_ptr_t");

    /// Functions for getting the underlying address
    inline uint64_t address() const {
        if constexpr (_is_guest_ptr_t_v) {
            return this->ptr_.address();
        } else {
            return this->address_;
        }
    }
    inline uint64_t page_mask() const { return address() & PageDirectory::PAGE_MASK; }
    inline uint64_t page_number() const { return address() >> PageDirectory::PAGE_SHIFT; }
    inline uint64_t page_offset() const { return address() & ~PageDirectory::PAGE_MASK; }
    inline uint64_t page_directory() const {
        static_assert(!_Physical, "page_directory() is only valid for virtual addresses");
        if constexpr (_is_guest_ptr_t_v) {
            return this->ptr_.page_directory();
        } else {
            return this->page_directory_;
        }
    }

    // Get the domain associcated with this pointer
    inline const Domain& domain() const {
        // The pointer must be initialized!
        if constexpr (_is_guest_ptr_t_v) {
            return this->ptr_.domain();
        } else {
            introvirt_assert(this->domain_ != nullptr, "");
            return *(this->domain_);
        }
    }
    inline size_t length() const {
        static_assert(_is_array_v, "length() is only valid on array types");
        if constexpr (_is_guest_ptr_t_v) {
            return this->ptr_.length();
        } else {
            return this->length_;
        }
    }
    inline decltype(auto) operator[](size_t index) const {
        static_assert(_is_array_v, "operator[] is only valid on arrays");
        introvirt_assert(*this, "operator[](size_t) called on null guest_ptr");
        return this->at(index);
    }

    /// Operators regardless of the underlying type
    inline decltype(auto) operator*() const {
        static_assert(_is_access_allowed, "operator*() is not valid for void");
        introvirt_assert(*this, "Tried to dereference while null");

        if constexpr (_is_pointer_v) {
            // Return a copy
            return get();
        } else {
            // Return a reference.
            // The parenthesis are decltype(auto) magic
            return (*get());
        }
    }
    inline auto operator->() const {
        static_assert(_is_access_allowed, "operator->() is not valid for void");
        introvirt_assert(*this, "Tried to dereference while null");
        return get();
    }

  private:
    inline decltype(auto) _get_size_t_ptr(size_t index) const {
        static_assert(_is_guest_ptr_t_v,
                      "_get_size_t_ptr(size_t) should only be called for _is_guest_ptr_t_v");

        // Construct a new pointer to return based on the value we hold
        // Return a nullptr if we're null.
        outptr_type result;
        if (*this) {
            // Create a new pointer based on this one, with the new address
            result._domain(&(this->ptr_.domain()));
            result._mapping(this->ptr_._mapping());
            if constexpr (!_Physical) {
                result._page_directory(this->ptr_.page_directory());
            }
            // Read the address we're holding in our guest_ptr_t pointer
            if constexpr (_is_array_v) {
                result.reset(this->ptr_[index]);
            } else {
                result.reset(*this->ptr_);
            }
        }
        return result;
    }

    inline decltype(auto) _get_non_size_t_ptr(size_t index) const {
        static_assert(_is_non_guest_ptr_t_v,
                      "_get_ptr(size_t) should only be called for _is_non_guest_ptr_t_v");

        // Construct a new pointer to return based on the value we hold
        // Return a nullptr if we're null.
        outptr_type result;
        if (*this) {
            // Create a new pointer based on this one, with the new address
            result.domain_ = this->domain_;
            result.mapping_ = this->mapping_;
            if constexpr (!_Physical) {
                result.page_directory_ = this->page_directory_;
            }
            // Read the address we're holding
            if constexpr (_is_array_v) {
                // at(index) is only available if _is_array_v,
                // so we don't have to worry about this assert on non-arrays
                introvirt_assert(index < this->length_, "Tried to access array out of bounds");
            }
            result.reset(this->buffer_[index]);
        }
        return result;
    }

    inline auto _get_ptr(size_t index) const {
        if constexpr (_is_guest_ptr_t_v) {
            return this->_get_size_t_ptr(index);
        } else {
            return this->_get_non_size_t_ptr(index);
        }
    }

  public:
    inline auto get() const {
        // Unlike any other accessor, this can return a null value
        static_assert(_is_access_allowed, "Get is not available for void");
        if constexpr (_is_pointer_v) {
            return _get_ptr(0);
        } else {
            return this->buffer_;
        }
    }

    inline decltype(auto) at(size_t index) const {
        static_assert(_is_access_allowed, "at() is not available for void");
        static_assert(_is_array_v, "at() is only valid on arrays");
        introvirt_assert(*this, "at(size_t) called on null guest_ptr");

        if constexpr (_is_pointer_v) {
            return _get_ptr(index);
        } else if constexpr (_is_array_v) {
            // Parens are for decltype(auto)
            // Makes it return it as a reference
            introvirt_assert(index < this->length_, "Tried to access array out of bounds");
            return (this->buffer_[index]);
        }
    }

    /// Setter methods
    template <
        typename U = _Tp, typename type = array_element_type,
        typename std::enable_if_t<!std::is_void_v<U> && !std::is_pointer_v<U>>* dummy = nullptr>
    inline void set(type value) const {
        // Non-pointer set method
        static_assert(_is_access_allowed, "set() is not available for void");
        static_assert(!_is_array_v, "set() requires an index for arrays");
        introvirt_assert(*this, "set(index) called on null guest_ptr");
        *this->buffer_ = value;
    }
    template <
        typename U = _Tp, typename type = array_element_type,
        typename std::enable_if_t<!std::is_void_v<U> && !std::is_pointer_v<U>>* dummy = nullptr>
    inline void set(size_t index, type value) const {
        // Non-pointer array set method
        static_assert(_is_access_allowed, "set() is not available for void");
        static_assert(_is_array_v, "set(index, value) is only valid on arrays");
        introvirt_assert(*this, "set(index, value) called on null guest_ptr");
        introvirt_assert(index < this->length_, "Tried to access array out of bounds");
        this->buffer_[index] = value;
    }
    template <typename U = array_element_type, typename PtrType = _PtrType, typename InTp,
              typename InPtrType, typename std::enable_if_t<std::is_pointer_v<U>>* dummy = nullptr>
    inline void set(const basic_guest_ptr<InTp, InPtrType, _Physical>& in) const {
        // Pointer set method
        static_assert(_is_access_allowed, "set() is not available for void");
        static_assert(!_is_array_v, "index must be provided for non-arrays");
        introvirt_assert(*this, "Tried to set while null");
        if constexpr (_is_guest_ptr_t_v) {
            // Set the value in our wrapped pointer
            this->ptr_.set(in.address());
        } else {
            *this->buffer_ = in.address();
        }
    }
    template <typename U = array_element_type, typename PtrType = _PtrType, typename InTp,
              typename InPtrType, typename std::enable_if_t<std::is_pointer_v<U>>* dummy = nullptr>
    inline void set(size_t index, const basic_guest_ptr<InTp, InPtrType, _Physical>& in) const {
        // Pointer array set method
        static_assert(_is_access_allowed, "set() is not available for void");
        static_assert(_is_array_v, "set(index, ptrval) is only valid on arrays");
        introvirt_assert(*this, "Tried to set while null");
        if constexpr (_is_guest_ptr_t_v) {
            // Set the value in our wrapped pointer
            this->ptr_.set(index, in.address());
        } else {
            *this->buffer_[index] = in.address();
        }
    }

    /// Implicit conversion operators
    template <typename U = _Tp, typename std::enable_if_t<!std::is_void_v<U> &&
                                                          !std::is_pointer_v<U>>* dummy = nullptr>
    inline operator pointer_type() const {
        // Automatically decay into pointer type we hold
        return this->buffer_;
    }

    /// Array operations for non-pointer types
    template <typename U = _Tp, typename std::enable_if_t<!std::is_pointer_v<U>>* dummy = nullptr>
    inline pointer_type begin() const {
        static_assert(_is_array_v, "begin() is only valid on array types");
        return this->buffer_;
    }
    template <typename U = _Tp, typename std::enable_if_t<!std::is_pointer_v<U>>* dummy = nullptr>
    inline pointer_type end() const {
        static_assert(_is_array_v, "end() is only valid on array types");
        return this->buffer_ + this->length_;
    }

    /// Default constructor and null reset
    basic_guest_ptr() { this->reset(); }

    void reset() {
        if constexpr (!_is_guest_ptr_t_v) {
            this->mapping_.reset();
            this->buffer_ = nullptr;
            this->domain_ = nullptr;
            this->address_ = 0;
            if constexpr (_Physical == false) {
                this->page_directory_ = 0;
            }
            if constexpr (_is_array_v) {
                this->length_ = 0;
            }
        } else if constexpr (_is_guest_ptr_t_v) {
            this->ptr_.reset();
        }
    }

    /// Special constructor to automatically create from nullptr
    basic_guest_ptr(std::nullptr_t) { this->reset(); }

    /// Special constructor to create guest_phys_ptr from guest_ptr
    template <bool Physical = _Physical, typename InPtrType,
              typename std::enable_if_t<Physical>* dummy = nullptr>
    basic_guest_ptr(const basic_guest_ptr<_Tp, InPtrType, false>& in) {
        static_assert(!_is_array_v && (_is_void_v || sizeof(_Tp) == 1),
                      "Only void or 1-byte conversions from virtual to physical are supported");

        this->_copy(in);
    }

    /// Special constructor and reset for guest_ptr_t variant
    template <bool is_guest_ptr_t_v = _is_guest_ptr_t_v, typename... Arguments,
              typename std::enable_if_t<is_guest_ptr_t_v>* dummy = nullptr>
    basic_guest_ptr(bool x64, Arguments&&... args) {
        this->ptr_.reset(x64, std::forward<Arguments>(args)...);
    }
    template <bool is_guest_ptr_t_v = _is_guest_ptr_t_v, typename... Arguments,
              typename std::enable_if_t<is_guest_ptr_t_v>* dummy = nullptr>
    void reset(bool x64, Arguments&&... args) {
        this->ptr_.reset(x64, std::forward<Arguments>(args)...);
    }

    /// Physical pointer constructors
    // Single fully specified
    template <bool is_array = _is_array_v,
              typename std::enable_if_t<!is_array && _Physical>* dummy = nullptr>
    basic_guest_ptr(const Domain& domain, uint64_t address) {
        this->domain_ = &domain;
        this->_reset(address);
    }
    template <bool is_array = _is_array_v,
              typename std::enable_if_t<!is_array && _Physical>* dummy = nullptr>
    void reset(const Domain& domain, uint64_t address) {
        if (this->domain_ != &domain) {
            this->domain_ = &domain;
            this->mapping_.reset();
        }
        this->_reset(address);
    }
    // Array fully specified
    template <bool is_array = _is_array_v,
              typename = typename std::enable_if_t<is_array && _Physical>>
    basic_guest_ptr(const Domain& domain, uint64_t address, size_t length) {
        this->domain_ = &domain;
        this->_reset(address, length);
    }
    template <bool is_array = _is_array_v,
              typename = typename std::enable_if_t<is_array && _Physical>>
    void reset(const Domain& domain, uint64_t address, size_t length) {
        if (this->domain_ != &domain) {
            this->domain_ = &domain;
            this->mapping_.reset();
        }
        this->_reset(address, length);
    }

    /// Virtual pointer constructors and reset methods
    // Single fully specified
    template <bool is_array = _is_array_v,
              typename std::enable_if_t<!is_array && !_Physical>* dummy = nullptr>
    basic_guest_ptr(const Domain& domain, uint64_t address, uint64_t page_directory) {
        this->domain_ = &domain;
        this->page_directory_ = page_directory;
        this->_reset(address);
    }
    template <bool is_array = _is_array_v,
              typename std::enable_if_t<!is_array && !_Physical>* dummy = nullptr>
    void reset(const Domain& domain, uint64_t address, uint64_t page_directory) {
        if (this->domain_ != &domain || this->page_directory_ != page_directory) {
            this->domain_ = &domain;
            this->page_directory_ = page_directory;
            this->mapping_.reset();
        }
        this->_reset(address);
    }
    // Array fully specified
    template <bool is_array = _is_array_v,
              typename std::enable_if_t<is_array && !_Physical>* dummy = nullptr>
    basic_guest_ptr(const Domain& domain, uint64_t address, uint64_t page_directory,
                    size_t length) {
        this->domain_ = &domain;
        this->page_directory_ = page_directory;
        this->_reset(address, length);
    }
    template <bool is_array = _is_array_v,
              typename std::enable_if_t<is_array && !_Physical>* dummy = nullptr>
    void reset(const Domain& domain, uint64_t address, uint64_t page_directory, size_t length) {
        if (this->domain_ != &domain || this->page_directory_ != page_directory) {
            this->domain_ = &domain;
            this->page_directory_ = page_directory;
            this->mapping_.reset();
        }
        this->_reset(address, length);
    }

    /// Helper constructor and reset using a vcpu
    // Single
    basic_guest_ptr(const Vcpu& vcpu, uint64_t address) { this->reset(vcpu, address); }
    void reset(const Vcpu& vcpu, uint64_t address) {
        static_assert(!_is_array_v, "reset() requires a length for arrays");
        if constexpr (_Physical) {
            this->reset(vcpu.domain(), address);
        } else {
            this->reset(vcpu.domain(), address, vcpu.registers().cr3());
        }
    }
    // Array
    basic_guest_ptr(const Vcpu& vcpu, uint64_t address, size_t length) {
        this->reset(vcpu, address, length);
    }
    void reset(const Vcpu& vcpu, uint64_t address, size_t length) {
        static_assert(_is_array_v, "reset() only requires a length for arrays");
        if constexpr (_Physical) {
            this->reset(vcpu.domain(), address, length);
        } else {
            this->reset(vcpu.domain(), address, vcpu.registers().cr3(), length);
        }
    }

    /// Helper reset methods specifying only an address (and length for arrays)
    // Single
    void reset(uint64_t address) {
        static_assert(!_is_array_v, "reset() requires a length for arrays");
        if constexpr (!_is_guest_ptr_t_v) {
            introvirt_assert(this->domain_, "Reset called with a null domain");
            if constexpr (_Physical == false) {
                introvirt_assert(this->page_directory_, "Reset called with null page directory");
            }
        }
        this->_reset(address);
    }
    // Array
    void reset(uint64_t address, size_t length) {
        static_assert(_is_array_v, "reset() only requires a length for arrays");
        if constexpr (!_is_guest_ptr_t_v) {
            introvirt_assert(this->domain_, "Reset called with a null domain");
            if constexpr (_Physical == false) {
                introvirt_assert(this->page_directory_, "Reset called with null page directory");
            }
        }
        this->_reset(address, length);
    }

    /// Copy and move constructors/assignments and reset methods
    // Copy
    template <typename Tp, typename PtrType>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>(
        const basic_guest_ptr<Tp, PtrType, _Physical>& in) {
        // Single
        this->_copy(in);
    }
    template <typename Tp, typename PtrType>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>(
        // Array
        const basic_guest_ptr<Tp, PtrType, _Physical>& in, size_t length) {
        static_assert(_is_array_v, "length parameter is only valid for arrays");
        this->_copy(in, length);
    }
    template <typename Tp, typename PtrType>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>&
    operator=(const basic_guest_ptr<Tp, PtrType, _Physical>& in) noexcept {
        this->_copy(in);
        return *this;
    }
    template <typename Tp, typename PtrType>
    void reset(const basic_guest_ptr<Tp, PtrType, _Physical>& in) {
        this->_copy(in);
    }
    template <typename Tp, typename PtrType>
    void reset(const basic_guest_ptr<Tp, PtrType, _Physical>& in, size_t length) {
        this->_copy(in, length);
    }
    // Move
    template <typename Tp, typename PtrType>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>(
        basic_guest_ptr<Tp, PtrType, _Physical>&& in) {
        // Single
        this->_move(std::move(in));
    }
    template <typename Tp, typename PtrType>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>(
        basic_guest_ptr<Tp, PtrType, _Physical>&& in, size_t length) {
        // Array
        static_assert(_is_array_v, "length parameter is only valid for arrays");
        this->_move(std::move(in), length);
    }
    template <typename Tp, typename PtrType>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>&
    operator=(basic_guest_ptr<Tp, PtrType, _Physical>&& in) noexcept {
        this->_move(std::move(in));
        return *this;
    }
    template <typename Tp, typename PtrType>
    void reset(basic_guest_ptr<Tp, PtrType, _Physical>&& in) {
        this->_move(std::move(in));
    }
    template <typename Tp, typename PtrType>
    void reset(basic_guest_ptr<Tp, PtrType, _Physical>&& in, size_t length) {
        this->_move(std::move(in), length);
    }

    /// Helper to create a new instance of this pointer
    basic_guest_ptr<void, void, _Physical, void> clone(uint64_t address) const {
        // Create a new void pointer using this pointer as context
        basic_guest_ptr<void, void, _Physical, void> result = *this;
        result.reset(address);
        return result;
    }

    /// Default constructors and copy/move operators
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>(
        const basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>&) noexcept = default;
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>&
    operator=(const basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>&) noexcept = default;
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>(
        basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>&&) noexcept = default;
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>&
    operator=(basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>&&) noexcept = default;

    /// Math operators

    // Prefix increment operator
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& operator++() { return operator+=(1); }
    // Postfix increment operator
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled> operator++(int) {
        basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled> result(*this);
        ++(*this);
        return result;
    }
    // Integer compound addition
    template <typename I>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& operator+=(I offset) {
        if constexpr (_is_guest_ptr_t_v) {
            this->ptr_ += offset;
        } else {
            _validate_valid_ptr();
            this->_reset(this->address_ + (offset * _element_size()));
        }
        return *this;
    }
    // Integer addition
    template <typename I>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled> operator+(I offset) const {
        _validate_valid_ptr();
        basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled> result = *this;
        result += offset;
        return result;
    }
    // Prefix decrement operator
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& operator--() { return operator-=(1); }
    // Postfix decrement operator
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled> operator--(int) {
        basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled> result(*this);
        --(*this);
        return result;
    }
    // Integer compound subtraction
    template <typename I>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& operator-=(I offset) {
        if constexpr (_is_guest_ptr_t_v) {
            this->ptr_ -= offset;
        } else {
            _validate_valid_ptr();
            this->_reset(this->address_ - (offset * _element_size()));
        }
        return *this;
    }
    // Integer subtraction
    template <typename I>
    basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled> operator-(I offset) const {
        _validate_valid_ptr();
        basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled> result = *this;
        result -= offset;
        return result;
    }

    // Pointer subtraction
    template <typename Tp, typename PtrType>
    ptrdiff_t operator-(const basic_guest_ptr<Tp, PtrType, _Physical>& in) const {
        _validate_valid_ptr();
        using NormalTp1 = std::remove_const_t<_Tp>;
        using NormalTp2 = std::remove_const_t<Tp>;
        static_assert(std::is_same_v<NormalTp1, NormalTp2>,
                      "Pointers must be of the same type for subtraction");

        return (this->address() - in.address()) / this->_element_size();
    }

    // Comparison operators
    explicit inline operator bool() const {
        if constexpr (_is_guest_ptr_t_v) {
            return this->ptr_.operator bool();
        } else {
            return this->address_ != 0;
        }
    }

    inline bool operator<(const basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& in) const {
        return this->address() < in.address();
    }
    inline bool operator<=(const basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& in) const {
        return this->address() <= in.address();
    }
    inline bool operator>(const basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& in) const {
        return this->address() > in.address();
    }
    inline bool operator>=(const basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& in) const {
        return this->address() >= in.address();
    }
    inline bool operator==(const basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& in) const {
        if constexpr (_Physical == false) {
            return (this->address() == in.address()) &&
                   (this->page_directory() == in.page_directory());
        } else {
            return (this->address() == in.address());
        }
    }
    inline bool operator!=(const basic_guest_ptr<_Tp, _PtrType, _Physical, _Enabled>& in) const {
        return !(*this == in);
    }

    // char
    template <typename U = std::remove_const_t<basic_type>,
              typename std::enable_if_t<_is_array_v && std::is_same_v<U, char>>* dummy = nullptr>
    operator std::string_view() const {
        return str();
    }
    template <typename U = std::remove_const_t<basic_type>,
              typename std::enable_if_t<std::is_same_v<U, char>>* dummy = nullptr>
    std::string_view str() const {
        static_assert(_is_array_v, "str() is only valid on char[]");
        return std::string_view(this->buffer_, this->length_);
    }

    // char16_t
    template <
        typename U = std::remove_const_t<basic_type>,
        typename std::enable_if_t<_is_array_v && std::is_same_v<U, char16_t>>* dummy = nullptr>
    operator std::u16string_view() const {
        return wstr();
    }
    template <typename U = std::remove_const_t<basic_type>,
              typename std::enable_if_t<std::is_same_v<U, char16_t>>* dummy = nullptr>
    std::u16string_view wstr() const {
        static_assert(_is_array_v, "wstr() is only valid on char16_t[]");
        return std::u16string_view(this->buffer_, this->length_);
    }
    template <typename U = std::remove_const_t<basic_type>,
              typename std::enable_if_t<std::is_same_v<U, char16_t>>* dummy = nullptr>
    std::string str() const {
        static_assert(_is_array_v, "str() is only valid on char16_t[]");
        return windows::Utf16String::convert(wstr());
    }

    // For normal types, print the pointer address
    template <typename U = std::remove_const_t<_Tp>,
              typename std::enable_if_t<(!std::is_same_v<U, char[]> &&
                                         !std::is_same_v<U, char16_t[]>)>* dummy = nullptr>
    inline std::ostream& write_stream(std::ostream& os) const {
        os << n2hexstr(address());
        return os;
    }

    // For char[] and char16_t[], print the actual string
    template <typename U = std::remove_const_t<_Tp>,
              typename std::enable_if_t<(std::is_same_v<U, char[]> ||
                                         std::is_same_v<U, char16_t[]>)>* dummy = nullptr>
    inline std::ostream& write_stream(std::ostream& os) const {
        os << str();
        return os;
    }

  protected:
    void _reconfigure_buffer() {
        if (this->mapping_) {
            char* const buf = reinterpret_cast<char*>(this->mapping_->get());
            const size_t buf_offset = this->address_ & ~PageDirectory::PAGE_MASK;
            if constexpr (_is_pointer_v) {
                this->buffer_ = reinterpret_cast<_PtrType*>(buf + buf_offset);
            } else {
                this->buffer_ = reinterpret_cast<pointer_type>(buf + buf_offset);
            }
        } else {
            this->buffer_ = nullptr;
        }
    }

    // Remap function for physical addresses
    template <bool Physical = _Physical, typename std::enable_if_t<Physical>* dummy = nullptr>
    void _remap() {
        // Calculate the number of pages required
        const uint64_t buffer_length = this->_buffer_length();
        const uint64_t first_pfn = this->page_number();
        const uint64_t last_pfn = (this->address_ + buffer_length - 1) >> PageDirectory::PAGE_SHIFT;
        const int page_count = (last_pfn - first_pfn) + 1;

        uint64_t pfns[page_count];

        // Add all of the pages to our pfn_list
        uint64_t pfn = this->page_number();
        for (int i = 0; i < page_count; ++i) {
            pfns[i] = pfn;
            ++pfn;
        }

        this->mapping_ = this->domain_->map_pfns(pfns, page_count);
        _reconfigure_buffer();
    }

    // Remap function for virtual addresses
    template <bool Physical = _Physical, typename std::enable_if_t<!Physical>* dummy = nullptr>
    void _remap() {
        // Calculate the number of pages required
        const uint64_t buffer_length = this->_buffer_length();
        const uint64_t first_pfn = this->page_number();
        const uint64_t last_pfn = (this->address_ + buffer_length - 1) >> PageDirectory::PAGE_SHIFT;
        const int page_count = (last_pfn - first_pfn) + 1;

        uint64_t pfns[page_count];

        // Translate the pages to physical addresses
        uint64_t va = this->address_ & PageDirectory::PAGE_MASK;
        for (int i = 0; i < page_count; ++i) {
            const uint64_t pa =
                this->domain_->page_directory().translate(va, this->page_directory_);
            const uint64_t pfn = pa >> PageDirectory::PAGE_SHIFT;
            pfns[i] = pfn;
            va += PageDirectory::PAGE_SIZE;
        }

        // Map and return
        this->mapping_ = this->domain_->map_pfns(pfns, page_count);
        _reconfigure_buffer();
    }

    void _reset(uint64_t address, size_t length = 0) {
        if constexpr (_is_guest_ptr_t_v) {
            // Special handling for our wrapped pointer
            if constexpr (_is_array_v) {
                this->ptr_.reset(address, length);
            } else {
                this->ptr_.reset(address);
            }
        } else {
            // Clear everything if a null address or length is provided
            if constexpr (_is_array_v) {
                if (address == 0 || length == 0) {
                    reset();
                    return;
                }
            } else {
                if (address == 0) {
                    reset();
                    return;
                }
            }

            // See if we need to remap
            if (this->mapping_) {
                // Does the new address change the mapped pages?
                const uint64_t old_pfn = this->address_ >> PageDirectory::PAGE_SHIFT;
                const uint64_t new_pfn = address >> PageDirectory::PAGE_SHIFT;
                if (old_pfn == new_pfn) {
                    // TODO:  If the mapping contains our buffer, even if it's not on the first
                    // page, we don't actually need a remap. We'd need to know the virtual address
                    // that the mapping starts at, though. For now we just require the first page to
                    // be the same.
                    const uint64_t page_offset = (address & ~PageDirectory::PAGE_MASK);
                    if ((page_offset + _buffer_length(length)) <= this->mapping_->length()) {
                        // Yep, no remap required. Just adjust the buffer pointer.
                        this->address_ = address;
                        if constexpr (_is_array_v) {
                            this->length_ = length;
                        }
                        _reconfigure_buffer();
                        return;
                    }
                }
            }

            this->address_ = address;
            if constexpr (_is_array_v) {
                this->length_ = length;
            }

            // A remap is required
            if constexpr (_is_access_allowed) {
                this->_remap();
            } else {
                this->mapping_.reset();
                _reconfigure_buffer();
            }
        }
    }

    void _validate_valid_ptr() const {
        if constexpr (_is_guest_ptr_t_v) {
            introvirt_assert(*this, "Operation performed with a null pointer");
        } else {
            introvirt_assert(this->domain_, "Operation performed with null domain");
            introvirt_assert(this->address_, "Operation performed with null address");
            if constexpr (!_Physical) {
                introvirt_assert(this->page_directory_,
                                 "Operation performed with null page directory");
            }
            if constexpr (_is_array_v) {
                introvirt_assert(this->length_, "Operation performed with zero length array");
            }
        }
    }

  private:
    // Calculate the size of the current buffer in bytes
    inline size_t _buffer_length() const {
        if constexpr (_is_array_v) {
            return this->_buffer_length(this->length_);
        } else {
            return _element_size();
        }
    }

    // Calculate the buffer size required for a given length in bytes
    inline size_t _buffer_length(size_t length) const {
        if constexpr (std::is_void_v<_Tp>) {
            return 1;
        } else if constexpr (_is_array_v) {
            return _element_size() * length;
        } else {
            return _element_size();
        }
    }

    constexpr size_t _element_size() const {
        if constexpr (_is_guest_ptr_t_v) {
            // Addition depends on the runtime type of thie pointer
            if (this->ptr_.x64()) {
                return sizeof(uint64_t);
            } else {
                return sizeof(uint32_t);
            }
        } else if constexpr (_is_pointer_v) {
            return sizeof(_PtrType);
        } else if constexpr (std::is_void_v<_Tp>) {
            return 1;
        } else {
            return sizeof(basic_type);
        }
    }

    // This function does everything but copy the mapping_, because that can be moved first
    template <typename InTp, typename InPtrType, bool InPhysical>
    void _copy_base(const basic_guest_ptr<InTp, InPtrType, InPhysical>& in, size_t length = 0) {
        /// Sanity checks
        using MyType = std::remove_const_t<std::remove_extent_t<_Tp>>;
        using InType = std::remove_const_t<std::remove_extent_t<InTp>>;
        constexpr bool is_array = std::is_array_v<InTp>;

        // The types have to be the same, or one of the types has to be void
        static_assert(std::is_same_v<MyType, InType> || std::is_void_v<_Tp> || std::is_void_v<InTp>,
                      "Constructing from incompatible type");
        // We can create a const from non-const, but not the other way around
        static_assert(!std::is_const_v<InTp> || std::is_const_v<_Tp>,
                      "Constructing would disregard const qualifiers");

        static_assert(!(!_Physical && InPhysical), "Cannot convert from physical to virtual");

        if (unlikely(!in)) {
            // Input is null, just clear ourselves
            this->reset();
            return;
        }

        if constexpr (!_is_guest_ptr_t_v) {
            this->domain_ = &(in.domain());
            if constexpr (_Physical && !InPhysical) {
                // Convert the address to physical
                this->address_ =
                    this->domain_->page_directory().translate(in.address(), in.page_directory());
                // Don't do the below stuff, we don't need a remap when converting virtual to
                // physical because we limit it to one byte types
                return;
            } else {
                // We have to set this so _reset() can figure out if it should reuse the same buffer
                this->address_ = in.address();
            }
            if constexpr (!_Physical) {
                this->page_directory_ = in.page_directory();
            }

            if constexpr (_is_array_v && is_array) {
                // Both this and the input are arrays
                // We can copy the length, but will use one if provided
                if (length == 0)
                    this->_reset(in.address(), in.length());
                else
                    this->_reset(in.address(), length);
            } else if constexpr (_is_array_v && !is_array) {
                // This is an array, and the input is not an array.
                // We need a length
                this->_reset(in.address(), length);
            } else if constexpr (!_is_array_v) {
                // This is not an array.
                // Disregard the length
                this->_reset(in.address());
            }
        }
    }

    template <typename InTp, typename InPtrType>
    void _copy_from_guest_ptr_t_base(const basic_guest_ptr<InTp, InPtrType, _Physical>& in,
                                     size_t length = 0) {

        static_assert(std::is_void_v<InPtrType> || std::is_same_v<InPtrType, uint32_t> ||
                          std::is_same_v<InPtrType, uint64_t>,
                      "InPtrType must be uint32_t or uint64_t");

        /// Sanity checks
        using MyType = std::remove_const_t<std::remove_extent_t<_Tp>>;
        using InType = std::remove_const_t<std::remove_extent_t<InTp>>;
        constexpr bool is_array = std::is_array_v<InTp>;

        // The types have to be the same, or one of the types has to be void
        static_assert(std::is_same_v<MyType, InType> || std::is_void_v<_Tp> || std::is_void_v<InTp>,
                      "Constructing from incompatible type");

        // We can create a const from non-const, but not the other way around
        static_assert(!std::is_const_v<InTp> || std::is_const_v<_Tp>,
                      "Constructing would disregard const qualifiers");

        static constexpr bool x64 = std::is_same_v<InPtrType, uint64_t>;
        this->ptr_.reset(x64);
        this->ptr_._domain(&(in.domain()));
        this->ptr_._address(in.address());
        if constexpr (!_Physical) {
            this->ptr_._page_directory(in.page_directory());
        }

        if constexpr (_is_array_v && is_array) {
            // Both this and the input are arrays
            // We can copy the length, but will use one if provided
            if (length == 0)
                this->ptr_.reset(x64, in.address(), in.length());
            else
                this->ptr_.reset(x64, in.address(), length);
        } else if constexpr (_is_array_v && !is_array) {
            // This is an array, and the input is not an array.
            // We need a length
            this->ptr_.reset(x64, in.address(), length);
        } else if constexpr (!_is_array_v) {
            // This is not an array.
            // Disregard the length
            this->ptr_.reset(x64, in.address());
        }
    }

    template <typename InTp, typename InPtrType>
    void _copy_guest_ptr_t(const basic_guest_ptr<InTp, InPtrType, _Physical>& in) {
        if constexpr (std::is_pointer_v<std::remove_extent_t<InTp>> && is_guest_size_v<InPtrType>) {
            // Both of us are guest_ptr_t pointers
            this->ptr_.reset(in.ptr_);
        } else {
            // We're a guest_ptr_t pointer but the source is a non-guest_ptr_t pointer
            static constexpr bool x64 = std::is_same_v<InPtrType, uint64_t>;
            this->ptr_.reset(x64);
            this->ptr_._mapping(in._mapping());
            _copy_from_guest_ptr_t_base(in);
        }
    }
    template <typename InTp, typename InPtrType>
    void _copy_guest_ptr_t(const basic_guest_ptr<InTp, InPtrType, _Physical>& in, size_t length) {
        if constexpr (std::is_pointer_v<std::remove_extent_t<InTp>> && is_guest_size_v<InPtrType>) {
            this->ptr_.reset(in.ptr_, length);
        } else {
            // We're a guest_ptr_t pointer but the source is a non-guest_ptr_t pointer
            static constexpr bool x64 = std::is_same_v<InPtrType, uint64_t>;
            this->ptr_.reset(x64);
            this->ptr_._mapping(in._mapping());
            _copy_from_guest_ptr_t_base(in, length);
        }
    }
    template <typename InTp, typename InPtrType>
    void _move_guest_ptr_t(basic_guest_ptr<InTp, InPtrType, _Physical>&& in) {
        if constexpr (std::is_pointer_v<std::remove_extent_t<InTp>> && is_guest_size_v<InPtrType>) {
            this->ptr_.reset(std::move(in.ptr_));
        } else {
            // We're a guest_ptr_t pointer but the source is a non-guest_ptr_t pointer
            static constexpr bool x64 = std::is_same_v<InPtrType, uint64_t>;
            this->ptr_.reset(x64);
            this->ptr_._mapping(std::move(in._mapping()));
            _copy_from_guest_ptr_t_base(in);
        }
    }
    template <typename InTp, typename InPtrType>
    void _move_guest_ptr_t(basic_guest_ptr<InTp, InPtrType, _Physical>&& in, size_t length) {
        if constexpr (std::is_pointer_v<std::remove_extent_t<InTp>> && is_guest_size_v<InPtrType>) {
            this->ptr_.reset(this->ptr_.x64(), std::move(in.ptr_), length);
        } else {
            // We're a guest_ptr_t pointer but the source is a non-guest_ptr_t pointer
            static constexpr bool x64 = std::is_same_v<InPtrType, uint64_t>;
            this->ptr_.reset(x64);
            this->ptr_._mapping(std::move(in._mapping()));
            _copy_from_guest_ptr_t_base(in, length);
        }
    }

    // copy constructor helper
    template <typename InTp, typename InPtrType, bool InPhysical>
    void _copy(const basic_guest_ptr<InTp, InPtrType, InPhysical>& in) {
        // We are an array, the input is not an array, and no length is provided
        static_assert(!(_is_array_v && !std::is_array_v<InTp>),
                      "A length is required to convert from non-array to array");

        if constexpr (_is_guest_ptr_t_v) {
            _copy_guest_ptr_t(in);
        } else {
            this->mapping_ = in._mapping();
            this->_copy_base(in);
        }
    }

    template <typename InTp, typename InPtrType, bool InPhysical>
    void _copy(const basic_guest_ptr<InTp, InPtrType, InPhysical>& in, size_t length) {
        // A length was provided, but this class is not an array
        static_assert(_is_array_v, "_copy() with length only valid for arrays");
        if constexpr (_is_guest_ptr_t_v) {
            _copy_guest_ptr_t(in, length);
        } else {
            this->address_ = in.address_;
            this->mapping_ = in._mapping();
            this->_copy_base(in, length);
        }
    }

    // Move constructor helper
    template <typename InTp, typename InPtrType, bool InPhysical>
    void _move(basic_guest_ptr<InTp, InPtrType, InPhysical>&& in) {
        // We are an array, the input is not an array, and no length is provided
        static_assert(!(_is_array_v && !std::is_array_v<InTp>),
                      "A length is required to convert from non-array to array");
        if constexpr (_is_guest_ptr_t_v) {
            _move_guest_ptr_t(std::move(in));
        } else {
            this->mapping_ = std::move(in._mapping());
            this->_copy_base(in);
        }
    }

    // Move constructor helper
    template <typename InTp, typename InPtrType, bool InPhysical>
    void _move(basic_guest_ptr<InTp, InPtrType, InPhysical>&& in, size_t length) {
        // A length was provided, but this class is not an array
        static_assert(_is_array_v, "_copy() with length only valid for arrays");
        if constexpr (_is_guest_ptr_t_v) {
            _move_guest_ptr_t(std::move(in), length);
        } else {
            this->mapping_ = std::move(in._mapping());
            this->_copy_base(in, length);
        }
    }

  private:
    // Getters and setters uses for casting
    inline const auto& _mapping() const {
        if constexpr (_is_guest_ptr_t_v) {
            return this->ptr_._mapping();
        } else {
            return this->mapping_;
        }
    }
    inline auto& _mapping() {
        if constexpr (_is_pointer_v && _is_guest_ptr_t_v) {
            return this->ptr_._mapping();
        } else if constexpr (!_is_pointer_v || !_is_guest_ptr_t_v) {
            return this->mapping_;
        }
    }
    inline void _mapping(const std::shared_ptr<GuestMemoryMapping>& in) {
        if constexpr (_is_pointer_v && _is_guest_ptr_t_v) {
            this->ptr_._mapping(in);
        } else if constexpr (!_is_pointer_v || !_is_guest_ptr_t_v) {
            this->mapping_ = in;
        }
    }
    inline void _mapping(std::shared_ptr<GuestMemoryMapping>&& in) {
        if constexpr (_is_pointer_v && _is_guest_ptr_t_v) {
            this->ptr_._mapping(std::move(in));
        } else if constexpr (!_is_pointer_v || !_is_guest_ptr_t_v) {
            this->mapping_ = std::move(in);
        }
    }
    inline auto _buffer() const {
        if constexpr (_is_guest_ptr_t_v) {
            return this->ptr_._buffer();
        } else {
            return this->buffer_;
        }
    }
    inline void _buffer(pointer_type in) {
        if constexpr (_is_guest_ptr_t_v) {
            this->ptr_._buffer(in);
        } else {
            this->buffer_ = in;
        }
    }
    inline void _domain(const Domain* in) {
        if constexpr (_is_guest_ptr_t_v) {
            this->ptr_._domain(in);
        } else {
            this->domain_ = in;
        }
    }
    inline void _address(uint64_t in) {
        if constexpr (_is_guest_ptr_t_v) {
            this->ptr_._address(in);
        } else {
            this->address_ = in;
        }
    }
    inline void _page_directory(uint64_t in) {
        if constexpr (_is_guest_ptr_t_v) {
            this->ptr_._page_directory(in);
        } else {
            this->page_directory_ = in;
        }
    }
    inline void _length(size_t in) {
        if constexpr (_is_guest_ptr_t_v) {
            this->ptr_._length(in);
        } else {
            this->length_ = in;
        }
    }

    // Friend other versions of this template
    template <typename U, typename PtrType, bool Physical, typename Enabled>
    friend class basic_guest_ptr;

    /// Friend the casting functions
    template <typename OutTp, typename OutPtrType, typename InTp, typename InPtrType, bool Physical>
    friend void _ptr_cast_impl(const basic_guest_ptr<InTp, InPtrType, Physical>&,
                               basic_guest_ptr<OutTp, OutPtrType, Physical>&);
    template <typename OutTp, typename OutPtrType, typename InTp, typename InPtrType, bool Physical>
    friend basic_guest_ptr<OutTp, OutPtrType, Physical>
    const_ptr_cast(const basic_guest_ptr<InTp, InPtrType, Physical>&);
    template <typename OutTp, typename OutPtrType, typename InTp, typename InPtrType, bool Physical>
    friend basic_guest_ptr<OutTp, OutPtrType, Physical>
    static_ptr_cast(const basic_guest_ptr<InTp, InPtrType, Physical>&);
    template <typename OutTp, typename OutPtrType, typename InTp, typename InPtrType, bool Physical>
    friend basic_guest_ptr<OutTp, OutPtrType, Physical>
    reinterpret_ptr_cast(const basic_guest_ptr<InTp, InPtrType, Physical>&);
    template <typename OutTp, typename OutPtrType, typename InTp, typename InPtrType, bool Physical>
    friend basic_guest_ptr<OutTp, OutPtrType, Physical>
    const_ptr_cast(basic_guest_ptr<InTp, InPtrType, Physical>&&);
    template <typename OutTp, typename OutPtrType, typename InTp, typename InPtrType, bool Physical>
    friend basic_guest_ptr<OutTp, OutPtrType, Physical>
    static_ptr_cast(basic_guest_ptr<InTp, InPtrType, Physical>&&);
    template <typename OutTp, typename OutPtrType, typename InTp, typename InPtrType, bool Physical>
    friend basic_guest_ptr<OutTp, OutPtrType, Physical>
    reinterpret_ptr_cast(basic_guest_ptr<InTp, InPtrType, Physical>&&);
};

template <typename _OutTp, typename _OutPtrType = void, typename _InTp, typename _PtrType,
          bool _Physical>
void _ptr_cast_impl(const basic_guest_ptr<_InTp, _PtrType, _Physical>& in,
                    basic_guest_ptr<_OutTp, _OutPtrType, _Physical>& out) {

    out._domain(&(in.domain()));
    if constexpr (!_Physical) {
        out._page_directory(in.page_directory());
    }
    if constexpr (std::is_array_v<_OutTp>) {
        // There's no way to provide the length with a cast, use a constructor
        static_assert(std::is_array_v<_InTp>, "Cannot cast from non-array to array directly");
        out.reset(in.address(), in.length());
    } else {
        out.reset(in.address());
    }
}

/// Copy casting functions
template <typename _OutTp, typename _OutPtrType = void, typename _InTp, typename _PtrType,
          bool _Physical>
basic_guest_ptr<_OutTp, _OutPtrType, _Physical>
const_ptr_cast(const basic_guest_ptr<_InTp, _PtrType, _Physical>& in) {
    basic_guest_ptr<_OutTp, _OutPtrType, _Physical> result;
    if (unlikely(!in))
        return result;
    result._mapping(in._mapping());
    result._buffer(const_cast<_OutTp*>(in._buffer()));
    _ptr_cast_impl<_OutTp>(in, result);
    return result;
}
template <typename _OutTp, typename _OutPtrType = void, typename _InTp, typename _PtrType,
          bool _Physical>
basic_guest_ptr<_OutTp, _OutPtrType, _Physical>
static_ptr_cast(const basic_guest_ptr<_InTp, _PtrType, _Physical>& in) {
    basic_guest_ptr<_OutTp, _OutPtrType, _Physical> result;
    if (unlikely(!in))
        return result;
    result._mapping(in._mapping());
    result._buffer(static_cast<_OutTp*>(in._buffer()));
    _ptr_cast_impl<_OutTp>(in, result);
    return result;
}
template <typename _OutTp, typename _OutPtrType = void, typename _InTp, typename _PtrType,
          bool _Physical>
basic_guest_ptr<_OutTp, _OutPtrType, _Physical>
reinterpret_ptr_cast(const basic_guest_ptr<_InTp, _PtrType, _Physical>& in) {
    basic_guest_ptr<_OutTp, _OutPtrType, _Physical> result;
    if (unlikely(!in))
        return result;
    result._mapping(in._mapping());
    result._buffer(reinterpret_cast<_OutTp*>(in._buffer()));
    _ptr_cast_impl<_OutTp>(in, result);
    return result;
}

/// Move casting functions
template <typename _OutTp, typename _OutPtrType = void, typename _InTp, typename _PtrType,
          bool _Physical>
basic_guest_ptr<_OutTp, _OutPtrType, _Physical>
const_ptr_cast(basic_guest_ptr<_InTp, _PtrType, _Physical>&& in) {
    basic_guest_ptr<_OutTp, _OutPtrType, _Physical> result;
    if (unlikely(!in))
        return result;
    result._mapping(std::move(in._mapping()));
    result._buffer(const_cast<_OutTp*>(in._buffer()));
    _ptr_cast_impl<_OutTp>(in, result);
    return result;
}
template <typename _OutTp, typename _OutPtrType = void, typename _InTp, typename _PtrType,
          bool _Physical>
basic_guest_ptr<_OutTp, _OutPtrType, _Physical>
static_ptr_cast(basic_guest_ptr<_InTp, _PtrType, _Physical>&& in) {
    basic_guest_ptr<_OutTp, _OutPtrType, _Physical> result;
    if (unlikely(!in))
        return result;
    result._mapping(std::move(in._mapping()));
    result._buffer(static_cast<_OutTp*>(in._buffer()));
    _ptr_cast_impl<_OutTp>(in, result);
    return result;
}
template <typename _OutTp, typename _OutPtrType = void, typename _InTp, typename _PtrType,
          bool _Physical>
basic_guest_ptr<_OutTp, _OutPtrType, _Physical>
reinterpret_ptr_cast(basic_guest_ptr<_InTp, _PtrType, _Physical>&& in) {
    basic_guest_ptr<_OutTp, _OutPtrType, _Physical> result;
    if (unlikely(!in))
        return result;
    result._mapping(std::move(in._mapping()));
    result._buffer(reinterpret_cast<_OutTp*>(in._buffer()));
    _ptr_cast_impl<_OutTp>(in, result);
    return result;
}

/// Null terminated array helpers

template <typename _CharType, typename _OutPtrType = void, typename _Tp, typename _PtrType,
          bool _Physical>
inline auto _map_guest_str(const basic_guest_ptr<_Tp, _PtrType, _Physical>& ptr,
                           size_t max_length = 0xFFFF) {

    using result_type =
        std::conditional_t<std::is_const_v<_Tp>, std::add_const_t<_CharType>, _CharType>;
    basic_guest_ptr<result_type, _OutPtrType, _Physical> result;

    constexpr std::size_t char_size = sizeof(std::remove_all_extents_t<_CharType>);

    if (!ptr) {
        return result;
    }

    std::size_t bytes_available = PageDirectory::PAGE_SIZE - ptr.page_offset();
    std::size_t chars_available = bytes_available / char_size;

    if constexpr (char_size > 1) {
        if (unlikely(chars_available == 0)) {
            // Not enough space for even one element. Can happen if the type is more than one
            // byte.
            bytes_available += PageDirectory::PAGE_SIZE;
            chars_available = bytes_available / char_size;
        }
    }

    // Scan for a null pointer
    size_t offset = 0;

    if constexpr (std::is_void_v<_Tp>) {
        result.reset(ptr, chars_available);
    } else if constexpr (!std::is_void_v<_Tp>) {
        result.reset(basic_guest_ptr<void, _PtrType, _Physical>(ptr), chars_available);
    }

    do {
        // Look for a null byte, starting at our offset
        while (offset < chars_available) {
            if (result[offset] == 0)
                goto done;

            // If we've hit the size limit, exit early
            if (unlikely(++offset >= max_length)) {
                goto done;
            }
        }

        // We didn't find a null character, map more data
        bytes_available += PageDirectory::PAGE_SIZE;
        chars_available = bytes_available / char_size;

        result.reset(result.address(), chars_available);

    } while (true);

done:
    // Shrink the offset to the actual requirement
    // This shouldn't trigger a remap
    result.reset(ptr.address(), offset);
    return result;
}

/**
 * @brief Helper function for map_guest_str<char>
 *
 * @param ptr The starting address of the string
 * @param max_length The maximum number of char values to map
 */
template <typename _Tp, typename _PtrType, bool _Physical>
inline basic_guest_ptr<char[], void, _Physical>
map_guest_cstring(const basic_guest_ptr<_Tp, _PtrType, _Physical>& ptr,
                  size_t max_length = 0xFFFF) {
    return _map_guest_str<char[]>(ptr);
}

/**
 * @brief Helper function for map_guest_str<char16_t>
 *
 * @param ptr The starting address of the string
 * @param max_length The maximum number of char16_t values to map
 */
template <typename _Tp, typename _PtrType, bool _Physical>
inline basic_guest_ptr<char16_t[], void, _Physical>
map_guest_wstring(const basic_guest_ptr<_Tp, _PtrType, _Physical>& ptr,
                  size_t max_length = 0xFFFF) {
    return _map_guest_str<char16_t[]>(ptr);
}

/// String and ostream helpers

// Get the hex address as a string
template <typename _Tp, typename _PtrType, bool _Physical>
inline std::string to_string(const basic_guest_ptr<_Tp, _PtrType, _Physical>& ptr) {
    return n2hexstr(ptr.address());
}

// The actual operator
template <typename _Tp, typename _PtrType, bool _Physical>
inline std::ostream& operator<<(std::ostream& os,
                                const basic_guest_ptr<_Tp, _PtrType, _Physical>& ptr) {
    return ptr.write_stream(os);
}

} // namespace introvirt

#include "guest_size_t_ptr.hh"

#include "guest_member_ptr.hh"
