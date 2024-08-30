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

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/fwd.hh>

namespace introvirt {

#define WRAPPED_GUESTPTR(x)                                                                        \
    if (this->x64_) {                                                                              \
        this->ptr64_.x;                                                                            \
    } else {                                                                                       \
        this->ptr32_.x;                                                                            \
    }

#define WRAPPED_GUESTPTR_RETURN(x)                                                                 \
    if (this->x64_) {                                                                              \
        return this->ptr64_.x;                                                                     \
    } else {                                                                                       \
        return this->ptr32_.x;                                                                     \
    }

#define WRAPPED_GUESTPTR_OPERATOR(x)                                                               \
    if (this->x64_) {                                                                              \
        this->ptr64_.x;                                                                            \
    } else {                                                                                       \
        this->ptr32_.x;                                                                            \
    }                                                                                              \
    return *this;

template <bool _Physical, bool _Array, bool _Const>
struct _guest_size_t_base {};

// Non-array, non-const
template <bool _Physical>
struct _guest_size_t_base<_Physical, false, false> {
  protected:
    bool x64_;
    basic_guest_ptr<uint32_t, void, _Physical> ptr32_;
    basic_guest_ptr<uint64_t, void, _Physical> ptr64_;
};

// Non-array, const
template <bool _Physical>
struct _guest_size_t_base<_Physical, false, true> {
  protected:
    bool x64_;
    basic_guest_ptr<const uint32_t, void, _Physical> ptr32_;
    basic_guest_ptr<const uint64_t, void, _Physical> ptr64_;
};

// Array, non-const
template <bool _Physical>
struct _guest_size_t_base<_Physical, true, false> {
  protected:
    bool x64_;
    basic_guest_ptr<uint32_t[], void, _Physical> ptr32_;
    basic_guest_ptr<uint64_t[], void, _Physical> ptr64_;
};

// Array, const
template <bool _Physical>
struct _guest_size_t_base<_Physical, true, true> {
  protected:
    bool x64_;
    basic_guest_ptr<const uint32_t[], void, _Physical> ptr32_;
    basic_guest_ptr<const uint64_t[], void, _Physical> ptr64_;
};

#define GUEST_SIZET_TYPE                                                                           \
    basic_guest_ptr<_Tp, _PtrType, _Physical, std::enable_if_t<is_guest_size_v<_Tp>>>
/**
 * @brief Specialization of basic_guest_ptr<_Tp, guest_ptr_t,  _Physical> to handle both uint32_t
 * and uint64_t
 *
 * This class cannot return actual references or pointers, because the size can vary.
 */
template <typename _Tp, typename _PtrType, bool _Physical>
class GUEST_SIZET_TYPE final
    : public _guest_size_t_base<_Physical, std::is_array_v<_Tp>, std::is_const_v<_Tp>> {

    using basic_type = typename std::remove_pointer_t<std::remove_extent_t<_Tp>>;
    using array_element_type = std::remove_extent_t<_Tp>;

    static constexpr bool _is_array_v = std::is_array_v<_Tp>;
    static constexpr bool _is_pointer_v = std::is_pointer_v<array_element_type>;
    static constexpr bool _is_ppointer_v =
        std::is_pointer_v<std::remove_pointer_t<array_element_type>>;
    static constexpr bool _is_guest_ptr_t_v = false;

    template <typename Tp, typename Tp2 = std::remove_all_extents_t<std::remove_const_t<Tp>>>
    static constexpr bool _is_supported_type() {
        return std::is_same_v<Tp2, uint32_t> || std::is_same_v<Tp2, uint64_t>;
    }

    using outptr_type =
        basic_guest_ptr<basic_type, std::conditional_t<_is_ppointer_v, _PtrType, void>, _Physical>;

  public:
    /// Basic information
    inline uint64_t address() const { WRAPPED_GUESTPTR_RETURN(address()); }
    inline uint64_t page_number() const { WRAPPED_GUESTPTR_RETURN(page_number()); }
    inline uint64_t page_offset() const { WRAPPED_GUESTPTR_RETURN(page_offset()); }
    inline uint64_t page_directory() const { WRAPPED_GUESTPTR_RETURN(page_directory()); }
    inline const Domain& domain() const { WRAPPED_GUESTPTR_RETURN(domain()); }
    inline std::string str() const { WRAPPED_GUESTPTR_RETURN(str()); }
    inline bool x64() const { return this->x64_; }
    explicit inline operator bool() const { WRAPPED_GUESTPTR_RETURN(operator bool()); }
    inline auto operator*() const { return get(); }
    inline size_t length() const { WRAPPED_GUESTPTR_RETURN(length()); }
    std::ostream& write_stream(std::ostream& os) const {
        WRAPPED_GUESTPTR_RETURN(write_stream(os));
    }

    /* Prefix increment operator */
    inline basic_guest_ptr<_Tp, _PtrType, _Physical>& operator++() {
        WRAPPED_GUESTPTR_OPERATOR(operator++());
    }
    /* Postfix increment operator */
    inline basic_guest_ptr<_Tp, _PtrType, _Physical> operator++(int) {
        basic_guest_ptr<_Tp, _PtrType, _Physical> result(*this);
        WRAPPED_GUESTPTR(operator++());
        return result;
    }
    /* Compound addition */
    template <typename I>
    inline basic_guest_ptr<_Tp, _PtrType, _Physical>& operator+=(I offset) {
        WRAPPED_GUESTPTR_OPERATOR(operator+=(offset));
    }
    /* Addition for integers */
    template <typename I>
    inline basic_guest_ptr<_Tp, _PtrType, _Physical> operator+(I offset) {
        basic_guest_ptr<_Tp, _PtrType, _Physical> result = *this;
        result += offset;
        return result;
    }
    /* Prefix decrement operator */
    inline basic_guest_ptr<_Tp, _PtrType, _Physical>& operator--() {
        WRAPPED_GUESTPTR_OPERATOR(operator--());
    }
    /* Postfix decrement operator */
    inline basic_guest_ptr<_Tp, _PtrType, _Physical> operator--(int) {
        basic_guest_ptr<_Tp, _PtrType, _Physical> result(*this);
        WRAPPED_GUESTPTR(operator--());
        return result;
    }
    /* Compount subtraction*/
    template <typename I>
    inline basic_guest_ptr<_Tp, _PtrType, _Physical>& operator-=(I offset) {
        WRAPPED_GUESTPTR_OPERATOR(operator-=(offset));
    }
    /* Subtraction for integers */
    template <typename I>
    inline basic_guest_ptr<_Tp, _PtrType, _Physical> operator-(I offset) {
        basic_guest_ptr<_Tp, _PtrType, _Physical> result = *this;
        result -= offset;
        return result;
    }

    template <typename PtrType>
    inline bool operator<(const basic_guest_ptr<void, PtrType, _Physical>& in) const {
        WRAPPED_GUESTPTR_RETURN(address() < in.address());
    }
    template <typename PtrType>
    inline bool operator<=(const basic_guest_ptr<void, PtrType, _Physical>& in) const {
        WRAPPED_GUESTPTR_RETURN(address() <= in.address());
    }
    template <typename PtrType>
    inline bool operator>(const basic_guest_ptr<void, PtrType, _Physical>& in) const {
        WRAPPED_GUESTPTR_RETURN(address() > in.address());
    }
    template <typename PtrType>
    inline bool operator>=(const basic_guest_ptr<void, PtrType, _Physical>& in) const {
        WRAPPED_GUESTPTR_RETURN(address() >= in.address());
    }
    template <typename PtrType>
    inline bool operator==(const basic_guest_ptr<void, PtrType, _Physical>& in) const {
        WRAPPED_GUESTPTR_RETURN(address() == in.address());
    }
    template <typename PtrType>
    inline bool operator!=(const basic_guest_ptr<void, PtrType, _Physical>& in) const {
        WRAPPED_GUESTPTR_RETURN(address() != in.address());
    }

  private:
    inline uint64_t _get_value(size_t index) const {
        if constexpr (_is_array_v) {
            uint64_t result;
            if (this->x64_) {
                result = this->ptr64_[index];
            } else {
                result = this->ptr32_[index];
            }
            return result;
        } else {
            uint64_t result;
            if (this->x64_) {
                result = *this->ptr64_;
            } else {
                result = *this->ptr32_;
            }
            return result;
        }
    }

    inline auto _get_ptr(size_t index) const {
        // Create a new guest_ptr_t based on the value we hold
        outptr_type result;
        result.x64_ = this->x64_;
        result._domain(&(this->domain()));
        result._mapping(this->_mapping());
        if constexpr (!_Physical) {
            result._page_directory(this->page_directory());
        }
        result.reset(this->x64_, this->_get_value(index));
        return result;
    }

    inline auto _get(size_t index) const {
        if constexpr (_is_pointer_v) {
            return _get_ptr(index);
        } else {
            return _get_value(index);
        }
    }

  public:
    /// Getter methods
    inline auto at(size_t index) const {
        static_assert(_is_array_v, "at(index) is only available for arrays");
        return _get(index);
    }
    inline auto operator[](size_t index) const {
        static_assert(_is_array_v, "operator[] is only available for arrays");
        return this->at(index);
    }
    inline auto get() const { return this->_get(0); }

    /// Setter methods

    // For non pointer values
    template <typename Tp = _Tp, typename std::enable_if_t<!std::is_pointer_v<Tp>>* dummy = nullptr>
    inline void set(uint64_t value) const {
        static_assert(!_is_array_v, "set(value) is not available for arrays");
        if (this->x64_) {
            *this->ptr64_ = value;
        } else {
            *this->ptr32_ = value;
        }
    }
    template <typename Tp = _Tp, typename std::enable_if_t<!std::is_pointer_v<Tp>>* dummy = nullptr>
    inline void set(size_t index, uint64_t value) const {
        static_assert(_is_array_v, "set(index, value) is only available for arrays");
        if (this->x64_) {
            this->ptr64_[index] = value;
        } else {
            this->ptr32_[index] = value;
        }
    }

    // For pointer values
    template <
        typename Tp = _Tp, typename InTp, typename InPtrType,
        typename std::enable_if_t<std::is_pointer_v<std::remove_extent_t<Tp>>>* dummy = nullptr>
    inline void set(const basic_guest_ptr<InTp, InPtrType, _Physical>& in) {
        static_assert(!_is_array_v, "set(ptr) is not available for arrays");
        WRAPPED_GUESTPTR_RETURN(set(in));
    }
    template <
        typename Tp = _Tp, typename InTp, typename InPtrType,
        typename std::enable_if_t<std::is_pointer_v<std::remove_extent_t<Tp>>>* dummy = nullptr>
    inline void set(size_t index, const basic_guest_ptr<InTp, InPtrType, _Physical>& in) {
        static_assert(_is_array_v, "set(index, ptr) is only available for arrays");
        WRAPPED_GUESTPTR_RETURN(set(index, in));
    }

    // Copy constructor and assignment
    template <typename Tp = _Tp, typename InTp, typename InPtrType>
    GUEST_SIZET_TYPE(const basic_guest_ptr<InTp, InPtrType, _Physical>& in) {
        *this = in;
    }
    template <typename Tp = _Tp, typename InTp, typename InPtrType>
    GUEST_SIZET_TYPE& operator=(const basic_guest_ptr<InTp, InPtrType, _Physical>& in) {
        if constexpr (_is_supported_type<InTp>()) {
            // We're being given a uint32_t([]) or uint64_t([])
            using InBasicType = std::remove_const_t<std::remove_extent_t<InTp>>;
            if constexpr (std::is_same_v<uint64_t, InBasicType>) {
                this->x64_ = true;
                this->ptr64_ = in;
            } else if constexpr (std::is_same_v<uint32_t, InBasicType>) {
                this->x64_ = false;
                this->ptr32_ = in;
            } else {
                static_assert(std::is_same_v<uint32_t, InBasicType> ||
                                  std::is_same_v<uint64_t, InBasicType>,
                              "Bug");
            }
        } else {
            static_assert(std::is_same_v<std::remove_const_t<Tp>, std::remove_const_t<InTp>> ||
                              std::is_void_v<Tp> || std::is_void_v<InTp>,
                          "Assignment from incompatible type");
            static_assert(std::is_const_v<Tp> || !std::is_const_v<InTp>,
                          "Cannot convert const to non-const");
            this->x64_ = in.x64_;
            if (this->x64_) {
                this->ptr64_ = in.ptr64_;
            } else {
                this->ptr32_ = in.ptr32_;
            }
        }
        return *this;
    }

    // Move constructor and assignment
    template <typename InTp, typename InPtrType>
    GUEST_SIZET_TYPE(basic_guest_ptr<InTp, InPtrType, _Physical>&& in) noexcept {
        *this = std::move(in);
    }
    template <typename Tp = _Tp, typename InTp, typename InPtrType>
    GUEST_SIZET_TYPE& operator=(basic_guest_ptr<InTp, InPtrType, _Physical>&& in) noexcept {
        if constexpr (_is_supported_type<InTp>()) {
            // We're being given a uint32_t([]) or uint64_t([])
            using InBasicType = std::remove_const_t<std::remove_extent_t<InTp>>;
            if constexpr (std::is_same_v<uint64_t, InBasicType>) {
                this->x64_ = true;
                this->ptr64_ = std::move(in);
            } else if constexpr (std::is_same_v<uint32_t, InBasicType>) {
                this->x64_ = false;
                this->ptr32_ = std::move(in);
            } else {
                static_assert(std::is_same_v<uint32_t, InBasicType> ||
                                  std::is_same_v<uint64_t, InBasicType>,
                              "Bug");
            }
        } else {
            static_assert(std::is_same_v<std::remove_const_t<Tp>, std::remove_const_t<InTp>> ||
                              std::is_void_v<Tp> || std::is_void_v<InTp>,
                          "Assignment from incompatible type");
            static_assert(std::is_const_v<Tp> || !std::is_const_v<InTp>,
                          "Cannot convert const to non-const");
            this->x64_ = in.x64_;
            if (this->x64_) {
                this->ptr64_ = std::move(in.ptr64_);
            } else {
                this->ptr32_ = std::move(in.ptr32_);
            }
        }
        return *this;
    }

    /// Common constructors
    GUEST_SIZET_TYPE() { this->x64_ = false; }
    template <typename... Arguments>
    GUEST_SIZET_TYPE(bool x64, Arguments&&... args) {
        this->x64_ = x64;
        WRAPPED_GUESTPTR(reset(std::forward<Arguments>(args)...));
    }
    template <typename... Arguments>
    GUEST_SIZET_TYPE(const Vcpu& vcpu, Arguments&&... args) {
        // Detect the correct pointer size based on the current vcpu state
        this->x64_ = (vcpu.long_mode() && !vcpu.long_compatibility_mode());
        WRAPPED_GUESTPTR(reset(vcpu, std::forward<Arguments>(args)...));
    }

    /// Helper to create a new instance of this pointer
    basic_guest_ptr<void, void, _Physical, void> clone(uint64_t address) const {
        // Create a new void pointer using this pointer as context
        basic_guest_ptr<void, void, _Physical, void> result;
        if (this->x64_) {
            result = this->ptr64_;
        } else {
            result = this->ptr32_;
        }
        result.reset(address);
        return result;
    }

    /// Reset operations

    // Forward any other combinations to the underlying pointer
    template <typename... Arguments>
    void reset(const Vcpu& vcpu, Arguments&&... args) {
        this->x64_ = (vcpu.long_mode() && !vcpu.long_compatibility_mode());
        WRAPPED_GUESTPTR(reset(std::forward<Arguments>(args)...));
    }
    template <typename... Arguments>
    void reset(bool x64, Arguments&&... args) {
        this->x64_ = x64;
        WRAPPED_GUESTPTR(reset(std::forward<Arguments>(args)...));
    }
    void reset() { WRAPPED_GUESTPTR(reset()); }

    // Special handling if we're handed a guest_size_t/guest_ptr_t
    template <typename U = _Tp, typename Tp, typename PtrType,
              typename std::enable_if_t<is_guest_size_v<Tp>>* dummy = nullptr>
    void reset(const basic_guest_ptr<Tp, PtrType, _Physical>& in) {
        *this = in;
    }
    template <typename U = _Tp, typename Tp, typename PtrType,
              typename std::enable_if_t<is_guest_size_v<Tp>>* dummy = nullptr>
    void reset(basic_guest_ptr<Tp, PtrType, _Physical>&& in) {
        *this = std::move(in);
    }

    /// Default constructors
    GUEST_SIZET_TYPE(const GUEST_SIZET_TYPE&) noexcept = default;
    GUEST_SIZET_TYPE& operator=(const GUEST_SIZET_TYPE&) noexcept = default;
    GUEST_SIZET_TYPE(GUEST_SIZET_TYPE&&) noexcept = default;
    GUEST_SIZET_TYPE& operator=(GUEST_SIZET_TYPE&&) noexcept = default;

  private:
    // Needed for conversion to work
    inline const auto& _mapping() const { WRAPPED_GUESTPTR_RETURN(_mapping()); }
    inline auto& _mapping() { WRAPPED_GUESTPTR_RETURN(_mapping()); }
    inline void _mapping(const std::shared_ptr<GuestMemoryMapping>& in) {
        WRAPPED_GUESTPTR(_mapping(in));
    }
    inline void _mapping(std::shared_ptr<GuestMemoryMapping>&& in) {
        WRAPPED_GUESTPTR(_mapping(std::move(in)));
    }
    inline auto _buffer() const {
        if (this->x64_) {
            return reinterpret_cast<std::remove_all_extents_t<_Tp>*>(this->ptr64_._buffer());
        } else {
            return reinterpret_cast<std::remove_all_extents_t<_Tp>*>(this->ptr32_._buffer());
        }
    }
    inline void _buffer(guest_ptr_t* in) {
        if (this->x64_) {
            this->ptr64_._buffer(reinterpret_cast<uint64_t*>(in));
        } else {
            this->ptr32_._buffer(reinterpret_cast<uint32_t*>(in));
        }
    }
    inline void _buffer(const guest_ptr_t* in) {
        if (this->x64_) {
            this->ptr64_._buffer(reinterpret_cast<const uint64_t*>(in));
        } else {
            this->ptr32_._buffer(reinterpret_cast<const uint32_t*>(in));
        }
    }

    inline void _domain(const Domain* in) { WRAPPED_GUESTPTR(_domain(in)); }
    inline void _address(uint64_t in) { WRAPPED_GUESTPTR(_address(in)); }
    inline void _page_directory(uint64_t in) { WRAPPED_GUESTPTR(_page_directory(in)); }
    inline void _length(size_t in) { WRAPPED_GUESTPTR(_length(in)); }

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

#undef GUEST_SIZET_TYPE
#undef WRAPPED_GUESTPTR_OPERATOR
#undef WRAPPED_GUESTPTR_RETURN
#undef WRAPPED_GUESTPTR

/**
 * @brief Helper class to transparently convert between guest size and a value
 */
class guest_size_t {
  public:
    guest_size_t() : value_(0) {}
    guest_size_t(uint64_t value) : value_(value) {}

    template <typename I, typename std::enable_if_t<std::is_integral_v<I>>* dummy = nullptr>
    guest_size_t& operator=(I value) {
        value_ = value;
        return *this;
    }

    operator uint64_t() const { return value_; }

  private:
    uint64_t value_;
};

} // namespace introvirt