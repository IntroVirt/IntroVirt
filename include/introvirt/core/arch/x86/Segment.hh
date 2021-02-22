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
#include <introvirt/util/compiler.hh>

#include <cstdint>

namespace introvirt {
namespace x86 {

class SegmentSelector final {
  public:
    /**
     * @brief Get the index into the descriptor table
     *
     * @return uint16_t indiciating the index into either the GDT or LDT
     */
    uint16_t index() const { return value_ >> 3; }

    /**
     * @brief Check if the selector is for the GDT or LDT
     *
     * @return true if for the LDT
     * @return false if for the GDT
     */
    bool table_indicator() const { return value_ & 0x4; }

    /**
     * @brief Get the requester privilege level
     *
     * @return uint16_t
     */
    uint16_t rpl() const { return value_ & 0x3; }

    /**
     * @brief Get the raw value of the selector
     *
     * @return uint16_t
     */
    uint16_t value() const { return value_; }

    explicit SegmentSelector(uint16_t value) : value_(value) {}

  public:
    const uint16_t value_;
};

/**
 * @brief Class to represent an x86 segment register
 */
class Segment final {
  public:
    /**
     * @brief Get the base address of the segment
     * @return The base address of the segment
     */
    uint64_t base() const { return base_; }
    /**
     * @brief Get the size of the segment
     *
     * @return The segment size
     */
    uint32_t limit() const { return limit_; }

    /**
     * @brief Get the segment selector
     *
     * @return The segment selector
     */
    SegmentSelector selector() const { return selector_; }

    bool present() const { return p_; }

    uint8_t dpl() const { return dpl_; }

    bool s() const { return s_; }

    uint8_t type() const { return type_; }

    bool granularity() const {
        verify_s();
        return g_;
    }

    bool db() const {
        verify_s();
        return db_;
    }

    bool long_mode() const {
        verify_s();
        return l_;
    }

    bool avl() const {
        verify_s();
        return avl_;
    }

    bool data() const {
        verify_s();
        return !code();
    }

    bool expand_down() const {
        verify_data();
        return type_ & 0x4;
    }

    bool writable() const {
        verify_data();
        return type_ & 0x2;
    }

    bool code() const {
        verify_s();
        return (type_ & 0x8);
    }

    bool conforming() const {
        verify_code();
        return type_ & 0x4;
    }

    bool readable() const {
        verify_code();
        return type_ & 0x2;
    }

    bool accessed() const {
        verify_s();
        return type_ & 0x1;
    }

    Segment(SegmentSelector sel, uint64_t base, uint32_t limit, uint8_t type, bool p, uint8_t dpl,
            bool db, bool s, bool l, bool g, bool avl)
        : selector_(sel), base_(base), limit_(limit), type_(type), p_(p), dpl_(dpl), db_(db), s_(s),
          l_(l), g_(g), avl_(avl) {}

  private:
    void verify_s() const {
        if (unlikely(s_ == 0))
            throw InvalidMethodException();
    }

    void verify_code() const {
        verify_s();
        if (unlikely(!code()))
            throw InvalidMethodException();
    }

    void verify_data() const {
        verify_s();
        if (unlikely(!data()))
            throw InvalidMethodException();
    }

  private:
    const SegmentSelector selector_;
    const uint64_t base_;
    const uint32_t limit_;
    const uint8_t type_;
    const bool p_;
    const uint8_t dpl_;
    const bool db_;
    const bool s_;
    const bool l_;
    const bool g_;
    const bool avl_;
};

} // namespace x86
} // namespace introvirt