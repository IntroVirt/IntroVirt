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

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>

namespace introvirt {
namespace windows {

/**
 * @brief Base UTF-16 class
 *
 * This is used by both WStr and UNICODE_STRING
 */
class Utf16String {
  public:
    /**
     * @returns The length of the string, in bytes
     */
    virtual uint16_t Length() const = 0;

    /**
     * @returns The raw UTF16LE buffer
     */
    virtual const uint8_t* Buffer() const = 0;

    /**
     * @returns The buffer converted to a UTF8 string
     */
    const std::string& utf8() const;

    /**
     * @returns The buffer as a u16string
     */
    const std::u16string& utf16() const;

    /**
     * @brief Sets the value of the string
     *
     * @param value The string to set
     *
     * @throws BufferTooSmallException if the buffer is too small for the input string
     */
    void set(const std::string& value);

    /**
     * @copydoc Utf16String::set(const std::string&)
     */
    virtual void set(const std::u16string& value) = 0;

    /**
     * Operator overload for converting to const std::u16string&
     */
    operator const std::u16string&() const;

  public:
    /**
     * Comparison operator. The comparison is case sensitive.
     */
    bool operator==(const std::string&) const;
    bool operator==(const std::u16string&) const;

    /**
     * Comparison operator. The comparison is case sensitive.
     */
    bool operator<(const std::string&) const;
    bool operator<(const std::u16string&) const;

    /**
     * @returns True if this string equals the given string
     */
    bool equals(const std::string&) const;
    bool equals(const std::u16string&) const;

    /**
     * @returns True if this string equals the given string, case insensitive.
     */
    bool iequals(const std::string&) const;
    bool iequals(const std::u16string&) const;

    /**
     * @returns True if this string starts with the given search string.
     */
    bool starts_with(const std::string&) const;
    bool starts_with(const std::u16string&) const;

    /**
     * @returns True if this string starts with the given search string. Case insensitive.
     */
    bool istarts_with(const std::string&) const;
    bool istarts_with(const std::u16string&) const;

    /**
     * @returns True if the string ends with the given search string.
     */
    bool ends_with(const std::string&) const;
    bool ends_with(const std::u16string&) const;

    /**
     * @returns True if the string ends with the given search string. Case insensitive.
     */
    bool iends_with(const std::string&) const;
    bool iends_with(const std::u16string&) const;

  public:
    Utf16String();
    virtual ~Utf16String();

    void write(std::ostream& os, const std::string& linePrefix = "") const;
    virtual Json::Value json() const;

    // Move semantics
    Utf16String(Utf16String&&) noexcept;
    Utf16String& operator=(Utf16String&&) noexcept;

    static const size_t npos;

  protected:
    /**
     * Flush cached UTF8
     */
    void invalidate();

  public:
    /**
     * @brief Convert a UTF16 string to UTF8
     * @param src The input string to convert
     */
    static std::string convert(std::u16string_view src);

    /**
     * @brief Convert a UTF8 string to UTF16
     * @param src The input string to convert
     */
    static std::u16string convert(std::string_view src);

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

const std::string& to_string(const Utf16String&);
std::ostream& operator<<(std::ostream& os, const Utf16String& str);

} /* namespace windows */
} /* namespace introvirt */
