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

#include <introvirt/windows/common/Utf16String.hh>
#include <introvirt/windows/exception/StringConversionException.hh>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/locale.hpp>

namespace introvirt {
namespace windows {

const size_t Utf16String::npos = std::u16string::npos;

class Utf16String::IMPL {
  public:
    std::string utf8;
    std::u16string utf16;
    bool utf16_valid{false};
};

std::string Utf16String::convert(std::u16string_view src) {
    try {
        return boost::locale::conv::utf_to_utf<char>(src.begin(), src.end());
    } catch (boost::locale::conv::conversion_error&) {
        throw StringConversionException("Conversion error");
    } catch (boost::locale::conv::invalid_charset_error&) {
        throw StringConversionException("Invalid character set");
    }
}

std::u16string Utf16String::convert(std::string_view src) {
    try {
        return boost::locale::conv::utf_to_utf<char16_t>(src.begin(), src.end());
    } catch (boost::locale::conv::conversion_error&) {
        throw StringConversionException("Conversion error");
    } catch (boost::locale::conv::invalid_charset_error&) {
        throw StringConversionException("Invalid character set");
    }
}

const std::string& Utf16String::utf8() const {
    if (pImpl->utf8.empty()) {
        pImpl->utf8 = convert(utf16());
    }
    return pImpl->utf8;
}

const std::u16string& Utf16String::utf16() const {
    if (!pImpl->utf16_valid) {
        pImpl->utf16 = std::u16string(reinterpret_cast<const char16_t*>(Buffer()),
                                      Length() / sizeof(char16_t));
        pImpl->utf16_valid = true;
    }
    return pImpl->utf16;
}

void Utf16String::set(const std::string& value) { set(convert(value)); }

void Utf16String::invalidate() {
    pImpl->utf8.clear();
    pImpl->utf16_valid = false;
}

Utf16String::operator const std::u16string&() const { return utf16(); }

bool Utf16String::operator==(const std::u16string& src) const { return equals(src); }

bool Utf16String::operator<(const std::u16string& src) const { return utf16() < src; }

bool Utf16String::equals(const std::string& search) const {
    return boost::algorithm::equals(utf8(), search);
}

bool Utf16String::equals(const std::u16string& search) const {
    std::string utf8search(convert(search));
    return equals(utf8search);
}

bool Utf16String::iequals(const std::string& search) const {
    return boost::algorithm::iequals(utf8(), search);
}

bool Utf16String::iequals(const std::u16string& search) const {
    std::string utf8search(convert(search));
    return iequals(utf8search);
}

bool Utf16String::starts_with(const std::string& search) const {
    return boost::algorithm::starts_with(utf8(), search);
}

bool Utf16String::starts_with(const std::u16string& search) const {
    std::string utf8search(convert(search));
    return starts_with(utf8search);
}

bool Utf16String::istarts_with(const std::string& search) const {
    return boost::algorithm::istarts_with(utf8(), search);
}

bool Utf16String::istarts_with(const std::u16string& search) const {
    std::string utf8search(convert(search));
    return istarts_with(utf8search);
}

bool Utf16String::ends_with(const std::string& search) const {
    return boost::algorithm::ends_with(utf8(), search);
}

bool Utf16String::ends_with(const std::u16string& search) const {
    std::string utf8search(convert(search));
    return ends_with(utf8search);
}

bool Utf16String::iends_with(const std::string& search) const {
    return boost::algorithm::iends_with(utf8(), search);
}

bool Utf16String::iends_with(const std::u16string& search) const {
    std::string utf8search(convert(search));
    return iends_with(utf8search);
}

void Utf16String::write(std::ostream& os, const std::string& linePrefix) const {
    os << linePrefix << utf8() << '\n';
}

Json::Value Utf16String::json() const {
    Json::Value result;
    result["value"] = utf8();
    return result;
}

Utf16String::Utf16String() : pImpl(std::make_unique<IMPL>()) {}

const std::string& to_string(const Utf16String& src) { return src.utf8(); }
std::ostream& operator<<(std::ostream& os, const Utf16String& src) {
    os << src.utf8();
    return os;
}

// Move semantics
Utf16String::Utf16String(Utf16String&&) noexcept = default;
Utf16String& Utf16String::operator=(Utf16String&&) noexcept = default;

Utf16String::~Utf16String() = default;

} /* namespace windows */
} /* namespace introvirt */
