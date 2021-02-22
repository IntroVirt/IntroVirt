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
#include "TOKEN_PRIVILEGES_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

#include <boost/io/ios_state.hpp>
#include <log4cxx/logger.h>

#include <cassert>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger(
    "introvirt.win.kernel.nt.syscall.types.token_information.TOKEN_PRIVILEGES"));

void TOKEN_PRIVILEGES_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    TOKEN_INFORMATION_IMPL_TYPE::write(os, linePrefix);

    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    for (const auto& luid_and_attributes : *this) {
        os << linePrefix << "LUID: 0x" << luid_and_attributes.Luid().value() << '\n';
        os << linePrefix << "\tAttributes: 0x" << std::hex
           << luid_and_attributes.Attributes().value() << " " << luid_and_attributes.Attributes()
           << '\n';
    }
}

Json::Value TOKEN_PRIVILEGES_IMPL::json() const {
    Json::Value privilegesJSON;

    for (const auto& luid_and_attributes : *this) {
        Json::Value luid_and_attributesJSON;
        luid_and_attributesJSON["LUID"] = luid_and_attributes.Luid().value();
        luid_and_attributesJSON["Attributes"] = luid_and_attributes.Attributes().value();
        privilegesJSON.append(luid_and_attributesJSON);
    }

    Json::Value result = TOKEN_INFORMATION_IMPL_TYPE::json();
    result["Privileges"] = privilegesJSON;
    return result;
}

TOKEN_PRIVILEGES_IMPL::TOKEN_PRIVILEGES_IMPL(const GuestVirtualAddress& gva)
    : array_iterable(gva, gva + offsetof(structs::_TOKEN_PRIVILEGES, Privileges),
                     TOKEN_INFORMATION_CLASS::TokenPrivileges, gva) {

    // This version just assumes the size is ok
    // This isn't ideal, but we'll assume the correct size.
    // NtAdjustPrivilegesToken has two versions of TOKEN_PRIVILEGES, in and out.
    // The input version doesn't have a size, the kernel assumes the caller is correct.

    // TODO: The output version does have a size paramter. For that one we should have a different
    // version of make_unique, but we'd have to adjust the jinja2 stuff to support it

    this->buffer_size_ = (this->data_->PrivilegeCount * sizeof(structs::_LUID_AND_ATTRIBUTES)) +
                         sizeof(structs::_TOKEN_PRIVILEGES);
}

TOKEN_PRIVILEGES_IMPL::TOKEN_PRIVILEGES_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
    : array_iterable(gva, gva + offsetof(structs::_TOKEN_PRIVILEGES, Privileges),
                     TOKEN_INFORMATION_CLASS::TokenPrivileges, gva, buffer_size) {}

std::unique_ptr<TOKEN_PRIVILEGES> TOKEN_PRIVILEGES::make_unique(const GuestVirtualAddress& gva) {
    return std::make_unique<TOKEN_PRIVILEGES_IMPL>(gva);
}

std::unique_ptr<TOKEN_PRIVILEGES> TOKEN_PRIVILEGES::make_unique(const GuestVirtualAddress& gva,
                                                                uint32_t buffer_size) {

    return std::make_unique<TOKEN_PRIVILEGES_IMPL>(gva, buffer_size);
}

} // namespace nt
} // namespace windows
} // namespace introvirt