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

#include <introvirt/core/exception/BadPhysicalAddressException.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>

#include <sstream>

namespace introvirt {

class BadPhysicalAddressException::IMPL {
  public:
    uint64_t gpa;
};

static std::string to_hex_string(uint64_t value) {
    std::stringstream ss;
    ss << std::hex << value;
    return ss.str();
}

BadPhysicalAddressException::BadPhysicalAddressException(uint64_t gpa, int err)
    : MemoryException("Bad physical address: 0x" + to_hex_string(gpa), err) {}

BadPhysicalAddressException::BadPhysicalAddressException(
    BadPhysicalAddressException&& src) noexcept = default;
BadPhysicalAddressException&
BadPhysicalAddressException::operator=(BadPhysicalAddressException&& src) noexcept = default;
BadPhysicalAddressException::~BadPhysicalAddressException() noexcept = default;

} // namespace introvirt
