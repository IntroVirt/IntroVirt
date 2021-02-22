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

#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>

namespace introvirt {

class VirtualAddressNotPresentException::IMPL {
  public:
    GuestVirtualAddress gva_;
};

GuestVirtualAddress VirtualAddressNotPresentException::virtual_address() const {
    return pImpl_->gva_;
}

VirtualAddressNotPresentException::VirtualAddressNotPresentException(const GuestVirtualAddress& gva)
    : MemoryException("Virtual address " + to_string(gva) + " not present"),
      pImpl_(std::make_unique<IMPL>()) {

    pImpl_->gva_ = gva;
}

VirtualAddressNotPresentException::VirtualAddressNotPresentException(
    VirtualAddressNotPresentException&& src) noexcept = default;
VirtualAddressNotPresentException& VirtualAddressNotPresentException::operator=(
    VirtualAddressNotPresentException&& src) noexcept = default;
VirtualAddressNotPresentException::~VirtualAddressNotPresentException() noexcept = default;

} // namespace introvirt
