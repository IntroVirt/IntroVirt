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
#include "SOCKADDR_IMPL.hh"
#include "SOCKADDR_IN_IMPL.hh"

#include <cstdint>
#include <introvirt/core/domain/Vcpu.hh>

namespace introvirt {
namespace windows {
namespace ws2_32 {

std::unique_ptr<SOCKADDR> SOCKADDR::make_unique(const GuestVirtualAddress& gva, bool x64) {
    // Read the family at the given address

    const uint16_t sa_family = *guest_ptr<uint16_t>(gva);
    switch (sa_family) {
    case AF_INET:
        return std::make_unique<SOCKADDR_IN_IMPL>(gva);
    }

    return std::make_unique<SOCKADDR_IMPL>(gva);
}

size_t SOCKADDR::size(bool x64) { return sizeof(structs::_SOCKADDR); }

size_t SOCKADDR::size(const Vcpu& vcpu) {
    return SOCKADDR::size(vcpu.long_mode() && !vcpu.long_compatibility_mode());
}

} // namespace ws2_32
} // namespace windows
} // namespace introvirt