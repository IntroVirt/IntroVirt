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

#include "TRANSMIT_FILE_BUFFERS_IMPL.hh"

#include <introvirt/core/domain/Vcpu.hh>

namespace introvirt {
namespace windows {
namespace ws2_32 {

std::shared_ptr<TRANSMIT_FILE_BUFFERS>
TRANSMIT_FILE_BUFFERS::make_shared(const guest_ptr<void>& ptr, bool x64) {
    if (x64) {
        return std::make_shared<TRANSMIT_FILE_BUFFERS_IMPL<uint64_t>>(ptr);
    }
    return std::make_shared<TRANSMIT_FILE_BUFFERS_IMPL<uint32_t>>(ptr);
}

size_t TRANSMIT_FILE_BUFFERS::size(bool x64) {
    if (x64) {
        return sizeof(structs::_TRANSMIT_FILE_BUFFERS<uint64_t>);
    }
    return sizeof(structs::_TRANSMIT_FILE_BUFFERS<uint32_t>);
}

size_t TRANSMIT_FILE_BUFFERS::size(const Vcpu& vcpu) {
    return TRANSMIT_FILE_BUFFERS::size(vcpu.long_mode() && !vcpu.long_compatibility_mode());
}

} // namespace ws2_32
} // namespace windows
} // namespace introvirt