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
#include "KEY_VALUE_DWORD_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

const uint32_t KEY_VALUE_DWORD_IMPL::DWORDValue() const {
    return *(reinterpret_cast<const uint32_t*>(Data()));
}

void KEY_VALUE_DWORD_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    KEY_VALUE_IMPL<KEY_VALUE_DWORD>::write(os, linePrefix);
    boost::io::ios_flags_saver ifs(os);
    os << linePrefix << "Value: " << DWORDValue();
    os << " [0x" << std::hex << DWORDValue() << "]\n";
}

Json::Value KEY_VALUE_DWORD_IMPL::json() const {
    Json::Value result = KEY_VALUE_IMPL<KEY_VALUE_DWORD>::json();
    result["DWORDValue"] = DWORDValue();
    return result;
}

KEY_VALUE_DWORD_IMPL::KEY_VALUE_DWORD_IMPL(const GuestVirtualAddress& gva, uint32_t size)
    : KEY_VALUE_IMPL<KEY_VALUE_DWORD>(REG_TYPE::REG_DWORD_LITTLE_ENDIAN, gva, size) {

    if (unlikely(DataSize() < sizeof(uint32_t)))
        throw BufferTooSmallException(sizeof(uint32_t), DataSize());
}

} // namespace nt
} // namespace windows
} /* namespace introvirt */
