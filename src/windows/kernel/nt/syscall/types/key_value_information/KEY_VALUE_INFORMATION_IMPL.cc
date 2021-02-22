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
#include "KEY_VALUE_INFORMATION_IMPL.hh"

#include "KEY_VALUE_BASIC_INFORMATION_IMPL.hh"
#include "KEY_VALUE_FULL_INFORMATION_IMPL.hh"
#include "KEY_VALUE_PARTIAL_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _BaseClass, typename _StructType>
void KEY_VALUE_INFORMATION_IMPL<_BaseClass, _StructType>::write(
    std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::dec;

    os << linePrefix << "KeyValueInformationClass: " << KeyValueInformationClass() << '\n';
    os << linePrefix << "TitleIndex: " << TitleIndex() << '\n';
    os << linePrefix << "Type: " << Type() << '\n';
}

template <typename _BaseClass, typename _StructType>
Json::Value KEY_VALUE_INFORMATION_IMPL<_BaseClass, _StructType>::json() const {
    Json::Value result;
    result["KeyValueInformationClass"] = to_string(KeyValueInformationClass());
    result["Name"] = Name();
    result["TitleIndex"] = TitleIndex();
    return result;
}

template <typename _BaseClass, typename _StructType>
KEY_VALUE_INFORMATION_IMPL<_BaseClass, _StructType>::KEY_VALUE_INFORMATION_IMPL(
    KEY_VALUE_INFORMATION_CLASS information_class, const GuestVirtualAddress& gva,
    uint32_t buffer_size)
    : class_(information_class), gva_(gva), buffer_size_(buffer_size) {

    if (unlikely(buffer_size < sizeof(_StructType)))
        throw BufferTooSmallException(sizeof(_StructType), buffer_size);

    data_.reset(gva_);
}

template <typename PtrType>
std::unique_ptr<KEY_VALUE_INFORMATION>
make_unique_impl(KEY_VALUE_INFORMATION_CLASS information_class, const GuestVirtualAddress& gva,
                 uint32_t buffer_size) {

    // TODO: Verify the "Align64" types work as expected
    switch (information_class) {
    case KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation:
        return std::make_unique<KEY_VALUE_BASIC_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation:
    case KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformationAlign64:
        return std::make_unique<KEY_VALUE_FULL_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation:
    case KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformationAlign64:
        return std::make_unique<KEY_VALUE_PARTIAL_INFORMATION_IMPL>(gva, buffer_size);
    }

    return std::make_unique<KEY_VALUE_INFORMATION_IMPL<>>(information_class, gva, buffer_size);
}

std::unique_ptr<KEY_VALUE_INFORMATION>
KEY_VALUE_INFORMATION::make_unique(const NtKernel& kernel,
                                   KEY_VALUE_INFORMATION_CLASS information_class,
                                   const GuestVirtualAddress& gva, uint32_t buffer_size) {

    if (unlikely(buffer_size == 0))
        return nullptr;

    if (kernel.x64())
        return make_unique_impl<uint64_t>(information_class, gva, buffer_size);
    else
        return make_unique_impl<uint32_t>(information_class, gva, buffer_size);
}

template class KEY_VALUE_INFORMATION_IMPL<KEY_VALUE_BASIC_INFORMATION,
                                          structs::_KEY_VALUE_BASIC_INFORMATION>;

template class KEY_VALUE_INFORMATION_IMPL<KEY_VALUE_FULL_INFORMATION,
                                          structs::_KEY_VALUE_FULL_INFORMATION>;

template class KEY_VALUE_INFORMATION_IMPL<KEY_VALUE_PARTIAL_INFORMATION,
                                          structs::_KEY_VALUE_PARTIAL_INFORMATION>;

} // namespace nt
} // namespace windows
} // namespace introvirt
