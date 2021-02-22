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
#include "FILE_MODE_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

void FILE_MODE_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;

    os << linePrefix << "FileInformationClass: " << FileInformationClass() << '\n';

    os << linePrefix << "Mode: 0x" << Mode() << " [ ";

    if (WriteThrough()) {
        os << "FILE_WRITE_THROUGH ";
    }
    if (SequentialOnly()) {
        os << "FILE_SEQUENTIAL_ONLY ";
    }
    if (NoIntermediateBuffering()) {
        os << "FILE_NO_INTERMEDIATE_BUFFERING ";
    }
    if (SynchronousIoAlert()) {
        os << "FILE_SYNCHRONOUS_IO_ALERT ";
    }
    if (SynchronousIoNonAlert()) {
        os << "FILE_SYNCHRONOUS_IO_NONALERT ";
    }
    if (DeleteOnClose()) {
        os << "FILE_DELETE_ON_CLOSE ";
    }
    os << "]\n";
}

Json::Value FILE_MODE_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["FileInformationClass"] = to_string(FileInformationClass());
    result["Mode"] = Mode();
    return result;
}

FILE_MODE_INFORMATION_IMPL::FILE_MODE_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                       uint32_t buffer_size)
    : gva_(gva), buffer_size_(buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_FILE_MODE_INFORMATION)))
        throw BufferTooSmallException(sizeof(structs::_FILE_MODE_INFORMATION), buffer_size);

    data_.reset(gva_);
}

bool FILE_MODE_INFORMATION::WriteThrough() const { return (Mode() & FILE_WRITE_THROUGH) != 0u; }

bool FILE_MODE_INFORMATION::SequentialOnly() const { return (Mode() & FILE_SEQUENTIAL_ONLY) != 0u; }

bool FILE_MODE_INFORMATION::NoIntermediateBuffering() const {
    return (Mode() & FILE_NO_INTERMEDIATE_BUFFERING) != 0u;
}

bool FILE_MODE_INFORMATION::SynchronousIoAlert() const {
    return (Mode() & FILE_SYNCHRONOUS_IO_ALERT) != 0u;
}

bool FILE_MODE_INFORMATION::SynchronousIoNonAlert() const {
    return (Mode() & FILE_SYNCHRONOUS_IO_NONALERT) != 0u;
}

bool FILE_MODE_INFORMATION::DeleteOnClose() const { return (Mode() & FILE_DELETE_ON_CLOSE) != 0u; }

} // namespace nt
} // namespace windows
} // namespace introvirt