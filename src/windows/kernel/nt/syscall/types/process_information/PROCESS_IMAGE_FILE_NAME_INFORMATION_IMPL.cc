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
#include "PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL.hh"

#include <introvirt/windows/WindowsGuest.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<PtrType>::write(std::ostream& os,
                                                              const std::string& linePrefix) const {
    PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL_BASE<PtrType>::write(os, linePrefix);

    os << linePrefix << "ImageFileName: " << ImageFileName() << '\n';
}

template <typename PtrType>
Json::Value PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<PtrType>::json() const {
    Json::Value result = PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL_BASE<PtrType>::json();
    result["ImageFileName"] = ImageFileName();
    return result;
}

template <typename PtrType>
void PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<PtrType>::parse() const {
    const GuestVirtualAddress pNameBuffer =
        this->gva_ +
        offsetof(structs::_PROCESS_IMAGE_FILE_NAME_INFORMATION<PtrType>, ImageFileName);

    ImageFileName_.emplace(pNameBuffer);

    // Used for invalidating the buffer
    ImageFileNameLength_ = ImageFileName_->Length();
}

template <typename PtrType>
PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<PtrType>::PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL(
    const GuestVirtualAddress& gva, uint32_t buffer_size)
    : PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<PtrType>(
          PROCESS_INFORMATION_CLASS::ProcessImageFileName, gva, buffer_size) {}

template <typename PtrType>
PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<PtrType>::PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL(
    PROCESS_INFORMATION_CLASS information_class, const GuestVirtualAddress& gva,
    uint32_t buffer_size)
    : PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL_BASE<PtrType>(information_class, gva, buffer_size) {

    parse();
}

template class PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<uint32_t>;
template class PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<uint64_t>;

} // namespace nt
} // namespace windows

namespace inject {

template <typename PtrType>
void GuestAllocation<windows::nt::PROCESS_IMAGE_FILE_NAME_INFORMATION>::init(
    uint16_t string_buffer_size) {

    using namespace windows::nt;

    const size_t structure_size = sizeof(structs::_PROCESS_IMAGE_FILE_NAME_INFORMATION<PtrType>);

    // Allocate memory for the size of the structure plus the size of the string
    buffer_.emplace(structure_size + string_buffer_size);

    // Figure out the buffer address
    GuestVirtualAddress BufferAddress = buffer_->address() + structure_size;

    // Prepare the UNICODE_STRING structure
    auto* data =
        reinterpret_cast<structs::_PROCESS_IMAGE_FILE_NAME_INFORMATION<PtrType>*>(buffer_->get());

    // Setting this up properly is only necessary for calling NtSetInformationProcess
    // I don't know if that's even legal, but we might as well make it valid.
    data->ImageFileName.Buffer = BufferAddress.value();
    data->ImageFileName.Length = 0;
    data->ImageFileName.MaximumLength = string_buffer_size;

    value_ = std::make_unique<PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<PtrType>>(
        buffer_->address(), structure_size + string_buffer_size);
}

GuestAllocation<windows::nt::PROCESS_IMAGE_FILE_NAME_INFORMATION>::GuestAllocation(
    uint16_t string_buffer_size) {

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<windows::WindowsGuest*>(domain.guest());
    assert(guest != nullptr);
    auto& kernel = guest->kernel();

    if (kernel.x64())
        this->init<uint64_t>(string_buffer_size);
    else
        this->init<uint32_t>(string_buffer_size);
}

} // namespace inject
} // namespace introvirt