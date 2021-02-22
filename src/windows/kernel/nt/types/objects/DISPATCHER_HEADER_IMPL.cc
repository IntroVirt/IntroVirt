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
#include "DISPATCHER_HEADER_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
DISPATCHER_HEADER::ObjectType DISPATCHER_HEADER_IMPL<PtrType>::Type() const {
    const uint8_t result = offsets_->Type.get<uint8_t>(buffer_);
    // TODO: Make DISPATCHER_HEADER::Type a "enum class : uint8_t"
    return static_cast<DISPATCHER_HEADER::ObjectType>(result);
}

template <typename PtrType>
bool DISPATCHER_HEADER_IMPL<PtrType>::Absolute() const {
    return offsets_->Absolute.get_bitfield<uint8_t>(buffer_);
}

template <typename PtrType>
uint32_t DISPATCHER_HEADER_IMPL<PtrType>::Size() const {
    // Header->Size is the size of the object in DWORDs
    uint32_t size = offsets_->Size.get_bitfield<uint8_t>(buffer_);
    return size * sizeof(uint32_t);
}

template <typename PtrType>
bool DISPATCHER_HEADER_IMPL<PtrType>::Inserted() const {
    return offsets_->Inserted.get_bitfield<uint8_t>(buffer_);
}

template <typename PtrType>
int32_t DISPATCHER_HEADER_IMPL<PtrType>::SignalState() const {
    return offsets_->SignalState.get<int32_t>(buffer_);
}

template <typename PtrType>
DISPATCHER_HEADER_IMPL<PtrType>::DISPATCHER_HEADER_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                        const GuestVirtualAddress& gva)
    : offsets_(LoadOffsets<structs::DISPATCHER_HEADER>(kernel)) {

    // Map in the structure. Doing one mapping is a lot cheaper than mapping every field.
    buffer_.reset(gva, offsets_->size());
}

template class DISPATCHER_HEADER_IMPL<uint32_t>;
template class DISPATCHER_HEADER_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt