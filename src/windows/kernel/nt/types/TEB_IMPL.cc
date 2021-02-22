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
#include "TEB_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.win.nt.types.teb"));

template <typename PtrType>
const NT_TIB& TEB_IMPL<PtrType>::NtTib() const {
    if (!NtTib_) {
        const GuestVirtualAddress pNtTib = gva_ + teb_->NtTib.offset();
        NtTib_.emplace(kernel_, pNtTib);
    }
    return *NtTib_;
}

template <typename PtrType>
const CLIENT_ID& TEB_IMPL<PtrType>::ClientId() const {
    if (!ClientId_) {
        const GuestVirtualAddress pNtTib = gva_ + teb_->ClientId.offset();
        ClientId_.emplace(pNtTib);
    }
    return *ClientId_;
}

template <typename PtrType>
WinError TEB_IMPL<PtrType>::LastErrorValue() const {
    return static_cast<WinError>(teb_->LastErrorValue.get<uint32_t>(buffer_));
}
template <typename PtrType>
void TEB_IMPL<PtrType>::LastErrorValue(WinError LastErrorValue) {
    teb_->LastErrorValue.set<uint32_t>(buffer_, static_cast<uint32_t>(LastErrorValue));
}

template <typename PtrType>
NTSTATUS TEB_IMPL<PtrType>::LastStatusValue() const {
    return NTSTATUS(teb_->LastStatusValue.get<uint32_t>(buffer_));
}

template <typename PtrType>
void TEB_IMPL<PtrType>::LastStatusValue(NTSTATUS status) {
    teb_->LastStatusValue.set<uint32_t>(buffer_, status.value());
}

template <typename PtrType>
GuestVirtualAddress TEB_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
TEB_IMPL<PtrType>::TEB_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva) {

    LOG4CXX_TRACE(logger, "TEB: " << gva_ << " DTB: 0x" << std::hex << gva_.page_directory());

    teb_ = LoadOffsets<structs::TEB>(kernel_);

    buffer_.reset(gva_, teb_->size());
}

template class TEB_IMPL<uint32_t>;
template class TEB_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
