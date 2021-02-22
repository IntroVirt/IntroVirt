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
#include "PEB_IMPL.hh"

#include <log4cxx/logger.h>

#include <type_traits>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.PEB"));

template <typename PtrType>
GuestVirtualAddress PEB_IMPL<PtrType>::ImageBaseAddress() const {
    return gva_.create(data_->ImageBaseAddress);
}

template <typename PtrType>
GuestVirtualAddress PEB_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
const PEB_LDR_DATA* PEB_IMPL<PtrType>::Ldr() const {
    if (!ldr) {
        try {
            ldr.emplace(gva_.create(data_->Ldr));
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "Failed to get Ldr: " << ex);
            return nullptr;
        }
    }
    return &(*ldr);
}

template <typename PtrType>
PEB_LDR_DATA* PEB_IMPL<PtrType>::Ldr() {
    const auto* const_this = this;
    return const_cast<PEB_LDR_DATA*>(const_this->Ldr());
}

template <typename PtrType>
const RTL_USER_PROCESS_PARAMETERS* PEB_IMPL<PtrType>::ProcessParameters() const {
    if (!rtlUserProcessParams) {
        try {
            rtlUserProcessParams.emplace(gva_.create(data_->ProcessParameters));
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "Failed to get ProcessParameters: " << ex);
            return nullptr;
        }
    }
    return &(*rtlUserProcessParams);
}

template <typename PtrType>
RTL_USER_PROCESS_PARAMETERS* PEB_IMPL<PtrType>::ProcessParameters() {
    const auto* const_this = this;
    return const_cast<RTL_USER_PROCESS_PARAMETERS*>(const_this->ProcessParameters());
}

template <typename PtrType>
uint32_t PEB_IMPL<PtrType>::OSMajorVersion() const {
    return data_->OSMajorVersion;
}

template <typename PtrType>
uint32_t PEB_IMPL<PtrType>::OSMinorVersion() const {
    return data_->OSMinorVersion;
}

template <typename PtrType>
uint16_t PEB_IMPL<PtrType>::OSBuildNumber() const {
    return data_->OSBuildNumber;
}

template <typename PtrType>
uint16_t PEB_IMPL<PtrType>::OSCSDVersion() const {
    return data_->OSCSDVersion;
}

template <typename PtrType>
uint32_t PEB_IMPL<PtrType>::OSPlatformId() const {
    return data_->OSPlatformId;
}

template <typename PtrType>
uint32_t PEB_IMPL<PtrType>::NumberOfProcessors() const {
    return data_->NumberOfProcessors;
}

template <typename PtrType>
bool PEB_IMPL<PtrType>::BeingDebugged() const {
    return data_->BeingDebugged;
}

template <typename PtrType>
void PEB_IMPL<PtrType>::BeingDebugged(bool BeingDebugged) {
    data_->BeingDebugged = BeingDebugged;
}

template <typename PtrType>
uint16_t PEB_IMPL<PtrType>::ServicePackNumber() const {
    return (OSCSDVersion() >> 8) & 0xFF;
}
template <typename PtrType>
uint16_t PEB_IMPL<PtrType>::MinorServicePackNumber() const {
    return (OSCSDVersion()) & 0xFF;
}

template <typename PtrType>
PEB_IMPL<PtrType>::PEB_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva_) {}

template class PEB_IMPL<uint32_t>;
template class PEB_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
