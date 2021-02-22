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

#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/condrv/types/ConDrvIoctl.hh>
#include <introvirt/windows/kernel/condrv/types/ConsoleCallServerGenericRequest.hh>
#include <introvirt/windows/kernel/nt/syscall/NtDeviceIoControlFile.hh>

#include "windows/kernel/condrv/structs/structs.hh"

#include <cstdint>

namespace introvirt {
namespace windows {
namespace condrv {

class ConDrvIoctl::IMPL {
  public:
    virtual ~IMPL() = default;

  public:
    ConsoleRequestIoctl ioctlCode;
    std::unique_ptr<ConsoleCallServerGenericRequest> genericRequestData;
};

template <typename PtrType>
class ConDrvIoctl::IMPL_SPEC final : public ConDrvIoctl::IMPL {
  public:
    IMPL_SPEC(const WindowsGuest& guest, const nt::NtDeviceIoControlFile& ioctl) {
        // Map the input buffer
        inputData.reset(ioctl.InputBufferPtr(), ioctl.InputBufferLength());

        // Handle the different types of IOCTL code
        ioctlCode = static_cast<ConsoleRequestIoctl>(ioctl.IoControlCode());

        switch (ioctlCode) {
        case ConsoleRequestIoctl::ConsoleCallServerGeneric: {
            // The address after the main IOCTL request header
            const auto pRequestData =
                ioctl.InputBufferPtr() + sizeof(ConsoleCallServerGenericHeader);
            const uint32_t requestDataLen =
                ioctl.InputBufferLength() - sizeof(ConsoleCallServerGenericHeader);

            auto serverData =
                reinterpret_cast<const ConsoleCallServerGenericHeader*>(inputData.get());
            genericRequestData = std::make_unique<ConsoleCallServerGenericRequest>(
                guest, pRequestData.create(serverData->requestHeaderPtr), pRequestData,
                requestDataLen);
            break;
        }
        case ConsoleRequestIoctl::ConsoleCommitState:
            break;
        case ConsoleRequestIoctl::ConsoleLaunchServerProcess:
            break;
        default:
            ioctlCode = ConsoleRequestIoctl::Unknown;
            break;
        }
    }

  private:
    using ConsoleCallServerGenericHeader = structs::ConsoleCallServerGenericHeader<PtrType>;
    guest_ptr<char[]> inputData;
};

ConsoleRequestIoctl ConDrvIoctl::IoctlCode() const { return pImpl->ioctlCode; }

ConsoleCallServerGenericRequest& ConDrvIoctl::GenericRequest() const {
    if (unlikely(IoctlCode() != ConsoleRequestIoctl::ConsoleCallServerGeneric)) {
        throw InvalidMethodException();
    }

    return *pImpl->genericRequestData;
}

ConDrvIoctl::ConDrvIoctl(const WindowsGuest& guest, const nt::NtDeviceIoControlFile& ioctl) {
    if (guest.x64()) {
        pImpl = std::make_unique<IMPL_SPEC<uint64_t>>(guest, ioctl);
    } else {
        pImpl = std::make_unique<IMPL_SPEC<uint32_t>>(guest, ioctl);
    }
}

ConDrvIoctl::~ConDrvIoctl() = default;

} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */
