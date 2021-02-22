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
#pragma once

#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/CLIENT_ID_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/PORT_MESSAGE.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class PORT_MESSAGE_IMPL final : public PORT_MESSAGE {
  public:
    int16_t DataLength() const override;

    int16_t TotalLength() const override;

    LPC_TYPE MessageType() const override;

    int16_t DataInfoOffset() const override;

    const CLIENT_ID& ClientId() const override;

    uint32_t MessageId() const override;

    uint32_t CallbackId() const override;

    GuestVirtualAddress address() const override;

    uint64_t HeaderSize() const override;

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    PORT_MESSAGE_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;
    const structs::PORT_MESSAGE* port_message_;
    std::optional<CLIENT_ID_IMPL<PtrType>> client_id_;
    guest_ptr<char[]> buffer;
};

} // namespace nt
} // namespace windows
} // namespace introvirt